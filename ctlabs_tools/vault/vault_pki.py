# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_pki.py
# Purpose : Dedicated CLI for Vault PKI Certificate Authority & TLS issuance
# -----------------------------------------------------------------------------
import argparse
import sys
import os
import json
import glob
import subprocess
import tempfile
import shutil
from datetime import datetime
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault PKI Certificate Authority Manager")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO (Global)
    p_info = subparsers.add_parser("info", help="Introspect locally issued TLS certificates")
    p_info.add_argument("--dir", default="~/.certs", help="Directory containing the certificates (default: ~/.certs)")

    # 2. ENGINE
    p_engine = subparsers.add_parser("engine", help="Manage PKI Secrets Engines")
    p_engine.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_engine.add_argument("mount", nargs="?", default="", help="Mount point (e.g., pki, pki_int)")
    p_engine.add_argument("--common-name", default="CTLabs Internal Root CA", help="Common Name for a new Root CA")
    p_engine.add_argument("--ttl", default="87600h", help="Max TTL for the CA (default 10 years)")

    # 3. ROLE
    p_role = subparsers.add_parser("role", help="Manage PKI Roles (Allowed Domains)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_role.add_argument("mount", nargs="?", default="", help="Mount point")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the PKI role")
    p_role.add_argument("--allowed-domains", help="Comma-separated allowed domains (e.g., ctlabs.internal)")
    p_role.add_argument("--allow-subdomains", action="store_true", help="Allow issuing certs for subdomains")
    p_role.add_argument("--ttl", default="720h", help="Max TTL for issued certificates")

    # 4. ISSUE
    p_issue = subparsers.add_parser("issue", help="Issue a TLS Certificate")
    p_issue.add_argument("mount", help="Mount point (e.g., pki)")
    p_issue.add_argument("role_name", help="PKI Role Name")
    p_issue.add_argument("common_name", help="The CN for the certificate (e.g., api.ctlabs.internal)")
    p_issue.add_argument("--ttl", default="24h", help="TTL for this specific cert")
    p_issue.add_argument("--out-dir", default="~/.certs", help="Directory to save the certificate files (default: ~/.certs)")

    # 5. EXEC (Ephemeral Injection)
    p_exec = subparsers.add_parser("exec", help="Issue an ephemeral TLS cert, inject env vars, and run a command")
    p_exec.add_argument("mount", help="Mount point (e.g., pki)")
    p_exec.add_argument("role_name", help="PKI Role Name")
    p_exec.add_argument("common_name", help="The CN for the certificate (e.g., client.ctlabs.internal)")
    p_exec.add_argument("--ttl", default="5m", help="TTL for this ephemeral cert (default 5m)")
    p_exec.add_argument("exec_cmd", nargs='*', help="The command to execute (prefix with '--')")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    
    # -------------------------------------------------------------------------
    # 1. INFO (Global Introspection)
    # -------------------------------------------------------------------------
    if cmd == "info":
        cert_paths = []
        
        # 1. Check Standard Permanent Directory
        cert_dir = os.path.expanduser(args.dir)
        if os.path.exists(cert_dir) and os.path.isdir(cert_dir):
            cert_paths.extend(glob.glob(os.path.join(cert_dir, "*.crt")))
            cert_paths.extend(glob.glob(os.path.join(cert_dir, "*.pem")))
            
        # 2. Check Ephemeral Sandbox Directories
        temp_dir = tempfile.gettempdir()
        ephemeral_certs = glob.glob(os.path.join(temp_dir, "vault-pki-*", "*.crt")) + glob.glob(os.path.join(temp_dir, "vault-pki-*", "*.pem"))
        cert_paths.extend(ephemeral_certs)
        
        if not cert_paths:
            print(f"❌ No active TLS certificates found in '{cert_dir}' or in temporary sandboxes.", file=sys.stderr)
            sys.exit(1)

        print("🔍 Introspecting Active TLS Certificates...")
        for cert in cert_paths:
            try:
                res = subprocess.run(["openssl", "x509", "-in", cert, "-noout", "-subject", "-issuer", "-enddate"], capture_output=True, text=True, check=True)
                lines = res.stdout.strip().split('\n')
                
                subject, issuer, enddate = "Unknown", "Unknown", "Unknown"
                time_str = "Unknown"

                for line in lines:
                    if line.startswith("subject="):
                        subject = line.split("=", 1)[1].strip()
                    elif line.startswith("issuer="):
                        issuer = line.split("=", 1)[1].strip()
                    elif line.startswith("notAfter="):
                        enddate = line.split("=", 1)[1].strip()
                        try:
                            clean_date = enddate.replace(" GMT", "")
                            clean_date = " ".join(clean_date.split())
                            to_date = datetime.strptime(clean_date, "%b %d %H:%M:%S %Y")
                            now = datetime.utcnow()
                            
                            if now < to_date:
                                rem = int((to_date - now).total_seconds())
                                mins = rem // 60
                                hours = mins // 60
                                days = hours // 24
                                if days > 0:
                                    time_str = f"{days} days, {hours % 24}h {mins % 60}m"
                                else:
                                    time_str = f"{hours}h {mins % 60}m"
                            else:
                                time_str = "EXPIRED ⚠️"
                        except Exception:
                            time_str = enddate 

                is_ca = "-ca.crt" in cert
                is_ephemeral = "vault-pki-" in cert
                
                badges = []
                if is_ca: badges.append("🏛️ CA Chain")
                if is_ephemeral: badges.append("👻 Ephemeral Sandbox")
                
                badge_str = f" ({', '.join(badges)})" if badges else ""

                print(f"\n📄 Certificate : {cert}{badge_str}")
                print(f"🏷️  Subject     : {subject}")
                print(f"🏛️  Issuer      : {issuer}")
                print(f"⏳ Remaining   : {time_str}")
                if "EXPIRED" in time_str or time_str == enddate:
                    print(f"   (Valid Until: {enddate})")

            except Exception as e:
                print(f"⚠️ Could not parse {cert}: {e}")
                
        sys.exit(0)

    # -------------------------------------------------------------------------
    # 2. ENGINE (CA Management)
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action
        mount = getattr(args, 'mount', '').strip('/')
        
        if action == "list":
            engines = vault.list_engines(backend_type="pki")
            if engines:
                print("🌐 Active PKI Certificate Authorities:")
                for e in engines: print(f"  ├─ {e}")
            else:
                print("ℹ️ No PKI Engines mounted.")
            sys.exit(0)
            
        if not mount:
            print("❌ Error: Mount point is required.", file=sys.stderr)
            sys.exit(1)
            
        client = vault._get_client()

        if action == "create":
            print(f"🚀 Configuring PKI Engine at '{mount}/'...")
            try:
                current_mounts = client.sys.list_mounted_secrets_engines()['data']
                if f"{mount}/" not in current_mounts:
                    client.sys.enable_secrets_engine('pki', path=mount, config={'max_lease_ttl': args.ttl})
                
                print(f"🔒 Generating Internal Root CA for '{args.common_name}'...")
                client.write(f"{mount}/root/generate/internal", common_name=args.common_name, ttl=args.ttl)
                
                issuer_url = f"{client.url}/v1/{mount}/ca"
                crl_url = f"{client.url}/v1/{mount}/crl"
                client.write(f"{mount}/config/urls", issuing_certificates=[issuer_url], crl_distribution_points=[crl_url])
                
                print(f"🎉 PKI CA enabled and configured at '{mount}/'")
            except Exception as e:
                print(f"❌ Error setting up PKI engine: {e}")
                
        elif action == "read":
            try:
                res = client.read(f"{mount}/cert/ca")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else: print(f"❌ No CA cert found at '{mount}/'")
            except Exception as e:
                print(f"❌ Error reading PKI engine: {e}")
                
        elif action == "info":
            try:
                res = client.read(f"{mount}/cert/ca")
                if res and 'data' in res and 'certificate' in res['data']:
                    cert_body = res['data']['certificate']
                    print(f"🏛️ PKI CA Engine: {mount}/")
                    
                    subject, enddate, sans = "Unknown", "Unknown", "None"
                    try:
                        ossl_res = subprocess.run(
                            ["openssl", "x509", "-noout", "-subject", "-enddate", "-ext", "subjectAltName"],
                            input=cert_body, text=True, capture_output=True
                        )
                        lines = ossl_res.stdout.strip().split('\n')
                        parsing_sans = False
                        
                        for line in lines:
                            line = line.strip()
                            if line.startswith("subject="): subject = line.split("=", 1)[1].strip()
                            elif line.startswith("notAfter="): enddate = line.split("=", 1)[1].strip()
                            elif line == "X509v3 Subject Alternative Name:": parsing_sans = True
                            elif parsing_sans and line:
                                sans = line
                                parsing_sans = False
                    except Exception:
                        pass
                    
                    print(f"  ├─ Subject : {subject}")
                    print(f"  ├─ SANs    : {sans}")
                    print(f"  ├─ Validity: {enddate}")
                    
                    try:
                        config_res = client.sys.read_mount_configuration(path=mount)
                        if config_res and 'data' in config_res:
                            print(f"  ├─ Max TTL : {config_res['data'].get('max_lease_ttl', 'Unknown')}s")
                    except Exception:
                        pass
                else:
                    print(f"❌ No active CA certificate found at '{mount}/'. (Has a root/intermediate been generated?)")
            except Exception as e:
                print(f"❌ Error reading PKI info: {e}")

        elif action == "update":
            print("ℹ️ Update action is not applicable to the base engine. Update roles instead.")

        elif action == "delete":
            print(f"🧹 Tearing down PKI CA engine at '{mount}/'...")
            try:
                client.sys.disable_secrets_engine(path=mount)
                print(f"🎉 PKI Engine destroyed!")
            except Exception as e:
                print(f"❌ Error deleting engine: {e}")

    # -------------------------------------------------------------------------
    # 3. ROLE
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        mount = getattr(args, 'mount', '').strip('/')
        role_name = getattr(args, 'role_name', '')
        
        if action == "list":
            if mount:
                engines_to_check = [mount]
            else:
                print("🔍 Searching across all active PKI engines...")
                engines = vault.list_engines(backend_type="pki") or []
                engines_to_check = [e.strip('/') for e in engines]

            if not engines_to_check:
                print("ℹ️ No PKI Engines currently mounted.")
                sys.exit(0)

            found_any = False
            for m in engines_to_check:
                client = vault._get_client()
                try:
                    res = client.list(f"{m}/roles")
                    roles = res.get('data', {}).get('keys', []) if res else []
                    if roles:
                        found_any = True
                        print(f"\n👥 Active PKI Roles at '{m}/':")
                        for r in roles: print(f"  ├─ {r}")
                except Exception as e:
                    if "404" not in str(e): print(f"❌ Error listing PKI roles at '{m}/': {e}")
            
            if not found_any: print("\nℹ️ No PKI roles found.")
            sys.exit(0)
            
        if not mount or not role_name:
            print("❌ Error: mount and role_name are required.", file=sys.stderr)
            sys.exit(1)
            
        client = vault._get_client()

        if action in ["create", "update"]:
            if not args.allowed_domains:
                print("❌ Error: --allowed-domains is required to create a PKI role.", file=sys.stderr)
                sys.exit(1)
                
            print(f"🚀 {action.capitalize()}ing PKI Role '{role_name}'...")
            try:
                domains = [d.strip() for d in args.allowed_domains.split(",")]
                client.write(
                    f"{mount}/roles/{role_name}",
                    allowed_domains=domains,
                    allow_subdomains=args.allow_subdomains,
                    max_ttl=args.ttl
                )
                print(f"✅ PKI Role '{role_name}' successfully configured.")
            except Exception as e:
                print(f"❌ Error configuring PKI role: {e}")
                
        elif action == "read":
            try:
                res = client.read(f"{mount}/roles/{role_name}")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else: print(f"❌ Role '{role_name}' not found.")
            except Exception as e:
                print(f"❌ Error reading role: {e}")
                
        elif action == "info":
            try:
                res = client.read(f"{mount}/roles/{role_name}")
                if res and 'data' in res:
                    d = res['data']
                    print(f"🏷️  PKI Role: {role_name}")
                    print(f"  ├─ Engine Mount      : {mount}/")
                    print(f"  ├─ Allowed Domains   : {', '.join(d.get('allowed_domains', []))}")
                    print(f"  ├─ Allow Subdomains  : {d.get('allow_subdomains', False)}")
                    print(f"  ├─ Allow Bare Domains: {d.get('allow_bare_domains', False)}")
                    print(f"  ├─ Allow Any Name    : {d.get('allow_any_name', False)}")
                    
                    max_ttl = d.get('max_ttl')
                    ttl_str = f"{max_ttl}s" if max_ttl else "System Default"
                    print(f"  ├─ Max TTL           : {ttl_str}")
                else: print(f"❌ Role '{role_name}' not found.")
            except Exception as e:
                print(f"❌ Error fetching role info: {e}")
                
        elif action == "delete":
            try:
                client.delete(f"{mount}/roles/{role_name}")
                print(f"✅ Deleted PKI role '{role_name}'.")
            except Exception as e:
                print(f"❌ Error deleting PKI role: {e}")

    # -------------------------------------------------------------------------
    # 4. ISSUE (Requesting Certificates)
    # -------------------------------------------------------------------------
    elif cmd == "issue":
        mount = args.mount.strip('/')
        role_name = args.role_name
        common_name = args.common_name
        out_dir = os.path.expanduser(args.out_dir)
        
        client = vault._get_client()
        print(f"🔒 Requesting TLS Certificate for '{common_name}' from {mount}/{role_name}...")
        
        try:
            res = client.write(f"{mount}/issue/{role_name}", common_name=common_name, ttl=args.ttl)
            if not res or 'data' not in res:
                print("❌ Failed to issue certificate: No data returned from Vault.")
                sys.exit(1)
                
            data = res['data']
            cert = data.get('certificate')
            priv_key = data.get('private_key')
            ca_chain = data.get('ca_chain', [])
            
            os.makedirs(out_dir, exist_ok=True)
            safe_cn = common_name.replace("*", "star")
            
            cert_path = os.path.join(out_dir, f"{safe_cn}.crt")
            key_path = os.path.join(out_dir, f"{safe_cn}.key")
            ca_path = os.path.join(out_dir, f"{safe_cn}-ca.crt")
            
            with open(cert_path, "w") as f: f.write(cert)
            with open(key_path, "w") as f: f.write(priv_key)
            with open(ca_path, "w") as f:
                for c in ca_chain: f.write(c + "\n")
                
            print(f"✅ Success! Certificate issued.")
            print(f"  ├─ Serial Number: {data.get('serial_number')}")
            print(f"  ├─ Private Key  : {key_path}")
            print(f"  ├─ Certificate  : {cert_path}")
            print(f"  ├─ CA Chain     : {ca_path}")
            
        except Exception as e:
            print(f"❌ Error issuing certificate: {e}")
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 5. EXEC (Ephemeral Mutual TLS)
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        mount = args.mount.strip('/')
        role_name = args.role_name
        common_name = args.common_name
        
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
            
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        client = vault._get_client()
        temp_dir = None
        exit_code = 1

        try:
            # 1. Create secure sandbox
            temp_dir = tempfile.mkdtemp(prefix="vault-pki-")
            os.chmod(temp_dir, 0o700)
            
            # 2. Issue short-lived cert
            print(f"🔒 Requesting ephemeral TLS Certificate for '{common_name}'...", file=sys.stderr)
            res = client.write(f"{mount}/issue/{role_name}", common_name=common_name, ttl=args.ttl)
            if not res or 'data' not in res:
                print("❌ Failed to issue certificate: No data returned from Vault.", file=sys.stderr)
                sys.exit(1)
                
            data = res['data']
            safe_cn = common_name.replace("*", "star")
            cert_path = os.path.join(temp_dir, f"{safe_cn}.crt")
            key_path = os.path.join(temp_dir, f"{safe_cn}.key")
            ca_path = os.path.join(temp_dir, f"{safe_cn}-ca.crt")
            
            with open(cert_path, "w") as f: f.write(data.get('certificate', ''))
            with open(key_path, "w") as f: f.write(data.get('private_key', ''))
            with open(ca_path, "w") as f:
                for c in data.get('ca_chain', []): f.write(c + "\n")
                
            # 3. Inject standard environment variables
            env = os.environ.copy()
            env["VAULT_PKI_CERT"] = cert_path
            env["VAULT_PKI_KEY"] = key_path
            env["VAULT_PKI_CA"] = ca_path
            
            print(f"🚀 Injecting certificates into environment and running command...\n" + "-"*40, file=sys.stderr)
            
            # 4. Execute command
            exit_code = subprocess.run(command_list, env=env).returncode

        except Exception as e:
            print(f"❌ Error during exec: {e}", file=sys.stderr)
            
        finally:
            # 5. Destroy the evidence
            if temp_dir and os.path.exists(temp_dir):
                print(f"\n🧹 Shredding ephemeral TLS certificates...", file=sys.stderr)
                shutil.rmtree(temp_dir, ignore_errors=True)
                
            sys.exit(exit_code)

if __name__ == "__main__":
    main()
