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
from datetime import datetime
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault PKI Certificate Authority Manager")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO (Global)
    p_info = subparsers.add_parser("info", help="Introspect locally issued TLS certificates")
    p_info.add_argument("--dir", default="./certs", help="Directory containing the certificates (default: ./certs)")

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
    p_issue.add_argument("--out-dir", default="./certs", help="Directory to save the certificate files")

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
        cert_dir = args.dir
        if not os.path.exists(cert_dir) or not os.path.isdir(cert_dir):
            print(f"❌ Directory '{cert_dir}' not found.", file=sys.stderr)
            sys.exit(1)

        cert_paths = glob.glob(os.path.join(cert_dir, "*.crt")) + glob.glob(os.path.join(cert_dir, "*.pem"))
        
        if not cert_paths:
            print(f"❌ No certificates (*.crt, *.pem) found in '{cert_dir}'.", file=sys.stderr)
            sys.exit(1)

        print(f"🔍 Introspecting Local TLS Certificates in '{cert_dir}'...")
        for cert in cert_paths:
            try:
                # Use openssl to extract the certificate metadata
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
                        
                        # Parse the OpenSSL date (e.g., 'Mar  7 20:00:00 2026 GMT')
                        try:
                            clean_date = enddate.replace(" GMT", "")
                            # Remove double spaces for clean parsing
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
                            time_str = enddate # Fallback if parsing fails

                is_ca = "-ca.crt" in cert
                badge = " (🏛️ CA Chain)" if is_ca else ""

                print(f"\n📄 Certificate : {cert}{badge}")
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
                
                # Configure URLs automatically
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
                # Get the actual CA Certificate text
                res = client.read(f"{mount}/cert/ca")
                if res and 'data' in res and 'certificate' in res['data']:
                    cert_body = res['data']['certificate']
                    print(f"🏛️ PKI CA Engine: {mount}/")
                    # Quick parsing for human readability
                    cert_lines = cert_body.strip().split('\n')
                    print(f"  ├─ Certificate : {cert_lines[0]} ... ({len(cert_lines)-2} lines) ... {cert_lines[-1]}")
                    
                    # Fetch config to show max TTL
                    config_res = client.sys.read_mount_configuration(path=mount)
                    if config_res and 'data' in config_res:
                        print(f"  ├─ Max TTL     : {config_res['data'].get('max_lease_ttl', 'Unknown')}s")
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
            
            # Write to files
            os.makedirs(args.out_dir, exist_ok=True)
            safe_cn = common_name.replace("*", "star")
            
            cert_path = os.path.join(args.out_dir, f"{safe_cn}.crt")
            key_path = os.path.join(args.out_dir, f"{safe_cn}.key")
            ca_path = os.path.join(args.out_dir, f"{safe_cn}-ca.crt")
            
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

if __name__ == "__main__":
    main()
