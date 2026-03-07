# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_pki.py
# Purpose : Dedicated CLI for Vault PKI (TLS Certificates)
# -----------------------------------------------------------------------------
import argparse
import sys
import os
import subprocess
import json
import tempfile
import shutil
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault PKI Certificate Authority Manager")
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout in seconds")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO
    p_info = subparsers.add_parser("info", help="Introspect current PKI environment")

    # 2. EXEC
    p_exec = subparsers.add_parser("exec", help="Issue a dynamic TLS cert and drop into a shell")
    p_exec.add_argument("engine", help="Mount point (e.g., pki)")
    p_exec.add_argument("role", help="Vault PKI Role")
    p_exec.add_argument("common_name", help="The domain to issue the cert for (e.g., api.ctlabs.local)")
    p_exec.add_argument("--ttl", default="4h", help="Requested TTL for the certificate")
    p_exec.add_argument("exec_cmd", nargs='*', help="Optional command to run remotely (prefix with '--')")

    # 3. ENGINE
    p_engine = subparsers.add_parser("engine", help="Manage PKI CA Engines")
    p_engine.add_argument("action", choices=["create", "delete", "list", "read"], help="Action to perform")
    p_engine.add_argument("mount", nargs="?", default="pki", help="Mount point")
    p_engine.add_argument("--common-name", default="CTLabs Internal Root CA", help="Root CA Name (for creation)")
    p_engine.add_argument("--max-ttl", default="87600h", help="Max TTL for the CA (default 10 years)")

    # 4. ROLE
    p_role = subparsers.add_parser("role", help="Manage PKI Roles (Allowed Domains)")
    p_role.add_argument("action", choices=["create", "delete", "list", "read"], help="Action to perform")
    p_role.add_argument("mount", nargs="?", default="pki", help="Mount point")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--allowed-domains", help="Comma-separated allowed domains (e.g., ctlabs.local)")
    p_role.add_argument("--ttl", default="72h", help="Max TTL for issued certificates")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    
    # -------------------------------------------------------------------------
    # 1. INFO
    # -------------------------------------------------------------------------
    if cmd == "info":
        cert = os.environ.get("TLS_CERT")
        if cert and os.path.exists(cert):
            print("🔍 Active JIT PKI Session:")
            print(f"📄 Cert: {os.environ.get('TLS_CERT')}")
            print(f"🔑 Key : {os.environ.get('TLS_KEY')}")
            print(f"🛡️  CA  : {os.environ.get('TLS_CA')}")
            sys.exit(0)
        else:
            print("ℹ️ No active JIT PKI session found.")
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 2. EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        mount = args.engine.strip('/')
        
        print(f"🔒 Requesting dynamic TLS certificate for '{args.common_name}'...", file=sys.stderr)
        cert_data = vault.issue_certificate(args.role, mount, args.common_name, ttl=args.ttl)
        if not cert_data: sys.exit(1)
        
        # Create a secure temporary directory
        temp_dir = tempfile.mkdtemp(prefix="vault-pki-")
        os.chmod(temp_dir, 0o700)
        
        cert_path = os.path.join(temp_dir, "tls.crt")
        key_path = os.path.join(temp_dir, "tls.key")
        ca_path = os.path.join(temp_dir, "ca.crt")
        
        # Write the certificates
        with open(cert_path, "w") as f: f.write(cert_data['certificate'])
        with open(key_path, "w") as f: f.write(cert_data['private_key'])
        with open(ca_path, "w") as f: f.write(cert_data['issuing_ca'])
        
        # Secure the private key
        os.chmod(key_path, 0o600)
        
        # Inject into environment
        os.environ["TLS_CERT"] = cert_path
        os.environ["TLS_KEY"] = key_path
        os.environ["TLS_CA"] = ca_path
        
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--": command_list = command_list[1:]
        
        print(f"✅ Certificates generated and stored securely in memory/tempfs.", file=sys.stderr)
        
        try:
            if command_list == ["bash"] or not command_list:
                # Interactive Subshell
                rc_content = f"""
if [ -f ~/.bashrc ]; then source ~/.bashrc; fi
export PS1="\\[\\e[36m\\][PKI JIT: {args.common_name}]\\[\\e[m\\] \\w \\$ "
echo "🔒 Vault JIT PKI Session Active!"
echo "👉 The following environment variables have been injected:"
echo "   \\$TLS_CERT = {cert_path}"
echo "   \\$TLS_KEY  = {key_path}"
echo "   \\$TLS_CA   = {ca_path}"
echo "⏳ Type 'exit' to close the session and securely shred the keys."
"""
                fd, rc_path = tempfile.mkstemp(suffix=".bashrc")
                with os.fdopen(fd, 'w') as f: f.write(rc_content)
                
                try:
                    exit_code = subprocess.run(["bash", "--rcfile", rc_path], env=os.environ).returncode
                finally:
                    os.remove(rc_path)
            else:
                # Direct Command Execution
                print(f"🚀 Executing command...\n" + "-"*40, file=sys.stderr)
                exit_code = subprocess.run(command_list, env=os.environ).returncode
                
        finally:
            # 🧹 SECURITY: ALWAYS wipe the private keys when the script exits
            print(f"\n🧹 Shredding temporary TLS certificates...", file=sys.stderr)
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.exit(exit_code)

    # -------------------------------------------------------------------------
    # 3. ENGINE
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        mount = args.mount.strip('/')
        
        if args.action == "list":
            engines = vault.list_engines(backend_type="pki")
            if engines:
                print("🌐 Active PKI CA Engines:")
                for e in engines: print(f"  ├─ {e}")
            else:
                print("ℹ️ No PKI CA Engines mounted.")
            sys.exit(0)
            
        elif args.action == "create":
            print(f"🚀 Configuring PKI Root CA at '{mount}/'...")
            if vault.setup_pki_engine(mount, common_name=args.common_name, max_ttl=args.max_ttl):
                print(f"🎉 PKI Root CA created at '{mount}/' (CN: {args.common_name})")
                
        elif args.action == "read":
            client = vault._get_client()
            try:
                res = client.read(f"{mount}/config/urls")
                if res and 'data' in res: print(json.dumps(res['data'], indent=2))
                else: print(f"❌ No CA config found at '{mount}/'")
            except Exception as e:
                print(f"❌ Error reading PKI engine: {e}")
                
        elif args.action == "delete":
            print(f"🧹 Tearing down PKI CA engine at '{mount}/'...")
            if vault.teardown_pki_engine(mount):
                print(f"🎉 Engine destroyed!")

    # -------------------------------------------------------------------------
    # 4. ROLE
    # -------------------------------------------------------------------------
    elif cmd == "role":
        mount = args.mount.strip('/')
        
        if args.action == "list":
            client = vault._get_client()
            try:
                res = client.list(f"{mount}/roles")
                roles = res.get('data', {}).get('keys', []) if res else []
                if roles:
                    print(f"👥 Active PKI Roles at '{mount}/':")
                    for r in roles: print(f"  ├─ {r}")
                else:
                    print("ℹ️ No PKI roles found.")
            except Exception as e:
                if "404" in str(e): print("ℹ️ No PKI roles found.")
                else: print(f"❌ Error listing PKI roles: {e}")
            sys.exit(0)
            
        if not args.role_name:
            print("❌ Error: role_name is required for this action.", file=sys.stderr)
            sys.exit(1)
            
        if args.action == "create":
            if not args.allowed_domains:
                print("❌ Error: --allowed-domains is required to create a PKI role.", file=sys.stderr)
                sys.exit(1)
            print(f"🚀 Creating PKI Role '{args.role_name}'...")
            if vault.create_pki_role(args.role_name, mount, args.allowed_domains, max_ttl=args.ttl):
                print(f"✅ PKI Role '{args.role_name}' successfully configured.")
                
        elif args.action == "read":
            details = vault.read_pki_role(args.role_name, mount)
            if details: print(json.dumps(details, indent=2))
            else: print(f"❌ Role '{args.role_name}' not found.")
                
        elif args.action == "delete":
            if vault.delete_pki_role(args.role_name, mount):
                print(f"✅ Deleted PKI role '{args.role_name}'.")

if __name__ == "__main__":
    main()
