# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_ssh.py
# Purpose : Dedicated CLI for Vault SSH Certificate Authority
# -----------------------------------------------------------------------------
import argparse
import sys
import os
import subprocess
import json
from .core import HashiVault

def parse_ssh_config(target_host):
    """Parses ~/.ssh/config to find the User and IdentityFile for a specific host."""
    config_path = os.path.expanduser("~/.ssh/config")
    
    # Smart Defaults
    principal = os.environ.get("USER", "root")
    identity_file = "~/.ssh/id_ed25519" 
    
    # Fallback to RSA if ed25519 doesn't exist and config is missing
    if not os.path.exists(os.path.expanduser(identity_file)):
        identity_file = "~/.ssh/id_rsa"

    if not os.path.exists(config_path):
        return principal, identity_file

    with open(config_path, 'r') as f:
        lines = f.readlines()

    in_host_block = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'): continue
        
        parts = line.split()
        key = parts[0].lower()
        
        # Check if we entered the block for our target host (or a wildcard block)
        if key == 'host':
            in_host_block = target_host in parts[1:] or '*' in parts[1:]
            
        if in_host_block:
            if key == 'user' and len(parts) > 1:
                principal = parts[1]
            elif key == 'identityfile' and len(parts) > 1:
                identity_file = parts[1]

    return principal, identity_file

def get_args():
    parser = argparse.ArgumentParser(description="Vault SSH Certificate Authority Manager")
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout in seconds")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO
    p_info = subparsers.add_parser("info", help="Introspect the current SSH CA session")

    # 2. EXEC
    p_exec = subparsers.add_parser("exec", help="Sign your SSH key and connect to a host")
    p_exec.add_argument("engine", help="Mount point (e.g., ssh)")
    p_exec.add_argument("role", help="Vault SSH Role")
    p_exec.add_argument("target_host", help="The SSH host to connect to (e.g., db-prod)")
    p_exec.add_argument("--key", help="Explicit path to public key (overrides ~/.ssh/config)")
    p_exec.add_argument("exec_cmd", nargs='*', help="Optional command to run remotely (prefix with '--')")

    # 3. ENGINE
    p_engine = subparsers.add_parser("engine", help="Manage SSH CA Engines")
    p_engine.add_argument("action", choices=["create", "delete", "list", "read"], help="Action to perform")
    p_engine.add_argument("mount", nargs="?", default="ssh", help="Mount point")

    # 4. ROLE
    p_role = subparsers.add_parser("role", help="Manage SSH Roles (Principals & Access)")
    p_role.add_argument("action", choices=["create", "delete", "list", "read"], help="Action to perform")
    p_role.add_argument("mount", nargs="?", default="ssh", help="Mount point")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--default-user", default="ubuntu", help="Default SSH principal")
    p_role.add_argument("--allowed-users", default="ubuntu,root", help="Comma-separated allowed principals")
    p_role.add_argument("--ttl", default="4h", help="Max TTL for signed certificates")

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
        print("🔍 Vault SSH Module Active.")
        print("To see your active local SSH certificates, run: ssh-add -l")
        sys.exit(0)

    # -------------------------------------------------------------------------
    # 2. EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        mount = args.engine.strip('/')
        target_host = args.target_host
        
        # Override with explicit flag, or fallback to smart config parsing
        if args.key:
            principal = os.environ.get("USER", "root")
            identity_file = args.key.replace(".pub", "")
        else:
            principal, identity_file = parse_ssh_config(target_host)
        
        # Clean up path
        identity_file = os.path.expanduser(identity_file.strip('"\''))
        pub_key_path = f"{identity_file}.pub"
        
        if not os.path.exists(pub_key_path):
            print(f"❌ Error: Public key not found at {pub_key_path}", file=sys.stderr)
            sys.exit(1)
            
        with open(pub_key_path, 'r') as f:
            pub_key = f.read()
            
        print(f"🔍 Resolved target '{target_host}': Principal '{principal}', Key '{pub_key_path}'", file=sys.stderr)
        print(f"🔒 Requesting signed SSH certificate from Vault...", file=sys.stderr)
        
        signed_key = vault.sign_ssh_key(args.role, mount, pub_key, principal)
        if not signed_key: sys.exit(1)
        
        # Save the certificate exactly where SSH expects it
        cert_path = pub_key_path.replace(".pub", "-cert.pub")
        with open(cert_path, 'w') as f:
            f.write(signed_key)
            
        print(f"✅ Certificate saved to {cert_path} and ready for use.", file=sys.stderr)
        
        # Build the SSH command
        ssh_command = ["ssh", target_host]
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--": 
            ssh_command.extend(command_list[1:])
        
        print(f"🚀 Connecting to {target_host}...\n" + "-"*40, file=sys.stderr)
        sys.exit(subprocess.run(ssh_command).returncode)

    # -------------------------------------------------------------------------
    # 3. ENGINE
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        mount = args.mount.strip('/')
        
        if args.action == "list":
            engines = vault.list_engines(backend_type="ssh")
            if engines:
                print("🌐 Active SSH CA Engines:")
                for e in engines: print(f"  ├─ {e}")
            else:
                print("ℹ️ No SSH CA Engines mounted.")
            sys.exit(0)
            
        elif args.action == "create":
            print(f"🚀 Configuring SSH CA Engine at '{mount}/'...")
            if vault.setup_ssh_engine(mount):
                print(f"🎉 SSH CA enabled at '{mount}/'")
                
        elif args.action == "read":
            client = vault._get_client()
            try:
                res = client.read(f"{mount}/config/ca")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else:
                    print(f"❌ No CA config found at '{mount}/'")
            except Exception as e:
                print(f"❌ Error reading SSH engine: {e}")
                
        elif args.action == "delete":
            print(f"🧹 Tearing down SSH CA engine at '{mount}/'...")
            if vault.teardown_ssh_engine(mount):
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
                    print(f"👥 Active SSH Roles at '{mount}/':")
                    for r in roles: print(f"  ├─ {r}")
                else:
                    print("ℹ️ No SSH roles found.")
            except Exception as e:
                if "404" in str(e): print("ℹ️ No SSH roles found.")
                else: print(f"❌ Error listing SSH roles: {e}")
            sys.exit(0)
            
        if not args.role_name:
            print("❌ Error: role_name is required for this action.", file=sys.stderr)
            sys.exit(1)
            
        if args.action == "create":
            print(f"🚀 Creating SSH Role '{args.role_name}'...")
            if vault.create_ssh_role(args.role_name, mount, args.default_user, args.allowed_users, args.ttl):
                print(f"✅ SSH Role '{args.role_name}' successfully configured.")
                
        elif args.action == "read":
            client = vault._get_client()
            try:
                res = client.read(f"{mount}/roles/{args.role_name}")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else:
                    print(f"❌ Role '{args.role_name}' not found.")
            except Exception as e:
                print(f"❌ Error reading role: {e}")
                
        elif args.action == "delete":
            client = vault._get_client()
            try:
                client.delete(f"{mount}/roles/{args.role_name}")
                print(f"✅ Deleted SSH role '{args.role_name}'.")
            except Exception as e:
                print(f"❌ Error deleting SSH role: {e}")

if __name__ == "__main__":
    main()
