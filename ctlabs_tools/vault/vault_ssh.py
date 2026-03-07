# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_ssh.py
# Purpose : Dedicated CLI for Vault SSH Certificate Authority
# -----------------------------------------------------------------------------
import argparse
import sys
import os
import subprocess
import json
import fnmatch
import tempfile
import shutil
import glob
from datetime import datetime
from .core import HashiVault

def parse_ssh_config(target_host):
    """Parses ~/.ssh/config using OpenSSH's strict 'first match wins' rule."""
    config_path = os.path.expanduser("~/.ssh/config")
    
    principal = None
    identity_file = None

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            lines = f.readlines()

        in_host_block = False
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'): continue
            
            parts = line.split()
            key = parts[0].lower()
            
            if key == 'host':
                # OpenSSH supports wildcards (e.g., Host db-* *.prod)
                in_host_block = any(fnmatch.fnmatch(target_host, pat) for pat in parts[1:])
                continue
                
            if in_host_block:
                # OpenSSH uses the FIRST value it encounters for a parameter
                if key == 'user' and not principal:
                    principal = parts[1]
                elif key == 'identityfile' and not identity_file:
                    identity_file = parts[1].strip('"\'')

    # Smart Fallbacks
    if not principal:
        principal = os.environ.get("USER", "root")
        
    # Advanced Key Discovery Logic
    if not identity_file:
        keys_dir = os.path.expanduser("~/.ssh/keys")
        
        if os.path.exists(os.path.join(keys_dir, "id_ed25519")):
            identity_file = os.path.join(keys_dir, "id_ed25519")
        elif os.path.exists(keys_dir) and os.path.isdir(keys_dir):
            pub_files = [f for f in os.listdir(keys_dir) if f.endswith(".pub") and not f.endswith("-cert.pub")]
            if len(pub_files) == 1:
                identity_file = os.path.join(keys_dir, pub_files[0][:-4])
        if not identity_file and os.path.exists(os.path.expanduser("~/.ssh/id_ed25519")):
            identity_file = "~/.ssh/id_ed25519"

    return principal, identity_file

def find_valid_ephemeral_key(principal, mount, role):
    """Scans for an active, unexpired ephemeral key matching the target principal, mount, and role."""
    safe_mount = mount.replace('/', '_')
    temp_dir = tempfile.gettempdir()
    
    # 🌟 FIX: Strictly limit the search to sandboxes created for this specific CA and Role!
    search_pattern = os.path.join(temp_dir, f"vault-ssh-{safe_mount}-{role}-*", "id_ed25519-cert.pub")
    cert_paths = glob.glob(search_pattern)
    
    for cert in cert_paths:
        try:
            res = subprocess.run(["ssh-keygen", "-L", "-f", cert], capture_output=True, text=True, check=True)
            lines = res.stdout.strip().split('\n')
            
            valid_str = ""
            principals = []
            parsing_principals = False
            
            for line in lines:
                line = line.strip()
                if line.startswith("Valid:"):
                    valid_str = line.split(":", 1)[1].strip()
                elif line.startswith("Principals:"):
                    parsing_principals = True
                elif parsing_principals:
                    if line.startswith("Critical Options:") or line.startswith("Extensions:"):
                        parsing_principals = False
                    elif line and line != "(none)":
                        principals.append(line)
            
            # Check if this cert grants access to our desired user
            if principal not in principals:
                continue
                
            # Check if it has at least 30 seconds of life left
            if " to " in valid_str:
                to_date_str = valid_str.split(" to ")[1].strip()
                to_date = datetime.fromisoformat(to_date_str)
                if (to_date - datetime.now()).total_seconds() > 30:
                    return cert.replace("-cert.pub", "")
        except Exception:
            continue
            
    return None

def get_args():
    parser = argparse.ArgumentParser(description="Vault SSH Certificate Authority Manager")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO
    p_info = subparsers.add_parser("info", help="Introspect the current SSH CA session")

    # 2. EXEC
    p_exec = subparsers.add_parser("exec", help="Sign your SSH key and connect to a host")
    p_exec.add_argument("engine", help="Mount point (e.g., ssh)")
    p_exec.add_argument("role", help="Vault SSH Role")
    p_exec.add_argument("target_host", help="The SSH host to connect to (e.g., db-prod)")
    p_exec.add_argument("--key", help="Explicit path to public key (overrides ~/.ssh/config)")
    p_exec.add_argument("--ephemeral", action="store_true", help="Force generation of a temporary, one-time-use SSH key")
    p_exec.add_argument("exec_cmd", nargs='*', help="The command to execute (prefix with '--')")

    # 3. ENGINE
    p_engine = subparsers.add_parser("engine", help="Manage SSH CA Engines")
    p_engine.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_engine.add_argument("mount", nargs="?", default="ssh", help="Mount point")

    # 4. ROLE
    p_role = subparsers.add_parser("role", help="Manage SSH Roles (Principals & Access)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
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
        cert_paths = []
        
        # 1. Check Standard Permanent Keys
        for target_dir in ["~/.ssh", "~/.ssh/keys"]:
            search_path = os.path.expanduser(target_dir)
            if os.path.exists(search_path) and os.path.isdir(search_path):
                for f in os.listdir(search_path):
                    if f.endswith("-cert.pub"):
                        cert_paths.append(os.path.join(search_path, f))
                        
        # 2. Check Ephemeral Key Directories (Active Sessions)
        temp_dir = tempfile.gettempdir()
        ephemeral_certs = glob.glob(os.path.join(temp_dir, "vault-ssh-*", "*-cert.pub"))
        cert_paths.extend(ephemeral_certs)
                
        if not cert_paths:
            print("❌ No active local SSH certificates (*-cert.pub) found.", file=sys.stderr)
            sys.exit(1)
            
        print("🔍 Introspecting Active SSH Certificates...")
        for cert in cert_paths:
            try:
                res = subprocess.run(["ssh-keygen", "-L", "-f", cert], capture_output=True, text=True, check=True)
                lines = res.stdout.strip().split('\n')
                
                key_id = "Unknown"
                principals = []
                valid_str = "Unknown"
                time_str = "Unknown"
                
                parsing_principals = False
                for line in lines:
                    line = line.strip()
                    if line.startswith("Key ID:"):
                        key_id = line.split(":", 1)[1].strip().strip('"')
                    elif line.startswith("Valid:"):
                        valid_str = line.split(":", 1)[1].strip()
                        if " to " in valid_str:
                            to_date_str = valid_str.split(" to ")[1].strip()
                            try:
                                to_date = datetime.fromisoformat(to_date_str)
                                now = datetime.now()
                                if now < to_date:
                                    rem = int((to_date - now).total_seconds())
                                    mins = rem // 60
                                    time_str = f"{mins} minutes ({rem}s)"
                                else:
                                    time_str = "EXPIRED ⚠️"
                            except ValueError:
                                time_str = valid_str
                    elif line.startswith("Principals:"):
                        parsing_principals = True
                        continue
                    elif parsing_principals:
                        if line.startswith("Critical Options:") or line.startswith("Extensions:"):
                            parsing_principals = False
                        else:
                            if line and line != "(none)":
                                principals.append(line)
                                
                is_ephemeral = "vault-ssh-" in cert
                badge = " (👻 Ephemeral Sandbox Key)" if is_ephemeral else ""
                
                print(f"\n📄 Certificate : {cert}{badge}")
                print(f"🆔 Key ID      : {key_id}")
                print(f"👤 Principals  : {', '.join(principals) if principals else 'None'}")
                print(f"⏳ Time Remaining: {time_str}")
                if "EXPIRED" in time_str:
                    print(f"   (Valid was: {valid_str})")

            except Exception as e:
                print(f"⚠️ Could not parse {cert}: {e}")
                
        sys.exit(0)

    # -------------------------------------------------------------------------
    # 2. EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        mount = args.engine.strip('/')
        target_host = args.target_host
        
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        
        use_ephemeral = args.ephemeral
        principal = None
        identity_file = None

        if not use_ephemeral:
            if args.key:
                principal = os.environ.get("USER", "root")
                identity_file = args.key
            else:
                principal, identity_file = parse_ssh_config(target_host)
                
            if not identity_file:
                use_ephemeral = True
                if not principal:
                    principal = os.environ.get("USER", "root")

        temp_dir = None
        exit_code = 1

        try:
            # --- EPHEMERAL FLOW ---
            if use_ephemeral:
                if not principal: principal = os.environ.get("USER", "root")
                
                # 🌟 FIX: Pass mount and role to guarantee cryptographic isolation!
                existing_key = find_valid_ephemeral_key(principal, mount, args.role)
                
                if existing_key:
                    print(f"♻️  Reusing active ephemeral key for Mount: '{mount}' | Role: '{args.role}'...", file=sys.stderr)
                    identity_file = existing_key
                else:
                    if not args.ephemeral:
                        print(f"ℹ️  No valid local SSH key found. Falling back to ephemeral key generation.", file=sys.stderr)
                        
                    # 🌟 FIX: Encode the mount and role into the temporary directory name
                    safe_mount = mount.replace('/', '_')
                    temp_dir = tempfile.mkdtemp(prefix=f"vault-ssh-{safe_mount}-{args.role}-")
                    os.chmod(temp_dir, 0o700)
                    identity_file = os.path.join(temp_dir, "id_ed25519")
                    
                    print(f"🔐 Generating temporary ephemeral SSH key...", file=sys.stderr)
                    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", identity_file, "-N", "", "-q", "-C", "vault-ephemeral"], check=True)
                    
                    pub_key_path = f"{identity_file}.pub"
                    with open(pub_key_path, 'r') as f: pub_key = f.read()
                    
                    print(f"🔍 Resolved target '{target_host}': Principal '{principal}'", file=sys.stderr)
                    print(f"🔒 Requesting signed ephemeral SSH certificate from Vault...", file=sys.stderr)
                    signed_key = vault.sign_ssh_key(args.role, mount, pub_key, principal)
                    if not signed_key: sys.exit(1)
                    
                    cert_path = f"{identity_file}-cert.pub"
                    with open(cert_path, 'w') as f: f.write(signed_key)
                
            # --- STANDARD FLOW ---
            else:
                identity_file = os.path.expanduser(identity_file)
                if identity_file.endswith(".pub"):
                    pub_key_path = identity_file
                    identity_file = identity_file[:-4]
                else:
                    pub_key_path = f"{identity_file}.pub"
                
                if not os.path.exists(pub_key_path):
                    print(f"❌ Error: Public key not found at {pub_key_path}", file=sys.stderr)
                    sys.exit(1)
                    
                with open(pub_key_path, 'r') as f: pub_key = f.read()
                    
                print(f"🔍 Resolved target '{target_host}': Principal '{principal}', Key '{pub_key_path}'", file=sys.stderr)
                print(f"🔒 Requesting signed SSH certificate from Vault...", file=sys.stderr)
                
                signed_key = vault.sign_ssh_key(args.role, mount, pub_key, principal)
                if not signed_key: sys.exit(1)
                
                cert_path = f"{identity_file}-cert.pub"
                with open(cert_path, 'w') as f: f.write(signed_key)
                    
                print(f"✅ Certificate saved to {cert_path} and ready for use.", file=sys.stderr)

            # Build the SSH command
            ssh_command = ["ssh"]
            if use_ephemeral:
                ssh_command.extend(["-i", identity_file, "-o", "IdentitiesOnly=yes"])
                
            ssh_command.append(target_host)
            
            if command_list:
                ssh_command.extend(command_list)
            
            print(f"🚀 Connecting to {target_host}...\n" + "-"*40, file=sys.stderr)
            exit_code = subprocess.run(ssh_command).returncode

        finally:
            # 🧹 SECURITY: Shred ephemeral keys on exit (but ONLY if this shell created it!)
            if temp_dir and os.path.exists(temp_dir):
                print(f"\n🧹 Shredding temporary SSH keys...", file=sys.stderr)
                shutil.rmtree(temp_dir, ignore_errors=True)
                
            sys.exit(exit_code)

    # -------------------------------------------------------------------------
    # 3. ENGINE
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action
        mount = args.mount.strip('/')
        
        if action == "list":
            engines = vault.list_engines(backend_type="ssh")
            if engines:
                print("🌐 Active SSH CA Engines:")
                for e in engines: print(f"  ├─ {e}")
            else:
                print("ℹ️ No SSH CA Engines mounted.")
            sys.exit(0)
            
        elif action == "create":
            print(f"🚀 Configuring SSH CA Engine at '{mount}/'...")
            if vault.setup_ssh_engine(mount):
                print(f"🎉 SSH CA enabled at '{mount}/'")
                
        elif action in ["read", "info"]:
            client = vault._get_client()
            try:
                res = client.read(f"{mount}/config/ca")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else:
                    print(f"❌ No CA config found at '{mount}/'")
            except Exception as e:
                print(f"❌ Error reading SSH engine: {e}")
                
        elif action == "update":
            print("ℹ️ Update action is not applicable to SSH CA root engine. Use 'role update' instead.")
                
        elif action == "delete":
            print(f"🧹 Tearing down SSH CA engine at '{mount}/'...")
            if vault.teardown_ssh_engine(mount):
                print(f"🎉 Engine destroyed!")

    # -------------------------------------------------------------------------
    # 4. ROLE
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        mount = args.mount.strip('/')
        role_name = args.role_name
        
        if action == "list":
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
            
        if not role_name:
            print("❌ Error: role_name is required for this action.", file=sys.stderr)
            sys.exit(1)
            
        if action in ["create", "update"]:
            print(f"🚀 {action.capitalize()}ing SSH Role '{role_name}'...")
            if vault.create_ssh_role(role_name, mount, args.default_user, args.allowed_users, args.ttl):
                print(f"✅ SSH Role '{role_name}' successfully configured.")
                
        elif action in ["read", "info"]:
            client = vault._get_client()
            try:
                res = client.read(f"{mount}/roles/{role_name}")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else:
                    print(f"❌ Role '{role_name}' not found.")
            except Exception as e:
                print(f"❌ Error reading role: {e}")
                
        elif action == "delete":
            client = vault._get_client()
            try:
                client.delete(f"{mount}/roles/{role_name}")
                print(f"✅ Deleted SSH role '{role_name}'.")
            except Exception as e:
                print(f"❌ Error deleting SSH role: {e}")

if __name__ == "__main__":
    main()
