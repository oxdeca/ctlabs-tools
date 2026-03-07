# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_ssh.py
# -----------------------------------------------------------------------------

import argparse, sys, os, subprocess
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
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    # EXEC
    p_exec = subparsers.add_parser("exec", help="Sign your SSH key and connect to a host")
    p_exec.add_argument("engine", help="Mount point (e.g., ssh)")
    p_exec.add_argument("role", help="Vault SSH Role")
    p_exec.add_argument("target_host", help="The SSH host to connect to (e.g., db-prod)")
    p_exec.add_argument("exec_cmd", nargs='*', help="Optional command to run remotely (prefix with '--')")

    # ENGINE
    p_engine = subparsers.add_parser("engine")
    p_engine.add_argument("action", choices=["create", "delete"])
    p_engine.add_argument("mount", nargs="?", default="ssh")

    # ROLE
    p_role = subparsers.add_parser("role")
    p_role.add_argument("action", choices=["create", "delete"])
    p_role.add_argument("mount", default="ssh")
    p_role.add_argument("role_name")
    p_role.add_argument("--default-user", default="ubuntu")
    p_role.add_argument("--allowed-users", default="ubuntu,root")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault()
    if not vault.ensure_valid_token(interactive=False): sys.exit(1)

    cmd = args.command
    
    if cmd == "exec":
        mount = args.engine.strip('/')
        target_host = args.target_host
        
        # 🧠 SMART UX: Auto-resolve credentials from ~/.ssh/config!
        principal, identity_file = parse_ssh_config(target_host)
        
        # Clean up path (e.g., remove quotes or expand ~)
        identity_file = os.path.expanduser(identity_file.strip('"\''))
        pub_key_path = f"{identity_file}.pub"
        
        if not os.path.exists(pub_key_path):
            print(f"❌ Error: Public key not found at {pub_key_path}")
            sys.exit(1)
            
        with open(pub_key_path, 'r') as f:
            pub_key = f.read()
            
        print(f"🔍 Discovered config for '{target_host}': User '{principal}', Key '{pub_key_path}'")
        print(f"🔒 Requesting signed SSH certificate for principal '{principal}'...")
        
        signed_key = vault.sign_ssh_key(args.role, mount, pub_key, principal)
        if not signed_key: sys.exit(1)
        
        # Save the certificate exactly where SSH expects it
        cert_path = pub_key_path.replace(".pub", "-cert.pub")
        with open(cert_path, 'w') as f:
            f.write(signed_key)
            
        print(f"✅ Certificate saved to {cert_path}")
        
        # Build the SSH command
        ssh_command = ["ssh", target_host]
        
        # If the user passed extra commands (like `vault-ssh exec ssh my-role db-prod -- ls -la`), append them
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--": 
            ssh_command.extend(command_list[1:])
        
        print(f"🚀 Connecting to {target_host}...\n" + "-"*40)
        sys.exit(subprocess.run(ssh_command).returncode)

    elif cmd == "engine":
        mount = args.mount.strip('/')
        if args.action == "create":
            if vault.setup_ssh_engine(mount): print(f"🎉 SSH CA enabled at '{mount}/'")
        elif args.action == "delete":
            if vault.teardown_ssh_engine(mount): print(f"🧹 SSH CA removed at '{mount}/'")

    elif cmd == "role":
        mount = args.mount.strip('/')
        if args.action == "create":
            if vault.create_ssh_role(args.role_name, mount, args.default_user, args.allowed_users):
                print(f"✅ SSH Role '{args.role_name}' created.")
        elif args.action == "delete":
            pass

if __name__ == "__main__":
    main()

