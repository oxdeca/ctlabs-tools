# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_ldap.py
# Purpose : Dedicated CLI for Vault LDAP Secrets Engine
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import os
import subprocess
import time
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault LDAP Secrets Engine Manager")
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. EXEC (JIT Execution)
    p_exec = subparsers.add_parser("exec", help="Run a command with JIT LDAP credentials")
    p_exec.add_argument("engine", help="The LDAP engine mount (e.g., ldap)")
    p_exec.add_argument("role", help="The Vault LDAP Secret Role to assume")
    p_exec.add_argument("exec_cmd", nargs='*', help="The command to execute (prefix with '--')")

    # 2. ENGINE (Bootstrap)
    p_engine = subparsers.add_parser("engine", help="Manage LDAP Secrets Engines")
    p_engine.add_argument("action", choices=["create", "delete", "list", "read", "update"], help="Action to perform")
    p_engine.add_argument("mount", nargs="?", default="ldap", help="Mount point (default: ldap)")
    p_engine.add_argument("--url", help="LDAP server URL (e.g., ldaps://ldap.example.com)")
    p_engine.add_argument("--bind-dn", help="DN of the master binding account")
    p_engine.add_argument("--bind-pass", help="Password for the master binding account")
    p_engine.add_argument("--user-dn", help="Base DN where dynamic users will be created")

    # 3. ROLE (Access Profiles)
    p_role = subparsers.add_parser("role", help="Manage LDAP Roles (LDIF templates)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list"], help="Action to perform")
    p_role.add_argument("mount", nargs="?", default="ldap", help="Mount point")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--creation-ldif", help="File path to the LDIF template for creating the user")
    p_role.add_argument("--deletion-ldif", help="File path to the LDIF template for deleting the user")

    # 4. INFO (Introspection)
    p_info = subparsers.add_parser("info", help="Introspect the active JIT LDAP token in your shell")

    # 5. LEASES
    p_leases = subparsers.add_parser("leases", help="Manage dynamic LDAP leases")
    leases_subs = p_leases.add_subparsers(dest="action", required=True)
    p_leases_list = leases_subs.add_parser("list", help="List active LDAP leases")
    p_leases_list.add_argument("mount", nargs="?", default="ldap", help="The mount point")
    p_leases_revoke = leases_subs.add_parser("revoke", help="Revoke leases")
    p_leases_revoke.add_argument("mount", help="The mount point")
    p_leases_revoke.add_argument("--id", help="Revoke a specific lease ID")
    p_leases_revoke.add_argument("--force", action="store_true", help="Force revoke ALL leases for this mount")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # 1. EXEC
    # -------------------------------------------------------------------------
    if cmd == "exec":
        mount_point = args.engine.strip('/')
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        print(f"🔒 Requesting dynamic LDAP credentials for role '{args.role}'...", file=sys.stderr)
        creds = vault.get_ldap_credentials(role_name=args.role, mount_point=mount_point)
        if not creds: sys.exit(1)

        username = creds.get('username')
        password = creds.get('password')

        # Try to extract the server URL from the engine config so we can inject it
        engine_config = vault.read_ldap_engine_config(mount_point)
        ldap_uri = engine_config.get("url", "") if engine_config else ""
        
        # Inject standard LDAP environment variables
        os.environ["LDAP_USERNAME"] = username
        os.environ["LDAP_PASSWORD"] = password
        os.environ["LDAP_BINDDN"]   = username # Many tools use BINDDN
        if ldap_uri:
            os.environ["LDAP_URI"] = ldap_uri
            os.environ["LDAPURL"]  = ldap_uri

        print(f"✅ Generated dynamic user: {username}", file=sys.stderr)
        print(f"🚀 Executing command...\n" + "-"*40, file=sys.stderr)

        if command_list == ["bash"]:
            import tempfile
            rc_content = f"""
if [ -f ~/.bashrc ]; then source ~/.bashrc; fi
export PS1="\\[\\e[33m\\][LDAP JIT: {args.role}]\\[\\e[m\\] \\w \\$ "
echo "🔒 Vault JIT LDAP Session Active!"
echo "👤 User: {username}"
echo "👉 Credentials injected as \\$LDAP_BINDDN and \\$LDAP_PASSWORD"
"""
            fd, rc_path = tempfile.mkstemp(suffix=".bashrc")
            with os.fdopen(fd, 'w') as f:
                f.write(rc_content)
                
            try:
                exit_code = subprocess.run(["bash", "--rcfile", rc_path], env=os.environ).returncode
                os.remove(rc_path)
                sys.exit(exit_code)
            except Exception as e:
                print(f"❌ Error starting shell: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            try:
                sys.exit(subprocess.run(command_list, env=os.environ).returncode)
            except FileNotFoundError:
                print(f"\n❌ Error: Command not found: {command_list[0]}", file=sys.stderr)
                sys.exit(1)

    # -------------------------------------------------------------------------
    # 2. ENGINE
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        mount_point = args.mount.strip('/')
        
        if args.action == "list":
            engines = vault.list_engines(backend_type="ldap")
            if engines:
                print("🌐 Active LDAP Secrets Engines:")
                for e in engines: print(f"  ├─ {e}")
            else:
                print("ℹ️ No LDAP Secrets Engines mounted.")
            sys.exit(0)

        if args.action == "create":
            if not all([args.url, args.bind_dn, args.bind_pass, args.user_dn]):
                print("❌ Error: --url, --bind-dn, --bind-pass, and --user-dn are required for creation.", file=sys.stderr)
                sys.exit(1)
            print(f"🚀 Configuring LDAP Engine at '{mount_point}/'...")
            if vault.setup_ldap_engine(mount_point, args.url, args.bind_dn, args.bind_pass, args.user_dn):
                print(f"🎉 LDAP Secrets Engine ready at '{mount_point}/'!")

        elif args.action == "delete":
            print(f"🧹 Tearing down LDAP engine at '{mount_point}/'...")
            if vault.teardown_ldap_engine(mount_point):
                print("🎉 Engine destroyed!")

        elif args.action == "read":
            config = vault.read_ldap_engine_config(mount_point)
            if config:
                if "bindpass" in config: config["bindpass"] = "*** REDACTED ***"
                print(json.dumps(config, indent=2))
            else:
                print("❌ Config not found.")
                
        elif args.action == "update":
            if vault.update_ldap_engine_config(mount_point, url=args.url, bind_dn=args.bind_dn, bind_pass=args.bind_pass, user_dn=args.user_dn):
                print("🎉 Successfully updated LDAP Engine Config!")

    # -------------------------------------------------------------------------
    # 3. ROLE
    # -------------------------------------------------------------------------
    elif cmd == "role":
        mount_point = args.mount.strip('/')
        
        if args.action == "list":
            roles = vault.list_ldap_roles(mount_point)
            if roles:
                print(f"👥 Active Roles at '{mount_point}/':")
                for r in roles: print(f"  ├─ {r}")
            else:
                print("ℹ️ No roles found.")
            sys.exit(0)

        if not args.role_name:
            print("❌ Error: role_name is required.", file=sys.stderr)
            sys.exit(1)

        if args.action == "read":
            data = vault.read_ldap_role(args.role_name, mount_point)
            if data: print(json.dumps(data, indent=2))
            
        elif args.action == "delete":
            if vault.delete_ldap_role(args.role_name, mount_point):
                print(f"✅ Deleted LDAP role '{args.role_name}'.")
            
        elif args.action in ["create", "update"]:
            if not args.creation_ldif or not args.deletion_ldif:
                print("❌ Error: --creation-ldif and --deletion-ldif files are required.", file=sys.stderr)
                sys.exit(1)
            
            try:
                with open(args.creation_ldif, 'r') as f: creation_content = f.read()
                with open(args.deletion_ldif, 'r') as f: deletion_content = f.read()
            except Exception as e:
                print(f"❌ Error reading LDIF files: {e}", file=sys.stderr)
                sys.exit(1)
                
            if vault.create_ldap_role(args.role_name, mount_point, creation_content, deletion_content):
                print(f"✅ LDAP Role '{args.role_name}' successfully configured.")

    # -------------------------------------------------------------------------
    # 4. INFO & LEASES
    # -------------------------------------------------------------------------
    elif cmd == "info":
        user = os.environ.get("LDAP_USERNAME")
        if not user:
            print("❌ No active LDAP JIT session found.", file=sys.stderr)
            sys.exit(1)
        print("🔍 Introspecting LDAP JIT Credential...")
        print(f"👤 Username : {user}")
        print(f"🌐 LDAP URI : {os.environ.get('LDAP_URI', 'Unknown')}")
        
    elif cmd == "leases":
        mount_point = args.mount.strip('/')
        if args.action == "list":
            roles = vault.list_leases(f"{mount_point}/creds/")
            if roles:
                print(f"\n📁 Active Leases for Engine: {mount_point}/")
                for role in roles:
                    lease_ids = vault.list_leases(f"{mount_point}/creds/{role}")
                    for lid in lease_ids:
                        print(f"  ├─ {mount_point}/creds/{role}{lid}")
            else:
                print("✅ No active LDAP leases found.")
                
        elif args.action == "revoke":
            if getattr(args, "id", None):
                if vault.revoke_lease(args.id): print("✅ Lease successfully revoked.")
            elif getattr(args, "force", False):
                if vault.force_revoke_prefix(mount_point): print("✅ All cluster leases forcefully wiped.")
            else:
                print("⚠️ Provide '--id <lease_id>' or use '--force'.")

if __name__ == "__main__":
    main()
