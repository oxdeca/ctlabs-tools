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

    # 1. INFO (Global Introspection)
    p_info = subparsers.add_parser("info", help="Introspect the active JIT LDAP token in your shell")

    # 2. EXEC (JIT Execution)
    p_exec = subparsers.add_parser("exec", help="Run a command with JIT LDAP credentials")
    p_exec.add_argument("name", help="The LDAP engine name (e.g., primary, auto-mounted at ldap/primary)")
    p_exec.add_argument("role", help="The Vault LDAP Secret Role to assume")
    p_exec.add_argument("exec_cmd", nargs='*', help="The command to execute (prefix with '--')")

    # 3. ENGINE (Bootstrap)
    p_engine = subparsers.add_parser("engine", help="Manage LDAP Secrets Engines")
    p_engine.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_engine.add_argument("name", nargs="?", default="", help="Engine name (e.g., primary)")
    p_engine.add_argument("--url", help="LDAP server URL (e.g., ldaps://ldap.example.com)")
    p_engine.add_argument("--bind-dn", help="DN of the master binding account")
    p_engine.add_argument("--bind-pass", help="Password for the master binding account")
    p_engine.add_argument("--user-dn", help="Base DN where dynamic users will be created")

    # 4. ROLE (Access Profiles)
    p_role = subparsers.add_parser("role", help="Manage LDAP Roles (LDIF templates)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_role.add_argument("engine_name", nargs="?", default="", help="Engine name")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--creation-ldif", help="File path to the LDIF template for creating the user")
    p_role.add_argument("--deletion-ldif", help="File path to the LDIF template for deleting the user")

    # 5. LEASES
    p_leases = subparsers.add_parser("leases", help="Manage dynamic LDAP leases")
    leases_subs = p_leases.add_subparsers(dest="action", required=True)
    
    p_leases_list = leases_subs.add_parser("list", help="List active LDAP leases")
    p_leases_list.add_argument("name", nargs="?", default="", help="Engine name (leave blank to search all)")
    
    p_leases_revoke = leases_subs.add_parser("revoke", help="Revoke leases")
    p_leases_revoke.add_argument("name", help="Engine name")
    p_leases_revoke.add_argument("--id", help="Revoke a specific lease ID")
    p_leases_revoke.add_argument("--force", action="store_true", help="Force revoke ALL leases for this engine")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # 1. INFO (Global)
    # -------------------------------------------------------------------------
    if cmd == "info":
        user = os.environ.get("LDAP_USERNAME")
        if not user:
            print("❌ No active LDAP JIT session found in this shell.", file=sys.stderr)
            sys.exit(1)
            
        print("🔍 Introspecting Active LDAP JIT Credential...")
        print(f"👤 Username : {user}")
        print(f"🌐 LDAP URI : {os.environ.get('LDAP_URI', 'Unknown')}")
        print(f"🔑 Password : {'*' * 8} (Stored securely in memory)")
        sys.exit(0)

    # -------------------------------------------------------------------------
    # 2. EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        name = args.name.strip('/')
        mount_point = f"ldap/{name}"
        
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        print(f"🔒 Requesting dynamic LDAP credentials for role '{args.role}' from '{mount_point}/'...", file=sys.stderr)
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
        os.environ["LDAP_BINDDN"]   = username # Many standard LDAP tools use BINDDN
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
    # 3. ENGINE
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action
        name = getattr(args, 'name', '').strip('/')
        mount = f"ldap/{name}" if name else ""
        
        if action == "list":
            engines = vault.list_engines(backend_type="ldap")
            if engines:
                print("🌐 Active LDAP Secrets Engines:")
                for e in engines: 
                    if e.startswith("ldap/"): print(f"  ├─ {e}")
            else:
                print("ℹ️ No LDAP Secrets Engines mounted.")
            sys.exit(0)

        if not name:
            print("❌ Error: Engine name is required.", file=sys.stderr)
            sys.exit(1)

        if action == "create":
            if not all([args.url, args.bind_dn, args.bind_pass, args.user_dn]):
                print("❌ Error: --url, --bind-dn, --bind-pass, and --user-dn are required for creation.", file=sys.stderr)
                sys.exit(1)
            print(f"🚀 Configuring LDAP Engine at '{mount}/'...")
            if vault.setup_ldap_engine(mount, args.url, args.bind_dn, args.bind_pass, args.user_dn):
                print(f"🎉 LDAP Secrets Engine ready at '{mount}/'!")

        elif action == "delete":
            print(f"🧹 Tearing down LDAP engine at '{mount}/'...")
            if vault.teardown_ldap_engine(mount):
                print("🎉 Engine destroyed!")

        elif action == "read":
            config = vault.read_ldap_engine_config(mount)
            if config:
                if "bindpass" in config: config["bindpass"] = "*** REDACTED ***"
                print(json.dumps(config, indent=2))
            else:
                print(f"❌ Config not found at '{mount}/'.")
                
        elif action == "info":
            config = vault.read_ldap_engine_config(mount)
            if config:
                print(f"🏛️  LDAP Engine: {mount}/")
                print(f"  ├─ URL      : {config.get('url', 'Unknown')}")
                print(f"  ├─ Bind DN  : {config.get('binddn', 'Unknown')}")
                print(f"  ├─ User DN  : {config.get('userdn', 'Unknown')}")
            else:
                print(f"❌ Config not found at '{mount}/'.")
                
        elif action == "update":
            if vault.update_ldap_engine_config(mount, url=args.url, bind_dn=args.bind_dn, bind_pass=args.bind_pass, user_dn=args.user_dn):
                print(f"🎉 Successfully updated LDAP Engine Config at '{mount}/'!")

    # -------------------------------------------------------------------------
    # 4. ROLE
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        engine_name = getattr(args, 'engine_name', '').strip('/')
        mount = f"ldap/{engine_name}" if engine_name else ""
        role_name = getattr(args, 'role_name', '')
        
        if action == "list":
            if mount:
                engines_to_check = [mount]
            else:
                print("🔍 Searching across all active LDAP engines...")
                engines = vault.list_engines(backend_type="ldap") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("ldap/")]

            if not engines_to_check:
                print("ℹ️ No LDAP Engines currently mounted.")
                sys.exit(0)

            found_any = False
            for m in engines_to_check:
                roles = vault.list_ldap_roles(m)
                if roles:
                    found_any = True
                    print(f"\n👥 Active LDAP Roles at '{m}/':")
                    for r in roles: print(f"  ├─ {r}")
            
            if not found_any: print("\nℹ️ No LDAP roles found.")
            sys.exit(0)

        if not engine_name or not role_name:
            print("❌ Error: engine_name and role_name are required.", file=sys.stderr)
            sys.exit(1)

        if action == "read":
            data = vault.read_ldap_role(role_name, mount)
            if data: print(json.dumps(data, indent=2))
            else: print(f"❌ Role '{role_name}' not found.")
            
        elif action == "info":
            data = vault.read_ldap_role(role_name, mount)
            if data:
                print(f"👥 LDAP Role: {role_name}")
                print(f"  ├─ Engine        : {mount}/")
                print(f"  ├─ Default TTL   : {data.get('default_ttl', 'System Default')}s")
                print(f"  ├─ Max TTL       : {data.get('max_ttl', 'System Default')}s")
                
                creation = data.get('creation_ldif', '')
                deletion = data.get('deletion_ldif', '')
                print(f"  ├─ Creation LDIF : {len(creation.splitlines())} lines")
                print(f"  ├─ Deletion LDIF : {len(deletion.splitlines())} lines")
            else:
                print(f"❌ Role '{role_name}' not found.")
            
        elif action == "delete":
            if vault.delete_ldap_role(role_name, mount):
                print(f"✅ Deleted LDAP role '{role_name}' from '{mount}/'.")
            
        elif action in ["create", "update"]:
            if not args.creation_ldif or not args.deletion_ldif:
                print("❌ Error: --creation-ldif and --deletion-ldif files are required.", file=sys.stderr)
                sys.exit(1)
            
            try:
                with open(args.creation_ldif, 'r') as f: creation_content = f.read()
                with open(args.deletion_ldif, 'r') as f: deletion_content = f.read()
            except Exception as e:
                print(f"❌ Error reading LDIF files: {e}", file=sys.stderr)
                sys.exit(1)
                
            if vault.create_ldap_role(role_name, mount, creation_content, deletion_content):
                print(f"✅ LDAP Role '{role_name}' successfully configured.")

    # -------------------------------------------------------------------------
    # 5. LEASES
    # -------------------------------------------------------------------------
    elif cmd == "leases":
        action = args.action
        name = getattr(args, 'name', '').strip('/')
        mount = f"ldap/{name}" if name else ""
        
        if action == "list":
            if mount:
                engines_to_check = [mount]
            else:
                print("🔍 Searching across all active LDAP engines...")
                engines = vault.list_engines(backend_type="ldap") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("ldap/")]
            
            if not engines_to_check:
                print("ℹ️ No LDAP Engines currently mounted.")
                sys.exit(0)

            found_any = False
            for m in engines_to_check:
                roles = vault.list_leases(f"{m}/creds/")
                if roles:
                    found_any = True
                    print(f"\n📁 Active Leases for Engine: {m}/")
                    for role in roles:
                        lease_ids = vault.list_leases(f"{m}/creds/{role}")
                        for lid in lease_ids:
                            print(f"  ├─ {m}/creds/{role}{lid}")
            
            if not found_any:
                print("✅ No active LDAP leases found.")
                
        elif action == "revoke":
            if not name:
                print("❌ Error: Engine name is required for revoke.", file=sys.stderr)
                sys.exit(1)
                
            if getattr(args, "id", None):
                if vault.revoke_lease(args.id): print("✅ Lease successfully revoked.")
            elif getattr(args, "force", False):
                if vault.force_revoke_prefix(mount): print(f"✅ All cluster leases for '{mount}/' forcefully wiped.")
            else:
                print("⚠️ Provide '--id <lease_id>' or use '--force'.")

if __name__ == "__main__":
    main()
