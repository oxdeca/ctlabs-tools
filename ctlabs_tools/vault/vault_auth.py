# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_auth.py
# Purpose : Dedicated CLI for Vault Authentication & Policy Management
# -----------------------------------------------------------------------------

import argparse
import sys
import json
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Authentication & Policy Manager")
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. APPROLE
    p_approle = subparsers.add_parser("approle", help="Manage Machine Identities (AppRoles)")
    p_approle.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_approle.add_argument("name", nargs="?", default="", help="Name of the AppRole")
    p_approle.add_argument("--ttl", default="1h", help="Token TTL (e.g. 1h, 30m) (used with create/update)")
    p_approle.add_argument("--policies", help="Comma-separated list of policies (used with create/update)")

    # 2. USER
    p_user = subparsers.add_parser("user", help="Manage Human Identities (Userpass / LDAP)")
    p_user.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_user.add_argument("name", nargs="?", default="", help="Username")
    p_user.add_argument("--method", choices=["userpass", "ldap"], help="Auth method (defaults to 'userpass' for create/read, 'all' for list)")
    p_user.add_argument("--password", help="Password (required for creating userpass users)")
    p_user.add_argument("--policies", help="Comma-separated list of policies")

    # 3. POLICY
    p_policy = subparsers.add_parser("policy", help="Manage Vault ACL Policies")
    p_policy.add_argument("action", choices=["create", "update", "read", "delete", "list"], help="Action to perform")
    p_policy.add_argument("name", nargs="?", default="", help="Name of the policy")
    p_policy.add_argument("--file", help="Path to an HCL file containing the policy rules (used with create/update)")

    # 4. GROUP
    p_group = subparsers.add_parser("group", help="Manage Auth Method Groups (e.g., LDAP groups)")
    p_group.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_group.add_argument("name", nargs="?", default="", help="Name of the group in LDAP")
    p_group.add_argument("--method", choices=["ldap", "okta"], default="ldap", help="Auth method (default: ldap)")
    p_group.add_argument("--policies", help="Comma-separated list of policies to assign to this group")

    # 5. ENTITY
    p_entity = subparsers.add_parser("entity", help="Manage Vault Identity Entities")
    p_entity.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "merge"], help="Action to perform")
    p_entity.add_argument("name", nargs="?", default="", help="Name of the entity (Source entity for merge)")
    p_entity.add_argument("--policies", help="Comma-separated list of policies to assign")
    p_entity.add_argument("--target", help="Destination entity name (Required for merge)")

    # 6. ALIAS
    p_alias = subparsers.add_parser("alias", help="Manage Identity Aliases (Link logins to Entities)")
    p_alias.add_argument("action", choices=["create", "delete"], help="Action to perform")
    p_alias.add_argument("entity_name", help="The Vault Entity to link to (e.g., peter)")
    p_alias.add_argument("alias_name", help="The login username or RoleID (e.g., p.smith)")
    p_alias.add_argument("--mount", default="userpass", help="The auth mount point (e.g., ldap, userpass, approle)")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    
    # Fast-fail for CLI tools
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    action = args.action
    name = getattr(args, 'name', '')

    # Ensure name is provided for everything except 'list'
    if cmd != "alias" and action != "list" and not name:
        print(f"❌ Error: 'name' is required for the '{action}' action.", file=sys.stderr)
        sys.exit(1)

    # -------------------------------------------------------------------------
    # 1. APPROLE MANAGEMENT
    # -------------------------------------------------------------------------
    if cmd == "approle":
        if action == "list":
            roles = vault.list_approles()
            if roles:
                print("📋 Existing AppRoles:")
                for r in roles: print(f"  ├─ {r}")
            else:
                print("ℹ️ No AppRoles found.")
                
        elif action in ["create", "update"]:
            policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
            if vault.create_or_update_approle(name, policies, ttl=args.ttl):
                print(f"✅ AppRole '{name}' successfully created/updated.")
                
        elif action == "read":  # Retrieves RoleID and SecretID
            creds = vault.get_approle_credentials(name)
            if creds: print(json.dumps(creds, indent=2))
            else: print(f"⚠️ Could not generate credentials for AppRole '{name}'.")
            
        elif action == "info":  # Introspects the config
            details = vault.read_approle(name)
            if details: print(json.dumps(details, indent=2))
            else: print(f"⚠️ AppRole '{name}' not found.")
            
        elif action == "delete":
            if vault.delete_approle(name):
                print(f"✅ Deleted AppRole '{name}'.")

    # -------------------------------------------------------------------------
    # 2. USER MANAGEMENT (Userpass & LDAP)
    # -------------------------------------------------------------------------
    elif cmd == "user":
        # 🧠 SMART UX: If no method provided, check BOTH for list, default to userpass for others
        method = getattr(args, 'method', None)

        if action == "list":
            methods_to_check = [method] if method else ["userpass", "ldap"]
            found_any = False
            
            for m in methods_to_check:
                users = vault.list_users(auth_type=m)
                if users:
                    print(f"👥 Existing '{m}' users:")
                    for u in users: print(f"  ├─ {u}")
                    found_any = True
                    
            if not found_any:
                print(f"ℹ️ No users found.")
                
        else:
            # For create/update/read/delete, default to 'userpass' if not specified
            method = method or "userpass"
            
            if action in ["create", "update"]:
                if method == "userpass" and action == "create" and not args.password:
                    print("❌ Error: --password is required when creating a userpass user.", file=sys.stderr)
                    sys.exit(1)
                if vault.create_user(name, password=args.password, policies=args.policies, auth_type=method):
                    print(f"✅ User '{name}' ({method}) successfully created/updated.")
                    
            elif action in ["read", "info"]:
                details = vault.read_user(name, auth_type=method)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ User '{name}' not found in '{method}'.")
                
            elif action == "delete":
                if vault.delete_user(name, auth_type=method):
                    print(f"✅ Deleted user '{name}' ({method}).")

    # -------------------------------------------------------------------------
    # 3. POLICY MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "policy":
        if action == "list":
            policies = vault.list_policies()
            if policies:
                print("📜 Existing ACL Policies:")
                for p in policies: print(f"  ├─ {p}")
            else:
                print("ℹ️ No policies found.")
                
        elif action in ["create", "update"]:
            if not args.file:
                print("❌ Error: --file <path_to_hcl> is required to create or update a policy.", file=sys.stderr)
                sys.exit(1)
            try:
                with open(args.file, 'r') as f:
                    rules = f.read()
                    
                # 🧠 FIX: Use our new clean abstraction layer
                if vault.create_policy(name, rules):
                    print(f"✅ Policy '{name}' successfully created/updated from {args.file}.")
            except Exception as e:
                print(f"❌ Error managing policy '{name}': {e}", file=sys.stderr)
                sys.exit(1)
                
        elif action == "read":
            rules = vault.read_policy(name)
            if rules: print(rules)  # Print raw HCL string
            else: print(f"⚠️ Policy '{name}' not found.")
            
        elif action == "delete":
            if vault.delete_policy(name):
                print(f"✅ Deleted policy '{name}'.")

    # -------------------------------------------------------------------------
    # 4. GROUP MANAGEMENT (LDAP/OIDC)
    # -------------------------------------------------------------------------
    elif cmd == "group":
        method = getattr(args, 'method', 'ldap')
        
        if action == "list":
            groups = vault.list_groups(auth_type=method)
            if groups:
                print(f"🏢 Existing '{method}' group mappings:")
                for g in groups: print(f"  ├─ {g}")
            else:
                print(f"ℹ️ No '{method}' groups found.")
                
        else:
            if not name:
                print(f"❌ Error: 'name' is required for the '{action}' action.", file=sys.stderr)
                sys.exit(1)
                
            if action in ["create", "update"]:
                if not args.policies:
                    print("⚠️ Warning: Creating a group without --policies means it grants no access.", file=sys.stderr)
                if vault.create_group(name, policies=args.policies, auth_type=method):
                    print(f"✅ Group '{name}' ({method}) successfully mapped.")
                    
            elif action in ["read", "info"]:
                details = vault.read_group(name, auth_type=method)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ Group '{name}' not found in '{method}'.")
                
            elif action == "delete":
                if vault.delete_group(name, auth_type=method):
                    print(f"✅ Deleted group mapping '{name}' ({method}).")

    # -------------------------------------------------------------------------
    # 5. ENTITY MANAGEMENT (Identity Secrets Engine)
    # -------------------------------------------------------------------------
    elif cmd == "entity":
        if action == "list":
            entities = vault.list_entities()
            if entities:
                print("👤 Existing Identity Entities:")
                for e in entities: print(f"  ├─ {e}")
            else:
                print("ℹ️ No entities found.")
                
        else:
            if not name:
                print(f"❌ Error: 'name' is required for the '{action}' action.", file=sys.stderr)
                sys.exit(1)
                
            if action in ["create", "update"]:
                if vault.create_entity(name, policies=args.policies):
                    print(f"✅ Entity '{name}' successfully created/updated.")
                    
            elif action in ["read", "info"]:
                details = vault.read_entity(name)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ Entity '{name}' not found.")

            elif action == "merge":
                if not args.target:
                    print("❌ Error: --target <destination_entity> is required when merging.", file=sys.stderr)
                    sys.exit(1)
                if vault.merge_entities(from_entity_name=name, to_entity_name=args.target):
                    print(f"✅ Successfully merged '{name}' into '{args.target}'. '{name}' has been deleted.")
                
            elif action == "delete":
                if vault.delete_entity(name):
                    print(f"✅ Deleted entity '{name}'.")

    # -------------------------------------------------------------------------
    # 6. ALIAS MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "alias":
        action = args.action
        entity_name = args.entity_name
        alias_name = args.alias_name
        mount = args.mount
        
        if action == "create":
            if vault.create_entity_alias(entity_name, alias_name, mount_point=mount):
                print(f"✅ Alias '{alias_name}' ({mount}) successfully linked to Entity '{entity_name}'.")
                
        elif action == "delete":
            if vault.delete_entity_alias(entity_name, alias_name, mount_point=mount):
                print(f"✅ Alias '{alias_name}' ({mount}) successfully removed from Entity '{entity_name}'.")


if __name__ == "__main__":
    main()
