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
    p_alias = subparsers.add_parser("alias", help="Manage Identity Aliases")
    p_alias.add_argument("action", choices=["create", "update", "read", "delete", "list"], help="Action to perform")
    p_alias.add_argument("alias_identifier", nargs="?", default="", help="Alias Name (for create) or Alias ID (for read/update/delete)")
    p_alias.add_argument("--entity", help="Entity name (required for create/update)")
    p_alias.add_argument("--mount", help="Auth mount path (e.g., userpass) (required for create/update)")

    # 7. KUBERNETES AUTH
    p_k8s = subparsers.add_parser("k8s", help="Manage Kubernetes Auth Roles & Configuration")
    p_k8s.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure"], help="Action to perform")
    p_k8s.add_argument("name", nargs="?", default="", help="Name of the Vault role (Required for all except list/configure)")
    
    # Flags for Role Management
    p_k8s.add_argument("--sa-names", help="Allowed K8s Service Accounts")
    p_k8s.add_argument("--sa-namespaces", help="Allowed K8s Namespaces")
    p_k8s.add_argument("--policies", help="Vault policies to grant")
    p_k8s.add_argument("--ttl", default="1h", help="Token TTL")
    
    # Flags for Backend Configuration (The "Phone Line")
    p_k8s.add_argument("--host", help="K8s API Host (for 'configure' action)")
    p_k8s.add_argument("--ca-cert", help="Path to K8s CA Cert file (for 'configure' action)")
    
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
            client = vault._get_client()
            try:
                res = client.list("identity/entity/name")
                if res and 'data' in res and 'keys' in res['data']:
                    keys = res['data']['keys']
                    print(f"👤 Existing Identity Entities ({len(keys)} found):")
                    for k in keys:
                        e_data = client.read(f"identity/entity/name/{k}")
                        if e_data and 'data' in e_data:
                            e_id = e_data['data'].get('id', 'Unknown')
                            aliases = e_data['data'].get('aliases', [])
                            print(f"  ├─ Name: {k} | ID: {e_id} | Aliases: {len(aliases)}")
                else:
                    print("ℹ️ No entities found.")
            except Exception as e:
                print(f"❌ Error fetching entity list: {e}", file=sys.stderr)
            sys.exit(0)
                
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
        alias_arg = args.alias_identifier
        entity_name = args.entity
        mount = args.mount
        client = vault._get_client()

        # ---------------------------------------------------------
        # LIST: Show all aliases globally to get their IDs
        # ---------------------------------------------------------
        if action == "list":
            try:
                res = client.list("identity/entity-alias/id")
                if res and 'data' in res and 'keys' in res['data']:
                    keys = res['data']['keys']
                    print(f"🔗 Global Aliases ({len(keys)} found):")
                    for k in keys:
                        a_data = client.read(f"identity/entity-alias/id/{k}")
                        if a_data and 'data' in a_data:
                            name = a_data['data'].get('name', 'Unknown')
                            mnt = a_data['data'].get('mount_path', 'Unknown')
                            canonical_id = a_data['data'].get('canonical_id')
                            
                            # 🧠 REVERSE LOOKUP: Fetch the parent entity name
                            parent_entity = "Unknown"
                            if canonical_id:
                                e_data = client.read(f"identity/entity/id/{canonical_id}")
                                if e_data and 'data' in e_data:
                                    parent_entity = e_data['data'].get('name', canonical_id)

                            print(f"  ├─ ID: {k} | Name: {name} | Mount: {mnt} | Entity: {parent_entity}")
                else:
                    print("ℹ️ No aliases found in Vault.")
            except Exception as e:
                print(f"❌ Error fetching alias list: {e}", file=sys.stderr)
            sys.exit(0)

        # 🧠 ENFORCE ALIAS ARGUMENT for all other actions
        if not alias_arg:
            print(f"❌ Error: Alias Name or ID is required for '{action}'.", file=sys.stderr)
            sys.exit(1)

        # ---------------------------------------------------------
        # READ: Dump the raw JSON using the Alias ID
        # ---------------------------------------------------------
        if action == "read":
            try:
                # You can now pass the ID you got from 'list' directly here
                res = client.read(f"identity/entity-alias/id/{alias_arg}")
                if res and 'data' in res: 
                    print(json.dumps(res['data'], indent=2))
                else: 
                    print(f"❌ Alias ID '{alias_arg}' not found.", file=sys.stderr)
            except Exception as e:
                print(f"❌ Error reading alias: {e}", file=sys.stderr)

        # ---------------------------------------------------------
        # CREATE / UPDATE: Vault treats POST as an upsert
        # ---------------------------------------------------------
        elif action in ["create", "update"]:
            if not entity_name or not mount:
                print("❌ Error: --entity and --mount are required to create/update an alias.", file=sys.stderr)
                sys.exit(1)
            print(f"🚀 {action.capitalize()}ing alias '{alias_arg}' for entity '{entity_name}'...")
            if vault.create_entity_alias(entity_name=entity_name, alias_name=alias_arg, mount_accessor_or_path=mount):
                print(f"✅ Alias successfully {action}d.")

        # ---------------------------------------------------------
        # DELETE: Destroy it by ID
        # ---------------------------------------------------------
        elif action == "delete":
            try:
                client.delete(f"identity/entity-alias/id/{alias_arg}")
                print(f"✅ Deleted alias ID '{alias_arg}'.")
            except Exception as e:
                print(f"❌ Error deleting alias: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 7. KUBERNETES MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "k8s":
        if action == "configure":
            if not args.host or not args.ca_cert:
                print("❌ Error: --host and --ca-cert are required for configuration.", file=sys.stderr)
                sys.exit(1)
            
            try:
                with open(args.ca_cert, 'r') as f:
                    ca_content = f.read()
                
                client = vault._get_client()
                # Link the Vault Auth Backend to the K8s Cluster
                client.write("auth/kubernetes/config", kubernetes_host=args.host, kubernetes_ca_cert=ca_content)
                print(f"✅ Kubernetes Auth Backend successfully linked to {args.host}")
            except Exception as e:
                print(f"❌ Error configuring K8s Auth: {e}", file=sys.stderr)
            sys.exit(0)
            
        if action == "list":
            roles = vault.list_kubernetes_roles()
            if roles:
                print("⚓ Existing Kubernetes Roles:")
                for r in roles: print(f"  ├─ {r}")
            else:
                print("ℹ️ No Kubernetes roles found.")
                
        else:
            # Note: 'name' is already validated by the global check at the top
            if action in ["create", "update"]:
                if not args.sa_names or not args.sa_namespaces:
                    print("❌ Error: --sa-names and --sa-namespaces are required to create a Kubernetes role.", file=sys.stderr)
                    sys.exit(1)
                    
                if vault.create_kubernetes_role(name, sa_names=args.sa_names, sa_namespaces=args.sa_namespaces, policies=args.policies, ttl=args.ttl):
                    print(f"✅ Kubernetes role '{name}' successfully created/updated.")
                    
            elif action in ["read", "info"]:
                details = vault.read_kubernetes_role(name)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ Kubernetes role '{name}' not found.")
                
            elif action == "delete":
                if vault.delete_kubernetes_role(name):
                    print(f"✅ Deleted Kubernetes role '{name}'.")


if __name__ == "__main__":
    main()
