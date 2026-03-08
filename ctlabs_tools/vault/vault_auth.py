# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_auth.py
# Purpose : Dedicated CLI for Vault Authentication & Policy Management
# -----------------------------------------------------------------------------

import argparse
import sys
import json
import re
import subprocess
from .core import HashiVault

def print_policy_table(name, hcl_text):
    """Parses raw Vault HCL and prints a color-coded permission table."""
    # 1. Strip comments to prevent regex confusion
    hcl_clean = re.sub(r'(#|//).*', '', hcl_text)
    hcl_clean = re.sub(r'/\*.*?\*/', '', hcl_clean, flags=re.DOTALL)
    
    # 2. Extract paths and capabilities
    paths = {}
    path_pattern = re.compile(r'path\s+"([^"]+)"\s*\{([^}]+)\}', re.MULTILINE)
    cap_pattern = re.compile(r'capabilities\s*=\s*\[(.*?)\]')
    
    for match in path_pattern.finditer(hcl_clean):
        path = match.group(1)
        body = match.group(2)
        cap_match = cap_pattern.search(body)
        if cap_match:
            caps_raw = cap_match.group(1)
            caps = [c.strip().strip('"\'') for c in caps_raw.split(',') if c.strip()]
            paths[path] = caps
        else:
            paths[path] = []

    print(f"\n📜 Policy: {name}")

    if not paths:
        print("=" * 95)
        print("⚠️ No parsable paths/capabilities found in this policy.")
        print("-" * 95)
        print(hcl_text.strip())
        print("=" * 95 + "\n")
        return

    # 3. Define columns and formatting
    all_caps = ["create", "read", "update", "patch", "delete", "list", "sudo", "deny"]
    max_path_len = max([len(p) for p in paths.keys()] + [25])
    
    # Calculate the exact dynamic width of the table
    header = f"{'Path'.ljust(max_path_len)} | " + " | ".join([c.capitalize().center(6) for c in all_caps])
    table_width = len(header)
    
    print("=" * table_width)
    print(header)
    print("-" * table_width)
    
    GREEN = "\033[92m"
    RED = "\033[91m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    
    # 4. Render Rows
    for path, caps in sorted(paths.items()):
        row = f"{path.ljust(max_path_len)} | "
        cap_strs = []
        for c in all_caps:
            if c in caps:
                if c == "deny":
                    cap_strs.append(f"{RED}{'ok'.center(6)}{RESET}")
                else:
                    cap_strs.append(f"{GREEN}{'ok'.center(6)}{RESET}")
            else:
                cap_strs.append(f"{DIM}{'--'.center(6)}{RESET}")
        row += " | ".join(cap_strs)
        print(row)
        
    print("=" * table_width + "\n")


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
    p_policy.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_policy.add_argument("name", nargs="?", default="", help="Name of the policy")
    p_policy.add_argument("--file", help="Path to an HCL file containing the policy rules (used with create/update)")

    # 4. GROUP
    p_group = subparsers.add_parser("group", help="Manage Identity Groups or External Auth Groups")
    p_group.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_group.add_argument("name", nargs="?", default="", help="Name of the group")
    p_group.add_argument("--method", choices=["identity", "ldap", "okta"], default="identity", help="Group type (default: identity. 'identity' is an internal Vault team)")
    p_group.add_argument("--policies", help="Comma-separated list of policies to assign to this group")
    p_group.add_argument("--members", help="Comma-separated list of Entity Names to add to the group (Only valid for --method identity)")

    # 5. ENTITY
    p_entity = subparsers.add_parser("entity", help="Manage Vault Identity Entities")
    p_entity.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "merge"], help="Action to perform")
    p_entity.add_argument("name", nargs="?", default="", help="Name of the entity (Source entity for merge)")
    p_entity.add_argument("--policies", help="Comma-separated list of policies to assign")
    p_entity.add_argument("--target", help="Destination entity name (Required for merge)")

    # 6. ALIAS
    p_alias = subparsers.add_parser("alias", help="Manage Identity Aliases")
    p_alias.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_alias.add_argument("alias_identifier", nargs="?", default="", help="Alias Name (for create) or Alias ID (for read/update/delete)")
    p_alias.add_argument("--entity", help="Entity name (required for create/update)")
    p_alias.add_argument("--mount", help="Auth mount path (e.g., userpass) (required for create/update)")

    # 7. KUBERNETES AUTH
    p_k8s = subparsers.add_parser("k8s", help="Manage Kubernetes Auth Roles & Configuration")
    p_k8s.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure"], help="Action to perform")
    p_k8s.add_argument("name", nargs="?", default="", help="Name of the Vault role (Required for all except list/configure)")
    p_k8s.add_argument("--sa-names", help="Allowed K8s Service Accounts")
    p_k8s.add_argument("--sa-namespaces", help="Allowed K8s Namespaces")
    p_k8s.add_argument("--policies", help="Vault policies to grant")
    p_k8s.add_argument("--ttl", default="1h", help="Token TTL")
    p_k8s.add_argument("--host", help="K8s API Host (for 'configure' action)")
    p_k8s.add_argument("--ca-cert", help="Path to K8s CA Cert file (for 'configure' action)")

    # 8. OIDC AUTH
    p_oidc = subparsers.add_parser("oidc", help="Manage OIDC Auth & Roles (SSO)")
    p_oidc.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure", "register"], help="Action to perform")
    p_oidc.add_argument("name", nargs="?", default="", help="Role name (OR 'Provider' like gcp/aws/okta for 'register')")
    p_oidc.add_argument("--client-id", help="OIDC Client ID (for 'configure' action)")
    p_oidc.add_argument("--client-secret", help="OIDC Client Secret (for 'configure')")
    p_oidc.add_argument("--default-role", default="default", help="Default OIDC role (for 'configure')")
    p_oidc.add_argument("--emails", help="Comma-separated list of allowed emails")
    p_oidc.add_argument("--groups", help="Comma-separated list of allowed Google Groups")
    p_oidc.add_argument("--policies", help="Comma-separated list of Vault policies")
    p_oidc.add_argument("--ttl", default="1h", help="Token TTL")
    p_oidc.add_argument("--gcp-project", help="GCP Project ID to use or create for the OAuth Client (for 'register')")
    p_oidc.add_argument("--admin-email", help="Your Google email to grant IAM roles to (for 'register')")

    # 9. GCP AUTH
    p_gcp = subparsers.add_parser("gcp", help="Manage GCP Auth Roles & Configuration")
    p_gcp.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure"], help="Action to perform")
    p_gcp.add_argument("name", nargs="?", default="", help="Name of the Vault role (Required for all except list/configure)")
    p_gcp.add_argument("--sa-emails", help="Comma-separated allowed GCP Service Accounts")
    p_gcp.add_argument("--policies", help="Comma-separated list of Vault policies")
    p_gcp.add_argument("--ttl", default="1h", help="Token TTL")
    p_gcp.add_argument("--type", default="iam", choices=["iam", "gce"], help="Type of GCP auth role (iam or gce)")
    
    p_gcp.add_argument("--project", help="GCP Project ID to auto-generate a Zero-Touch credential (for 'configure' action)")
    p_gcp.add_argument("--sa-name", default="vault-gcp-auth", help="Service Account name for Zero-Touch setup (default: vault-gcp-auth)")
    p_gcp.add_argument("--credentials", help="Path to an existing GCP credentials JSON file (Alternative to --project)")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    action = args.action
    name = getattr(args, 'name', '')

    if cmd != "alias" and action not in ["list", "configure", "register"] and not name:
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
                
        elif action == "read":
            creds = vault.get_approle_credentials(name)
            if creds: print(json.dumps(creds, indent=2))
            else: print(f"⚠️ Could not generate credentials for AppRole '{name}'.")
            
        elif action == "info":
            details = vault.read_approle(name)
            if details:
                print(f"🤖 AppRole: {name}")
                policies = details.get('token_policies', [])
                print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                print(f"  ├─ Token TTL: {details.get('token_ttl', 'System Default')}")
                print(f"  ├─ Bind Secret ID: {details.get('bind_secret_id', True)}")
            else: print(f"⚠️ AppRole '{name}' not found.")
            
        elif action == "delete":
            if vault.delete_approle(name):
                print(f"✅ Deleted AppRole '{name}'.")

    # -------------------------------------------------------------------------
    # 2. USER MANAGEMENT (Userpass & LDAP)
    # -------------------------------------------------------------------------
    elif cmd == "user":
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
            method = method or "userpass"
            if action in ["create", "update"]:
                if method == "userpass" and action == "create" and not args.password:
                    print("❌ Error: --password is required when creating a userpass user.", file=sys.stderr)
                    sys.exit(1)
                if vault.create_user(name, password=args.password, policies=args.policies, auth_type=method):
                    print(f"✅ User '{name}' ({method}) successfully created/updated.")
                    
            elif action == "read":
                details = vault.read_user(name, auth_type=method)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ User '{name}' not found in '{method}'.")
                
            elif action == "info":
                details = vault.read_user(name, auth_type=method)
                if details:
                    print(f"👤 User: {name} ({method})")
                    policies = details.get('token_policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
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
                if vault.create_policy(name, rules):
                    print(f"✅ Policy '{name}' successfully created/updated from {args.file}.")
            except Exception as e:
                print(f"❌ Error managing policy '{name}': {e}", file=sys.stderr)
                sys.exit(1)
                
        elif action in ["read", "info"]:
            rules = vault.read_policy(name)
            if rules:
                if action == "info":
                    print_policy_table(name, rules)
                else:
                    print(rules)
            else: print(f"⚠️ Policy '{name}' not found.")
            
        elif action == "delete":
            if vault.delete_policy(name):
                print(f"✅ Deleted policy '{name}'.")

    # -------------------------------------------------------------------------
    # 4. GROUP MANAGEMENT (Identity & External)
    # -------------------------------------------------------------------------
    elif cmd == "group":
        method = getattr(args, 'method', 'identity')
        
        if action == "list":
            if name:
                if method == "identity":
                    details = vault.read_identity_group(name)
                    if details:
                        member_ids = details.get("member_entity_ids", [])
                        if not member_ids:
                            print(f"ℹ️ Group '{name}' has no members.")
                        else:
                            print(f"👥 Members of Identity Group '{name}':")
                            client = vault._get_client()
                            for eid in member_ids:
                                try:
                                    e_data = client.read(f"identity/entity/id/{eid}")
                                    if e_data and 'data' in e_data:
                                        member_name = e_data['data'].get('name', 'Unknown')
                                        print(f"  ├─ {member_name} (ID: {eid})")
                                    else:
                                        print(f"  ├─ {eid} (Unknown Name)")
                                except Exception:
                                    print(f"  ├─ {eid} (Error fetching name)")
                    else:
                        print(f"⚠️ Group '{name}' not found.")
                else:
                    print(f"ℹ️ Member listing is not supported for external '{method}' groups.")
            
            else:
                if method == "identity":
                    groups = vault.list_identity_groups()
                    label = "Internal Vault Identity Groups"
                else:
                    groups = vault.list_groups(auth_type=method)
                    label = f"External '{method}' Group Mappings"

                if groups:
                    print(f"🏢 Existing {label}:")
                    for g in groups: print(f"  ├─ {g}")
                else:
                    print(f"ℹ️ No {label} found.")
                
        else:
            if not name:
                print(f"❌ Error: 'name' is required for the '{action}' action.", file=sys.stderr)
                sys.exit(1)
                
            if action in ["create", "update"]:
                if method == "identity":
                    entity_ids = []
                    missing_entities = []
                    
                    if args.members:
                        for member_name in [m.strip() for m in args.members.split(",") if m.strip()]:
                            ent = vault.read_entity(member_name)
                            if ent and 'id' in ent:
                                entity_ids.append(ent['id'])
                            else:
                                missing_entities.append(member_name)
                                
                    if missing_entities:
                        print(f"❌ Error: The following entities were not found in Vault: {', '.join(missing_entities)}", file=sys.stderr)
                        print("👉 You must create them first using 'vault-auth entity create <name>' before adding them to a group.", file=sys.stderr)
                        sys.exit(1)

                    if vault.create_identity_group(name, policies=args.policies, member_entity_ids=entity_ids):
                        print(f"✅ Vault Identity Group '{name}' successfully created/updated.")
                else:
                    if vault.create_group(name, policies=args.policies, auth_type=method):
                        print(f"✅ External Group Mapping '{name}' ({method}) successfully created/updated.")
                    
            elif action == "read":
                if method == "identity":
                    details = vault.read_identity_group(name)
                    
                    if details:
                        member_ids = details.get("member_entity_ids", [])
                        if member_ids:
                            client = vault._get_client()
                            member_names = []
                            for eid in member_ids:
                                try:
                                    e_data = client.read(f"identity/entity/id/{eid}")
                                    if e_data and 'data' in e_data:
                                        member_names.append(e_data['data'].get('name', eid))
                                    else:
                                        member_names.append(eid)
                                except Exception:
                                    member_names.append(eid)
                            details["member_entity_names"] = member_names
                            
                else:
                    details = vault.read_group(name, auth_type=method)
                    
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ Group '{name}' not found for method '{method}'.")
                
            elif action == "info":
                if method == "identity":
                    details = vault.read_identity_group(name)
                    if details:
                        print(f"🏢 Identity Group: {name}")
                        print(f"  ├─ ID: {details.get('id')}")
                        policies = details.get('policies', [])
                        print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                        
                        member_ids = details.get("member_entity_ids", [])
                        if member_ids:
                            client = vault._get_client()
                            print(f"  ├─ Members:")
                            for eid in member_ids:
                                try:
                                    e_data = client.read(f"identity/entity/id/{eid}")
                                    if e_data and 'data' in e_data:
                                        print(f"  │  ├─ {e_data['data'].get('name', eid)} (ID: {eid})")
                                    else:
                                        print(f"  │  ├─ {eid} (Unknown Name)")
                                except Exception:
                                    print(f"  │  ├─ {eid} (Error fetching name)")
                        else:
                            print(f"  ├─ Members: None")
                    else:
                        print(f"⚠️ Group '{name}' not found.")
                else:
                    details = vault.read_group(name, auth_type=method)
                    if details:
                        print(f"🏢 External Group ({method}): {name}")
                        policies = details.get('policies', [])
                        print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                    else:
                        print(f"⚠️ Group '{name}' not found for method '{method}'.")
                
            elif action == "delete":
                if method == "identity":
                    if vault.delete_identity_group(name):
                        print(f"✅ Deleted Identity Group '{name}'.")
                else:
                    if vault.delete_group(name, auth_type=method):
                        print(f"✅ Deleted external group mapping '{name}' ({method}).")

    # -------------------------------------------------------------------------
    # 5. ENTITY MANAGEMENT
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
                    
            elif action == "read":
                details = vault.read_entity(name)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ Entity '{name}' not found.")
                
            elif action == "info":
                details = vault.read_entity(name)
                if details:
                    print(f"👤 Entity: {details.get('name')}")
                    print(f"  ├─ ID: {details.get('id')}")
                    policies = details.get('policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                    
                    aliases = details.get('aliases', [])
                    if aliases:
                        print(f"  ├─ Aliases:")
                        for a in aliases:
                            print(f"  │  ├─ {a.get('name')} (Mount: {a.get('mount_path')})")
                    else:
                        print(f"  ├─ Aliases: None")
                        
                    groups = details.get('group_ids', [])
                    if groups:
                        group_names = []
                        client = vault._get_client()
                        for gid in groups:
                            try:
                                g_data = client.read(f"identity/group/id/{gid}")
                                if g_data and 'data' in g_data:
                                    group_names.append(g_data['data'].get('name', gid))
                                else:
                                    group_names.append(gid)
                            except:
                                group_names.append(gid)
                        print(f"  ├─ Groups: {', '.join(group_names)}")
                    else:
                        print(f"  ├─ Groups: None")
                else: 
                    print(f"⚠️ Entity '{name}' not found.")
                    
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

        if not alias_arg:
            print(f"❌ Error: Alias Name or ID is required for '{action}'.", file=sys.stderr)
            sys.exit(1)

        if action == "read":
            try:
                res = client.read(f"identity/entity-alias/id/{alias_arg}")
                if res and 'data' in res: 
                    print(json.dumps(res['data'], indent=2))
                else: 
                    print(f"❌ Alias ID '{alias_arg}' not found.", file=sys.stderr)
            except Exception as e:
                print(f"❌ Error reading alias: {e}", file=sys.stderr)
                
        elif action == "info":
            try:
                res = client.read(f"identity/entity-alias/id/{alias_arg}")
                if res and 'data' in res: 
                    data = res['data']
                    print(f"🔗 Alias: {data.get('name')}")
                    print(f"  ├─ ID: {data.get('id')}")
                    print(f"  ├─ Mount: {data.get('mount_path')}")
                    
                    canonical_id = data.get('canonical_id')
                    parent_entity = "Unknown"
                    if canonical_id:
                        try:
                            e_data = client.read(f"identity/entity/id/{canonical_id}")
                            if e_data and 'data' in e_data:
                                parent_entity = e_data['data'].get('name', canonical_id)
                        except:
                            pass
                    print(f"  ├─ Entity: {parent_entity}")
                else: 
                    print(f"❌ Alias ID '{alias_arg}' not found.", file=sys.stderr)
            except Exception as e:
                print(f"❌ Error fetching alias info: {e}", file=sys.stderr)

        elif action in ["create", "update"]:
            if not entity_name or not mount:
                print("❌ Error: --entity and --mount are required to create/update an alias.", file=sys.stderr)
                sys.exit(1)
            print(f"🚀 {action.capitalize()}ing alias '{alias_arg}' for entity '{entity_name}'...")
            if vault.create_entity_alias(entity_name=entity_name, alias_name=alias_arg, mount_accessor_or_path=mount):
                print(f"✅ Alias successfully {action}d.")

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
            if action in ["create", "update"]:
                if not args.sa_names or not args.sa_namespaces:
                    print("❌ Error: --sa-names and --sa-namespaces are required to create a Kubernetes role.", file=sys.stderr)
                    sys.exit(1)
                if vault.create_kubernetes_role(name, sa_names=args.sa_names, sa_namespaces=args.sa_namespaces, policies=args.policies, ttl=args.ttl):
                    print(f"✅ Kubernetes role '{name}' successfully created/updated.")
                    
            elif action == "read":
                details = vault.read_kubernetes_role(name)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ Kubernetes role '{name}' not found.")
                
            elif action == "info":
                details = vault.read_kubernetes_role(name)
                if details:
                    print(f"⚓ Kubernetes Role: {name}")
                    print(f"  ├─ Service Accounts: {', '.join(details.get('bound_service_account_names', []))}")
                    print(f"  ├─ Namespaces: {', '.join(details.get('bound_service_account_namespaces', []))}")
                    policies = details.get('token_policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                    print(f"  ├─ Token TTL: {details.get('token_ttl', 'System Default')}s")
                else: print(f"⚠️ Kubernetes role '{name}' not found.")
                
            elif action == "delete":
                if vault.delete_kubernetes_role(name):
                    print(f"✅ Deleted Kubernetes role '{name}'.")

    # -------------------------------------------------------------------------
    # 8. OIDC / SSO MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "oidc":
        if action == "configure":
            if not args.client_id or not args.client_secret:
                print("❌ Error: --client-id and --client-secret are required for configure.", file=sys.stderr)
                sys.exit(1)
            if vault.configure_oidc(args.client_id, args.client_secret, args.default_role):
                print("✅ OIDC Engine configured successfully. Vault is now linked to Google.")
            else:
                sys.exit(1)

        elif action == "list":
            roles = vault.list_oidc_roles()
            if roles:
                print("🌐 Existing OIDC Roles:")
                for r in roles: print(f"  ├─ {r}")
            else:
                print("ℹ️ No OIDC roles found.")

        elif action in ["create", "update"]:
            if not args.emails and not args.groups:
                print("❌ Error: Must provide either --emails or --groups to bind to the role.", file=sys.stderr)
                sys.exit(1)
            
            bound_claims = {}
            if args.emails:
                bound_claims["email"] = [e.strip() for e in args.emails.split(",")]
            if args.groups:
                bound_claims["groups"] = [g.strip() for g in args.groups.split(",")]

            if vault.create_oidc_role(name, bound_claims, policies=args.policies, ttl=args.ttl):
                print(f"✅ OIDC Role '{name}' successfully {action}d.")

        elif action == "read":
            details = vault.read_oidc_role(name)
            if details:
                print(json.dumps(details, indent=2))
            else:
                print(f"⚠️ OIDC role '{name}' not found.")
                
        elif action == "info":
            details = vault.read_oidc_role(name)
            if details:
                print(f"🌐 OIDC Role: {name}")
                claims = details.get('bound_claims', {})
                if claims:
                    print(f"  ├─ Bound Claims:")
                    for k, v in claims.items():
                        val_str = ', '.join(v) if isinstance(v, list) else v
                        print(f"  │  ├─ {k}: {val_str}")
                else:
                    print(f"  ├─ Bound Claims: None")
                policies = details.get('token_policies', [])
                print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                print(f"  ├─ Token TTL: {details.get('token_ttl', 'System Default')}s")
            else:
                print(f"⚠️ OIDC role '{name}' not found.")

        elif action == "delete":
            if vault.delete_oidc_role(name):
                print(f"✅ Deleted OIDC role '{name}'.")
    
        elif action == "register":
            import subprocess
            
            provider = name.lower()

            if provider == "gcp":
                if not args.gcp_project or not args.admin_email:
                    print("❌ Error: --gcp-project and --admin-email are required for 'register gcp'.", file=sys.stderr)
                    sys.exit(1)
                    
                project_id = args.gcp_project
                admin_email = args.admin_email

                print(f"🚀 Step 1: Checking GCP Project '{project_id}'...")
                res = subprocess.run(["gcloud", "projects", "describe", project_id], capture_output=True, text=True)
                
                if res.returncode != 0:
                    print(f"   ℹ️ Project not found. Creating '{project_id}'...")
                    subprocess.run(["gcloud", "projects", "create", project_id], check=True)
                else:
                    print("   ✅ Project exists.")

                print(f"🚀 Step 2: Assigning OAuth IAM roles to {admin_email}...")
                subprocess.run(["gcloud", "projects", "add-iam-policy-binding", project_id, 
                                "--member", f"user:{admin_email}", "--role", "roles/oauthconfig.editor"], capture_output=True)
                subprocess.run(["gcloud", "projects", "add-iam-policy-binding", project_id, 
                                "--member", f"user:{admin_email}", "--role", "roles/clientauthconfig.editor"], capture_output=True)
                print("   ✅ IAM Roles assigned.")

                print("\n" + "="*60)
                print("🛑 ACTION REQUIRED: MANUAL GCP CONSOLE SETUP 🛑")
                print("="*60)
                print(f"1️⃣  Configure the Consent Screen:")
                print(f"   🔗 URL: https://console.cloud.google.com/apis/credentials/consent?project={project_id}")
                print(f"2️⃣  Create the OAuth Client ID (Web Application):")
                print(f"   🔗 URL: https://console.cloud.google.com/apis/credentials?project={project_id}")
                print(f"   👉 Add Redirect URIs:")
                print(f"      - http://localhost:8250/oidc/callback")
                print(f"      - https://vault.yourdomain.com:8200/ui/vault/auth/oidc/oidc/callback")
                print("="*60)
                
                client_id = input("🔑 Paste your new Client ID: ").strip()
                client_secret = getpass.getpass("🕵️  Paste your new Client Secret: ").strip()
                discovery_url = "https://accounts.google.com"

            elif provider in ["azure", "entraid"]:
                client_id = input("🔑 Paste your Entra ID Application (client) ID: ").strip()
                tenant_id = input("🏢 Paste your Directory (tenant) ID: ").strip()
                client_secret = getpass.getpass("🕵️  Paste your Entra ID Client Secret: ").strip()
                discovery_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

            elif provider == "okta":
                okta_domain = input("🌐 Paste your Okta Domain (e.g., dev-123.okta.com): ").strip()
                client_id = input("🔑 Paste your Client ID: ").strip()
                client_secret = getpass.getpass("🕵️  Paste your Client Secret: ").strip()
                
                okta_domain = okta_domain.replace("https://", "").strip("/")
                discovery_url = f"https://{okta_domain}"

            else:
                print(f"❌ Error: Unsupported OIDC provider '{provider}'.", file=sys.stderr)
                print("   Supported providers: gcp, azure, okta", file=sys.stderr)
                sys.exit(1)

            if not client_id or not client_secret:
                print("❌ Aborting: Client ID and Secret are required.", file=sys.stderr)
                sys.exit(1)

            print(f"\n🚀 Step 3: Configuring Vault OIDC Engine for {provider.upper()}...")
            if vault.configure_oidc(client_id, client_secret, args.default_role, discovery_url=discovery_url):
                print(f"🎉 SUCCESS! Vault SSO is fully registered with {provider.upper()}.")
            else:
                sys.exit(1)

    # -------------------------------------------------------------------------
    # 9. GCP AUTH MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "gcp":
        if action == "configure":
            creds_content = None
            
            if getattr(args, 'credentials', None):
                try:
                    with open(args.credentials, 'r') as f:
                        creds_content = f.read()
                except Exception as e:
                    print(f"❌ Error reading credentials file: {e}", file=sys.stderr)
                    sys.exit(1)
                    
            elif getattr(args, 'project', None):
                project = args.project
                sa_name = args.sa_name
                sa_email = f"{sa_name}@{project}.iam.gserviceaccount.com"
                
                print(f"🚀 Initializing Zero-Touch GCP Auth Verifier in project: {project}...")
                
                print(f"  ├─ Ensuring Service Account '{sa_name}' exists...")
                subprocess.run([
                    "gcloud", "iam", "service-accounts", "create", sa_name,
                    "--display-name=Vault GCP Auth Verifier", "--project", project
                ], capture_output=True) 
                
                print(f"  ├─ Granting necessary IAM roles for token verification...")
                subprocess.run([
                    "gcloud", "projects", "add-iam-policy-binding", project,
                    f"--member=serviceAccount:{sa_email}",
                    "--role=roles/iam.serviceAccountKeyAdmin"
                ], capture_output=True)
                
                subprocess.run([
                    "gcloud", "projects", "add-iam-policy-binding", project,
                    f"--member=serviceAccount:{sa_email}",
                    "--role=roles/compute.viewer"
                ], capture_output=True)
                
                print("  ├─ 🔑 Generating JSON Key in-memory and updating Vault...")
                res = subprocess.run([
                    "gcloud", "iam", "service-accounts", "keys", "create", "-",
                    f"--iam-account={sa_email}", "--project", project
                ], capture_output=True, text=True)
                
                if res.returncode != 0:
                    print(f"❌ Failed to generate Service Account key: {res.stderr}", file=sys.stderr)
                    sys.exit(1)
                    
                creds_content = res.stdout.strip()
                
            else:
                print("❌ Error: You must provide either --project (for zero-touch) or --credentials (for manual file).", file=sys.stderr)
                sys.exit(1)
            
            if vault.configure_gcp_auth(credentials=creds_content):
                print(f"✅ GCP Auth Backend successfully configured.")
            else:
                sys.exit(1)
                
        elif action == "list":
            roles = vault.list_gcp_auth_roles()
            if roles:
                print("☁️ Existing GCP Auth Roles:")
                for r in roles: print(f"  ├─ {r}")
            else:
                print("ℹ️ No GCP auth roles found.")
                
        else:
            if action in ["create", "update"]:
                if not args.sa_emails:
                    print("❌ Error: --sa-emails is required to create a GCP auth role.", file=sys.stderr)
                    sys.exit(1)
                if vault.create_gcp_auth_role(name, sa_emails=args.sa_emails, policies=args.policies, ttl=args.ttl, role_type=args.type):
                    print(f"✅ GCP auth role '{name}' successfully created/updated.")
                    
            elif action == "read":
                details = vault.read_gcp_auth_role(name)
                if details: print(json.dumps(details, indent=2))
                else: print(f"⚠️ GCP auth role '{name}' not found.")
                
            elif action == "info":
                details = vault.read_gcp_auth_role(name)
                if details:
                    print(f"☁️ GCP Auth Role: {name}")
                    print(f"  ├─ Type: {details.get('type', 'iam')}")
                    print(f"  ├─ Service Accounts: {', '.join(details.get('bound_service_accounts', []))}")
                    policies = details.get('token_policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                    print(f"  ├─ Token TTL: {details.get('token_ttl', 'System Default')}s")
                else: print(f"⚠️ GCP auth role '{name}' not found.")
                
            elif action == "delete":
                if vault.delete_gcp_auth_role(name):
                    print(f"✅ Deleted GCP auth role '{name}'.")

if __name__ == "__main__":
    main()
