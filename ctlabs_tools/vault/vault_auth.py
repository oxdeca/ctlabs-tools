# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_auth.py
# Purpose : Dedicated CLI for Vault Authentication & Policy Management
# -----------------------------------------------------------------------------

import argparse
import sys
import json
import re
import subprocess
import getpass
from .core import HashiVault

def print_policy_table(name, hcl_text):
    """Parses raw Vault HCL and prints a color-coded permission table."""
    hcl_clean = re.sub(r'(#|//).*', '', hcl_text)
    hcl_clean = re.sub(r'/\*.*?\*/', '', hcl_clean, flags=re.DOTALL)
    
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

    all_caps = ["create", "read", "update", "patch", "delete", "list", "sudo", "deny"]
    max_path_len = max([len(p) for p in paths.keys()] + [25])
    
    header = f"{'Path'.ljust(max_path_len)} | " + " | ".join([c.capitalize().center(6) for c in all_caps])
    table_width = len(header)
    
    print("=" * table_width)
    print(header)
    print("-" * table_width)
    
    GREEN = "\033[92m"
    RED = "\033[91m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    
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

def get_auth_mounts(client, engine_type):
    """Dynamically queries sys/auth to find all active mount paths for an engine type."""
    try:
        res = client.sys.list_auth_methods()
        mounts = []
        for path, info in res.get('data', {}).items():
            if info['type'] == engine_type:
                mounts.append(path.strip('/'))
        return mounts if mounts else [engine_type]
    except Exception:
        return [engine_type]

def parse_target(name_args, default_root, action, is_config=False):
    """
    Smart token parser. Supports formats:
    - role_name (Defaults to root mount)
    - mount_name role_name
    - mount_name/role_name
    - default_root/mount_name/role_name
    """
    tokens = []
    if name_args:
        for arg in name_args:
            tokens.extend([t for t in arg.split('/') if t])
            
    # Strip empty tokens
    tokens = [t for t in tokens if t]
    
    # Strip the default root if the user provided it redundantly (e.g. 'approle/dev/my-role')
    if tokens and tokens[0] == default_root:
        tokens.pop(0)
        
    if action in ["list", "configure"] or is_config:
        # If it's a list or config action, the entire path string represents the MOUNT
        if not tokens:
            return default_root, ""
        else:
            return f"{default_root}/{'/'.join(tokens)}", ""
    else:
        # If it's a create/read/delete action, the LAST token is the role name, everything before is the mount
        if not tokens:
            return default_root, ""
        elif len(tokens) == 1:
            return default_root, tokens[0]
        else:
            name = tokens[-1]
            sub_mount = "/".join(tokens[:-1])
            return f"{default_root}/{sub_mount}", name

def get_args():
    parser = argparse.ArgumentParser(description="Vault Authentication & Policy Manager")
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. APPROLE
    p_approle = subparsers.add_parser("approle", help="Manage Machine Identities (AppRoles)")
    p_approle.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_approle.add_argument("name_args", nargs="*", help="Supports: <role>, <mount> <role>, or <mount>/<role>")
    p_approle.add_argument("--ttl", default="1h", help="Token TTL (e.g. 1h, 30m)")
    p_approle.add_argument("--policies", help="Comma-separated list of policies")

    # 2. USER
    p_user = subparsers.add_parser("user", help="Manage Human Identities (Userpass / LDAP)")
    p_user.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_user.add_argument("name_args", nargs="*", help="Supports: <user>, <mount> <user>, or <mount>/<user>")
    p_user.add_argument("--type", choices=["userpass", "ldap"], help="Auth method type (defaults to 'userpass' for create/read, 'all' for list)")
    p_user.add_argument("--password", help="Password (required for creating userpass users)")
    p_user.add_argument("--policies", help="Comma-separated list of policies")

    # 3. POLICY
    p_policy = subparsers.add_parser("policy", help="Manage Vault ACL Policies")
    p_policy.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_policy.add_argument("name_args", nargs="*", help="Name of the policy")
    p_policy.add_argument("--file", help="Path to an HCL file containing the policy rules")

    # 4. GROUP
    p_group = subparsers.add_parser("group", help="Manage Identity Groups or External Auth Groups")
    p_group.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_group.add_argument("name_args", nargs="*", help="Supports: <group>, <mount> <group>, or <mount>/<group>")
    p_group.add_argument("--type", choices=["identity", "ldap", "okta"], help="Group type (defaults to 'identity')")
    p_group.add_argument("--policies", help="Comma-separated list of policies to assign to this group")
    p_group.add_argument("--members", help="Comma-separated list of Entity Names to add (identity only)")

    # 5. ENTITY
    p_entity = subparsers.add_parser("entity", help="Manage Vault Identity Entities")
    p_entity.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "merge"])
    p_entity.add_argument("name_args", nargs="*", help="Name of the entity (Source entity for merge)")
    p_entity.add_argument("--policies", help="Comma-separated list of policies to assign")
    p_entity.add_argument("--target", help="Destination entity name (Required for merge)")

    # 6. ALIAS
    p_alias = subparsers.add_parser("alias", help="Manage Identity Aliases")
    p_alias.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_alias.add_argument("name_args", nargs="*", help="Alias Name (for create) or Alias ID (for read/update/delete)")
    p_alias.add_argument("--entity", help="Entity name (required for create/update)")
    p_alias.add_argument("--mount", help="Auth mount accessor or path")

    # 7. KUBERNETES AUTH
    p_k8s = subparsers.add_parser("k8s", help="Manage Kubernetes Auth Roles & Configuration")
    p_k8s.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure"])
    p_k8s.add_argument("name_args", nargs="*", help="Supports: <role>, <cluster_mount> <role>, or <cluster_mount>/<role>")
    p_k8s.add_argument("--sa-names", help="Allowed K8s Service Accounts")
    p_k8s.add_argument("--sa-namespaces", help="Allowed K8s Namespaces")
    p_k8s.add_argument("--policies", help="Vault policies to grant")
    p_k8s.add_argument("--ttl", default="1h", help="Token TTL")
    p_k8s.add_argument("--host", help="K8s API Host (for 'configure' action)")
    p_k8s.add_argument("--ca-cert", help="Path to K8s CA Cert file (for 'configure' action)")

    # 8. OIDC AUTH
    p_oidc = subparsers.add_parser("oidc", help="Manage OIDC Auth & Roles (SSO)")
    p_oidc.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure", "register"])
    p_oidc.add_argument("name_args", nargs="*", help="Supports: <role>, <mount> <role>. For 'register': <provider> (e.g. gcp, azure, okta)")
    p_oidc.add_argument("--client-id", help="OIDC Client ID (for 'configure' action)")
    p_oidc.add_argument("--client-secret", help="OIDC Client Secret (for 'configure')")
    p_oidc.add_argument("--default-role", default="default", help="Default OIDC role (for 'configure')")
    p_oidc.add_argument("--emails", help="Comma-separated list of allowed emails")
    p_oidc.add_argument("--groups", help="Comma-separated list of allowed Google Groups")
    p_oidc.add_argument("--policies", help="Comma-separated list of Vault policies")
    p_oidc.add_argument("--ttl", default="1h", help="Token TTL")
    p_oidc.add_argument("--gcp-project", help="GCP Project ID to use or create for the OAuth Client")
    p_oidc.add_argument("--admin-email", help="Your Google email to grant IAM roles to")

    # 9. GCP AUTH
    p_gcp = subparsers.add_parser("gcp", help="Manage GCP Auth Roles & Configuration")
    p_gcp.add_argument("action", choices=["create", "update", "read", "delete", "list", "info", "configure"])
    p_gcp.add_argument("name_args", nargs="*", help="Supports: <role>, <mount> <role>, or <mount>/<role>")
    p_gcp.add_argument("--sa-emails", help="Comma-separated allowed GCP Service Accounts")
    p_gcp.add_argument("--policies", help="Comma-separated list of Vault policies")
    p_gcp.add_argument("--ttl", default="1h", help="Token TTL")
    p_gcp.add_argument("--type", default="iam", choices=["iam", "gce"], help="Type of GCP auth role")
    p_gcp.add_argument("--project", help="GCP Project ID to auto-generate a Zero-Touch credential")
    p_gcp.add_argument("--sa-name", default="vault-gcp-auth", help="Service Account name for Zero-Touch setup")
    p_gcp.add_argument("--credentials", help="Path to an existing GCP credentials JSON file")

    # 10. LDAP AUTH METHOD
    p_ldap = subparsers.add_parser("ldap", help="Manage LDAP Auth Configuration & Mappings")
    ldap_subs = p_ldap.add_subparsers(dest="ldap_cmd", required=True)

    p_ldap_cfg = ldap_subs.add_parser("config", help="Manage LDAP Connection Config")
    p_ldap_cfg.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_ldap_cfg.add_argument("name_args", nargs="*", help="Supports: <mount> (Overrides default 'ldap' mount)")
    p_ldap_cfg.add_argument("--url", help="LDAP server URL (e.g., ldaps://ldap.example.com)")
    p_ldap_cfg.add_argument("--bind-dn", help="Bind DN")
    p_ldap_cfg.add_argument("--bind-pass", help="Bind Password")
    p_ldap_cfg.add_argument("--user-dn", help="User search base DN")
    p_ldap_cfg.add_argument("--group-dn", help="Group search base DN")
    p_ldap_cfg.add_argument("--user-attr", help="User attribute (e.g., uid, sAMAccountName)")
    p_ldap_cfg.add_argument("--group-attr", help="Group attribute (e.g., cn)")

    p_ldap_grp = ldap_subs.add_parser("group", help="Map LDAP Groups to Policies")
    p_ldap_grp.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_ldap_grp.add_argument("name_args", nargs="*", help="Supports: <group_name>, <mount> <group_name>")
    p_ldap_grp.add_argument("--policies", help="Comma-separated Vault policies")

    p_ldap_usr = ldap_subs.add_parser("user", help="Map specific LDAP Users to Policies")
    p_ldap_usr.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_ldap_usr.add_argument("name_args", nargs="*", help="Supports: <user_name>, <mount> <user_name>")
    p_ldap_usr.add_argument("--policies", help="Comma-separated Vault policies")
    p_ldap_usr.add_argument("--groups", help="Comma-separated LDAP groups to implicitly attach")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    client = vault._get_client()
    
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    action = args.action

    # -------------------------------------------------------------------------
    # 1. APPROLE MANAGEMENT
    # -------------------------------------------------------------------------
    if cmd == "approle":
        mount, name = parse_target(args.name_args, "approle", action)
        
        if action == "list":
            mounts = [mount] if args.name_args else get_auth_mounts(client, 'approle')
            found = False
            for m in mounts:
                try:
                    roles = client.list(f"auth/{m}/role")['data']['keys']
                    if roles:
                        print(f"📋 AppRoles in '{m}/':")
                        for r in roles: print(f"  ├─ {r}")
                        found = True
                except: pass
            if not found: print(f"ℹ️ No AppRoles found{' in specified mount' if args.name_args else ''}.")
                
        elif action in ["create", "update"]:
            if not name:
                print("❌ Error: Role name is required.", file=sys.stderr)
                sys.exit(1)
            policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
            try:
                client.write(f"auth/{mount}/role/{name}", token_policies=policies, token_ttl=args.ttl)
                print(f"✅ AppRole '{name}' successfully created/updated in '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                
        elif action == "read":
            if not name:
                print("❌ Error: Role name is required.", file=sys.stderr)
                sys.exit(1)
            try:
                role_id = client.read(f"auth/{mount}/role/{name}/role-id")['data']['role_id']
                secret_id = client.write(f"auth/{mount}/role/{name}/secret-id")['data']['secret_id']
                print(json.dumps({"role_id": role_id, "secret_id": secret_id}, indent=2))
            except Exception as e: print(f"⚠️ Could not generate credentials for AppRole '{name}' at '{mount}/': {e}", file=sys.stderr)
            
        elif action == "info":
            if not name:
                print("❌ Error: Role name is required.", file=sys.stderr)
                sys.exit(1)
            try:
                details = client.read(f"auth/{mount}/role/{name}")['data']
                print(f"🤖 AppRole: {name} (Mount: {mount}/)")
                policies = details.get('token_policies', [])
                print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                print(f"  ├─ Token TTL: {details.get('token_ttl', 'System Default')}")
                print(f"  ├─ Bind Secret ID: {details.get('bind_secret_id', True)}")
            except Exception: print(f"⚠️ AppRole '{name}' not found in '{mount}/'.", file=sys.stderr)
            
        elif action == "delete":
            if not name:
                print("❌ Error: Role name is required.", file=sys.stderr)
                sys.exit(1)
            try:
                client.delete(f"auth/{mount}/role/{name}")
                print(f"✅ Deleted AppRole '{name}' from '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 2. USER MANAGEMENT (Userpass & LDAP)
    # -------------------------------------------------------------------------
    elif cmd == "user":
        auth_type = getattr(args, 'type', None)

        if action == "list":
            methods_to_check = [auth_type] if auth_type else ["userpass", "ldap"]
            found_any = False
            for m_type in methods_to_check:
                mount, _ = parse_target(args.name_args, m_type, action)
                mounts = [mount] if args.name_args else get_auth_mounts(client, m_type)
                for m in mounts:
                    try:
                        users = client.list(f"auth/{m}/users")['data']['keys']
                        if users:
                            print(f"👥 Users in '{m}/' ({m_type}):")
                            for u in users: print(f"  ├─ {u}")
                            found_any = True
                    except: pass
            if not found_any: print(f"ℹ️ No users found.")
                
        else:
            auth_type = auth_type or "userpass"
            mount, name = parse_target(args.name_args, auth_type, action)
            
            if not name:
                print("❌ Error: User name is required.", file=sys.stderr)
                sys.exit(1)
                
            if action in ["create", "update"]:
                if auth_type == "userpass" and action == "create" and not args.password:
                    print("❌ Error: --password is required when creating a userpass user.", file=sys.stderr)
                    sys.exit(1)
                    
                policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
                payload = {"token_policies": policies} if auth_type == "userpass" else {"policies": policies}
                if args.password: payload["password"] = args.password
                
                try:
                    client.write(f"auth/{mount}/users/{name}", **payload)
                    print(f"✅ User '{name}' successfully created/updated in '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                    
            elif action == "read":
                try:
                    details = client.read(f"auth/{mount}/users/{name}")['data']
                    print(json.dumps(details, indent=2))
                except: print(f"⚠️ User '{name}' not found in '{mount}/'.", file=sys.stderr)
                
            elif action == "info":
                try:
                    details = client.read(f"auth/{mount}/users/{name}")['data']
                    print(f"👤 User: {name} (Mount: {mount}/)")
                    policies = details.get('token_policies', []) if auth_type == "userpass" else details.get('policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                except: print(f"⚠️ User '{name}' not found in '{mount}/'.", file=sys.stderr)
                
            elif action == "delete":
                try:
                    client.delete(f"auth/{mount}/users/{name}")
                    print(f"✅ Deleted user '{name}' from '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 3. POLICY MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "policy":
        name = args.name_args[0] if args.name_args else ""
        if action == "list":
            try:
                policies = client.sys.list_policies()['data']['keys']
                print("📜 Existing ACL Policies:")
                for p in policies: print(f"  ├─ {p}")
            except: print("ℹ️ No policies found.")
        elif action in ["create", "update"]:
            if not name or not args.file:
                print("❌ Error: Policy name and --file <path_to_hcl> are required.", file=sys.stderr)
                sys.exit(1)
            try:
                with open(args.file, 'r') as f: rules = f.read()
                client.sys.create_or_update_policy(name=name, policy=rules)
                print(f"✅ Policy '{name}' successfully created/updated.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
        elif action in ["read", "info"]:
            if not name:
                print("❌ Error: Policy name is required.", file=sys.stderr)
                sys.exit(1)
            try:
                res = client.read(f"sys/policies/acl/{name}")
                if not res: res = client.read(f"sys/policy/{name}")
                rules = res['data'].get('policy') or res['data'].get('rules', '')
                if action == "info": print_policy_table(name, rules)
                else: print(rules)
            except: print(f"⚠️ Policy '{name}' not found.", file=sys.stderr)
        elif action == "delete":
            if not name:
                print("❌ Error: Policy name is required.", file=sys.stderr)
                sys.exit(1)
            try:
                client.sys.delete_policy(name=name)
                print(f"✅ Deleted policy '{name}'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 4. GROUP MANAGEMENT (Identity & External)
    # -------------------------------------------------------------------------
    elif cmd == "group":
        grp_type = getattr(args, 'type', None)
        
        if action == "list":
            if grp_type and grp_type != "identity" and args.name_args:
                # E.g. vault-auth group list oidc/dev --type oidc -> list roles in mount
                mount, _ = parse_target(args.name_args, grp_type, action)
                try:
                    groups = client.list(f"auth/{mount}/groups")['data']['keys']
                    if groups:
                        print(f"🏢 Groups in '{mount}/':")
                        for g in groups: print(f"  ├─ {g}")
                    else: print(f"ℹ️ No groups found in '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
            elif grp_type == "identity" and args.name_args:
                # E.g. vault-auth group list my-identity-group -> list members
                name = args.name_args[0]
                try:
                    details = client.read(f"identity/group/name/{name}")['data']
                    member_ids = details.get("member_entity_ids", [])
                    if not member_ids: print(f"ℹ️ Group '{name}' has no members.")
                    else:
                        print(f"👥 Members of Identity Group '{name}':")
                        for eid in member_ids:
                            try:
                                e_data = client.read(f"identity/entity/id/{eid}")
                                print(f"  ├─ {e_data['data'].get('name', 'Unknown')} (ID: {eid})")
                            except: print(f"  ├─ {eid} (Unknown Name)")
                except: print(f"⚠️ Group '{name}' not found.")
            else:
                methods_to_check = [grp_type] if grp_type else ["identity", "ldap", "okta"]
                found_any = False
                for m_type in methods_to_check:
                    if m_type == "identity":
                        try:
                            keys = client.list("identity/group/name")['data']['keys']
                            if keys:
                                print(f"🏢 Internal Vault Identity Groups:")
                                for k in keys: print(f"  ├─ {k}")
                                found_any = True
                        except: pass
                    else:
                        mounts = get_auth_mounts(client, m_type)
                        for m in mounts:
                            try:
                                keys = client.list(f"auth/{m}/groups")['data']['keys']
                                if keys:
                                    print(f"🏢 Groups in '{m}/' ({m_type}):")
                                    for k in keys: print(f"  ├─ {k}")
                                    found_any = True
                            except: pass
                if not found_any: print("ℹ️ No groups found.")
                
        else:
            grp_type = grp_type or "identity"
            mount, name = parse_target(args.name_args, grp_type, action)
            
            if grp_type == "identity":
                # Identity doesn't use mounts, just flat name
                name = "/".join(args.name_args) if args.name_args else ""
                
            if not name:
                print(f"❌ Error: Group name is required for the '{action}' action.", file=sys.stderr)
                sys.exit(1)
                
            if action in ["create", "update"]:
                policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
                if grp_type == "identity":
                    entity_ids = []
                    missing_entities = []
                    if args.members:
                        for m_name in [m.strip() for m in args.members.split(",") if m.strip()]:
                            try:
                                ent = client.read(f"identity/entity/name/{m_name}")['data']
                                entity_ids.append(ent['id'])
                            except: missing_entities.append(m_name)
                    if missing_entities:
                        print(f"❌ Error: Entities not found in Vault: {', '.join(missing_entities)}", file=sys.stderr)
                        sys.exit(1)
                    try:
                        client.write(f"identity/group/name/{name}", policies=policies, member_entity_ids=entity_ids)
                        print(f"✅ Vault Identity Group '{name}' successfully created/updated.")
                    except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                else:
                    try:
                        client.write(f"auth/{mount}/groups/{name}", policies=policies)
                        print(f"✅ External Group Mapping '{name}' successfully created/updated in '{mount}/'.")
                    except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                    
            elif action == "read":
                try:
                    details = client.read(f"identity/group/name/{name}")['data'] if grp_type == "identity" else client.read(f"auth/{mount}/groups/{name}")['data']
                    print(json.dumps(details, indent=2))
                except: print(f"⚠️ Group '{name}' not found.", file=sys.stderr)
                
            elif action == "info":
                try:
                    details = client.read(f"identity/group/name/{name}")['data'] if grp_type == "identity" else client.read(f"auth/{mount}/groups/{name}")['data']
                    if grp_type == "identity":
                        print(f"🏢 Identity Group: {name}")
                    else:
                        print(f"🏢 External Group ({grp_type}): {name} (Mount: {mount}/)")
                    policies = details.get('policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                except: print(f"⚠️ Group '{name}' not found.", file=sys.stderr)
                
            elif action == "delete":
                try:
                    if grp_type == "identity": client.delete(f"identity/group/name/{name}")
                    else: client.delete(f"auth/{mount}/groups/{name}")
                    print(f"✅ Deleted group '{name}'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 5. ENTITY MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "entity":
        name = "/".join(args.name_args) if args.name_args else ""
        if action == "list":
            try:
                keys = client.list("identity/entity/name")['data']['keys']
                print(f"👤 Existing Identity Entities ({len(keys)} found):")
                for k in keys: print(f"  ├─ {k}")
            except: print("ℹ️ No entities found.")
                
        else:
            if not name:
                print(f"❌ Error: Entity name is required.", file=sys.stderr)
                sys.exit(1)
            if action in ["create", "update"]:
                policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
                try:
                    client.write(f"identity/entity/name/{name}", policies=policies)
                    print(f"✅ Entity '{name}' successfully created/updated.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
            elif action == "read":
                try: print(json.dumps(client.read(f"identity/entity/name/{name}")['data'], indent=2))
                except: print(f"⚠️ Entity '{name}' not found.", file=sys.stderr)
            elif action == "info":
                try:
                    details = client.read(f"identity/entity/name/{name}")['data']
                    print(f"👤 Entity: {details.get('name')}")
                    print(f"  ├─ ID: {details.get('id')}")
                    policies = details.get('policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                    aliases = details.get('aliases', [])
                    if aliases:
                        print(f"  ├─ Aliases:")
                        for a in aliases: print(f"  │  ├─ {a.get('name')} (Mount: {a.get('mount_path')})")
                    else: print(f"  ├─ Aliases: None")
                except: print(f"⚠️ Entity '{name}' not found.", file=sys.stderr)
            elif action == "merge":
                if not getattr(args, 'target', None):
                    print("❌ Error: --target is required for merge.", file=sys.stderr)
                    sys.exit(1)
                try:
                    from_id = client.read(f"identity/entity/name/{name}")['data']['id']
                    to_id = client.read(f"identity/entity/name/{args.target}")['data']['id']
                    client.write("identity/entity/merge", from_entity_ids=[from_id], to_entity_id=to_id)
                    print(f"✅ Successfully merged '{name}' into '{args.target}'.")
                except Exception as e: print(f"❌ Error merging entities: {e}", file=sys.stderr)
            elif action == "delete":
                try:
                    client.delete(f"identity/entity/name/{name}")
                    print(f"✅ Deleted entity '{name}'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 6. ALIAS MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "alias":
        action = args.action
        alias_arg = args.name_args[0] if args.name_args else ""
        
        if action == "list":
            try:
                keys = client.list("identity/entity-alias/id")['data']['keys']
                print(f"🔗 Global Aliases ({len(keys)} found):")
                for k in keys:
                    a_data = client.read(f"identity/entity-alias/id/{k}")['data']
                    name = a_data.get('name', 'Unknown')
                    mnt = a_data.get('mount_path', 'Unknown')
                    print(f"  ├─ ID: {k} | Name: {name} | Mount: {mnt}")
            except: print("ℹ️ No aliases found.")
            sys.exit(0)

        if not alias_arg:
            print(f"❌ Error: Alias ID/Name is required.", file=sys.stderr)
            sys.exit(1)

        if action == "read":
            try: print(json.dumps(client.read(f"identity/entity-alias/id/{alias_arg}")['data'], indent=2))
            except: print(f"❌ Alias '{alias_arg}' not found.", file=sys.stderr)
        elif action == "info":
            try:
                data = client.read(f"identity/entity-alias/id/{alias_arg}")['data']
                print(f"🔗 Alias: {data.get('name')}")
                print(f"  ├─ ID: {data.get('id')}")
                print(f"  ├─ Mount: {data.get('mount_path')}")
            except: print(f"❌ Alias '{alias_arg}' not found.", file=sys.stderr)
        elif action in ["create", "update"]:
            try:
                ent_id = client.read(f"identity/entity/name/{args.entity}")['data']['id']
                client.write("identity/entity-alias", name=alias_arg, canonical_id=ent_id, mount_accessor=args.mount)
                print(f"✅ Alias successfully {action}d.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
        elif action == "delete":
            try:
                client.delete(f"identity/entity-alias/id/{alias_arg}")
                print(f"✅ Deleted alias '{alias_arg}'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 7. KUBERNETES MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "k8s":
        mount, name = parse_target(args.name_args, "kubernetes", action)
        
        if action == "configure":
            if not args.host or not args.ca_cert:
                print("❌ Error: --host and --ca-cert are required for configuration.", file=sys.stderr)
                sys.exit(1)
            try:
                with open(args.ca_cert, 'r') as f: ca_content = f.read()
                client.write(f"auth/{mount}/config", kubernetes_host=args.host, kubernetes_ca_cert=ca_content)
                print(f"✅ Kubernetes Auth Backend successfully linked to {args.host} at '{mount}/'")
            except Exception as e: print(f"❌ Error configuring K8s Auth: {e}", file=sys.stderr)
            sys.exit(0)
            
        if action == "list":
            mounts = [mount] if args.name_args else get_auth_mounts(client, 'kubernetes')
            found = False
            for m in mounts:
                try:
                    keys = client.list(f"auth/{m}/role")['data']['keys']
                    if keys:
                        print(f"⚓ K8s Roles in '{m}/':")
                        for k in keys: print(f"  ├─ {k}")
                        found = True
                except: pass
            if not found: print(f"ℹ️ No Kubernetes roles found.")
                
        elif action in ["create", "update"]:
            if not name or not args.sa_names or not args.sa_namespaces:
                print("❌ Error: Role name, --sa-names, and --sa-namespaces are required.", file=sys.stderr)
                sys.exit(1)
            policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
            sa_names = [s.strip() for s in args.sa_names.split(",")]
            sa_ns = [s.strip() for s in args.sa_namespaces.split(",")]
            try:
                client.write(f"auth/{mount}/role/{name}", bound_service_account_names=sa_names, bound_service_account_namespaces=sa_ns, token_policies=policies, token_ttl=args.ttl)
                print(f"✅ Kubernetes role '{name}' successfully created/updated in '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                
        elif action == "read":
            if not name: sys.exit("❌ Error: Role name is required.")
            try: print(json.dumps(client.read(f"auth/{mount}/role/{name}")['data'], indent=2))
            except: print(f"⚠️ Kubernetes role '{name}' not found in '{mount}/'.", file=sys.stderr)
                
        elif action == "info":
            if not name: sys.exit("❌ Error: Role name is required.")
            try:
                details = client.read(f"auth/{mount}/role/{name}")['data']
                print(f"⚓ Kubernetes Role: {name} (Mount: {mount}/)")
                print(f"  ├─ Service Accounts: {', '.join(details.get('bound_service_account_names', []))}")
                print(f"  ├─ Namespaces: {', '.join(details.get('bound_service_account_namespaces', []))}")
                policies = details.get('token_policies', [])
                print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                print(f"  ├─ Token TTL: {details.get('token_ttl', 'System Default')}s")
            except: print(f"⚠️ Kubernetes role '{name}' not found in '{mount}/'.", file=sys.stderr)
                
        elif action == "delete":
            if not name: sys.exit("❌ Error: Role name is required.")
            try:
                client.delete(f"auth/{mount}/role/{name}")
                print(f"✅ Deleted Kubernetes role '{name}' from '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 8. OIDC / SSO MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "oidc":
        mount, name = parse_target(args.name_args, "oidc", action)
        
        if action == "configure":
            if not args.client_id or not args.client_secret:
                print("❌ Error: --client-id and --client-secret are required for configure.", file=sys.stderr)
                sys.exit(1)
            try:
                client.write(f"auth/{mount}/config", oidc_client_id=args.client_id, oidc_client_secret=args.client_secret, default_role=args.default_role)
                print(f"✅ OIDC Engine configured successfully at '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

        elif action == "list":
            mounts = [mount] if args.name_args else get_auth_mounts(client, 'oidc')
            found = False
            for m in mounts:
                try:
                    keys = client.list(f"auth/{m}/role")['data']['keys']
                    if keys:
                        print(f"🌐 OIDC Roles in '{m}/':")
                        for k in keys: print(f"  ├─ {k}")
                        found = True
                except: pass
            if not found: print(f"ℹ️ No OIDC roles found.")

        elif action in ["create", "update"]:
            if not name: sys.exit("❌ Error: Role name is required.")
            if not args.emails and not args.groups:
                print("❌ Error: Must provide either --emails or --groups to bind to the role.", file=sys.stderr)
                sys.exit(1)
            bound_claims = {}
            if args.emails: bound_claims["email"] = [e.strip() for e in args.emails.split(",")]
            if args.groups: bound_claims["groups"] = [g.strip() for g in args.groups.split(",")]
            policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
            try:
                client.write(f"auth/{mount}/role/{name}", bound_claims=bound_claims, token_policies=policies, user_claim="sub", token_ttl=args.ttl)
                print(f"✅ OIDC Role '{name}' successfully {action}d in '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

        elif action == "read":
            if not name: sys.exit("❌ Error: Role name is required.")
            try: print(json.dumps(client.read(f"auth/{mount}/role/{name}")['data'], indent=2))
            except: print(f"⚠️ OIDC role '{name}' not found in '{mount}/'.", file=sys.stderr)
                
        elif action == "info":
            if not name: sys.exit("❌ Error: Role name is required.")
            try:
                details = client.read(f"auth/{mount}/role/{name}")['data']
                print(f"🌐 OIDC Role: {name} (Mount: {mount}/)")
                claims = details.get('bound_claims', {})
                if claims:
                    print(f"  ├─ Bound Claims:")
                    for k, v in claims.items(): print(f"  │  ├─ {k}: {v}")
                print(f"  ├─ Policies: {', '.join(details.get('token_policies', []))}")
            except: print(f"⚠️ OIDC role '{name}' not found in '{mount}/'.", file=sys.stderr)

        elif action == "delete":
            if not name: sys.exit("❌ Error: Role name is required.")
            try:
                client.delete(f"auth/{mount}/role/{name}")
                print(f"✅ Deleted OIDC role '{name}' from '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
    
        elif action == "register":
            # For register, the 'name' is actually the provider (e.g. gcp, okta)
            provider = name.lower()
            if not provider: sys.exit("❌ Error: Provider name is required (e.g. gcp, okta, azure).")

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
                else: print("   ✅ Project exists.")

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
                sys.exit(1)

            print(f"\n🚀 Step 3: Configuring Vault OIDC Engine for {provider.upper()}...")
            try:
                client.write(f"auth/{mount}/config", oidc_discovery_url=discovery_url, oidc_client_id=client_id, oidc_client_secret=client_secret, default_role="default")
                print(f"🎉 SUCCESS! Vault SSO is fully registered with {provider.upper()} at '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 9. GCP AUTH MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "gcp":
        mount, name = parse_target(args.name_args, "gcp", action)
        
        if action == "configure":
            creds_content = ""
            if getattr(args, 'credentials', None):
                try:
                    with open(args.credentials, 'r') as f: creds_content = f.read()
                except Exception as e:
                    print(f"❌ Error reading credentials file: {e}", file=sys.stderr)
                    sys.exit(1)
            elif getattr(args, 'project', None):
                project = args.project
                sa_name = args.sa_name
                sa_email = f"{sa_name}@{project}.iam.gserviceaccount.com"
                
                print(f"🚀 Initializing Zero-Touch GCP Auth Verifier in project: {project}...")
                subprocess.run([
                    "gcloud", "iam", "service-accounts", "create", sa_name,
                    "--display-name=Vault GCP Auth Verifier", "--project", project
                ], capture_output=True) 
                
                subprocess.run(["gcloud", "projects", "add-iam-policy-binding", project, f"--member=serviceAccount:{sa_email}", "--role=roles/iam.serviceAccountKeyAdmin"], capture_output=True)
                subprocess.run(["gcloud", "projects", "add-iam-policy-binding", project, f"--member=serviceAccount:{sa_email}", "--role=roles/compute.viewer"], capture_output=True)
                
                res = subprocess.run(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project], capture_output=True, text=True)
                if res.returncode != 0:
                    print(f"❌ Failed to generate Service Account key: {res.stderr}", file=sys.stderr)
                    sys.exit(1)
                creds_content = res.stdout.strip()
            else:
                print("❌ Error: You must provide either --project (for zero-touch) or --credentials (for manual file).", file=sys.stderr)
                sys.exit(1)
            
            try:
                client.write(f"auth/{mount}/config", credentials=creds_content)
                print(f"✅ GCP Auth Backend successfully configured at '{mount}/'.")
            except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                
        elif action == "list":
            mounts = [mount] if args.name_args else get_auth_mounts(client, 'gcp')
            found = False
            for m in mounts:
                try:
                    keys = client.list(f"auth/{m}/role")['data']['keys']
                    if keys:
                        print(f"☁️ GCP Roles in '{m}/':")
                        for k in keys: print(f"  ├─ {k}")
                        found = True
                except: pass
            if not found: print("ℹ️ No GCP auth roles found.")
                
        else:
            if not name: sys.exit("❌ Error: Role name is required.")
            if action in ["create", "update"]:
                if not args.sa_emails:
                    print("❌ Error: --sa-emails is required to create a GCP auth role.", file=sys.stderr)
                    sys.exit(1)
                sa_emails = [s.strip() for s in args.sa_emails.split(",")]
                policies = [p.strip() for p in args.policies.split(",")] if args.policies else []
                try:
                    client.write(f"auth/{mount}/role/{name}", type=args.type, bound_service_accounts=sa_emails, token_policies=policies, token_ttl=args.ttl)
                    print(f"✅ GCP auth role '{name}' successfully created/updated in '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                    
            elif action == "read":
                try: print(json.dumps(client.read(f"auth/{mount}/role/{name}")['data'], indent=2))
                except: print(f"⚠️ GCP auth role '{name}' not found in '{mount}/'.", file=sys.stderr)
                
            elif action == "info":
                try:
                    details = client.read(f"auth/{mount}/role/{name}")['data']
                    print(f"☁️ GCP Auth Role: {name} (Mount: {mount}/)")
                    print(f"  ├─ Type: {details.get('type', 'iam')}")
                    print(f"  ├─ Service Accounts: {', '.join(details.get('bound_service_accounts', []))}")
                    policies = details.get('token_policies', [])
                    print(f"  ├─ Policies: {', '.join(policies) if policies else 'None'}")
                except: print(f"⚠️ GCP auth role '{name}' not found in '{mount}/'.", file=sys.stderr)
                
            elif action == "delete":
                try:
                    client.delete(f"auth/{mount}/role/{name}")
                    print(f"✅ Deleted GCP auth role '{name}' from '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 10. LDAP AUTH METHOD
    # -------------------------------------------------------------------------
    elif cmd == "ldap":
        ldap_cmd = args.ldap_cmd
        action = args.action
        
        # Determine if this is a config action (which doesn't have a role name)
        is_config = (ldap_cmd == "config")
        mount, name = parse_target(args.name_args, "ldap", action, is_config=is_config)

        if ldap_cmd in ["user", "group"]:
            if action not in ["list"] and not name:
                print(f"❌ Error: 'name' is required for the '{action}' action.", file=sys.stderr)
                sys.exit(1)

        if ldap_cmd == "config":
            if action in ["list", "read", "info"]:
                mounts = [mount] if args.name_args else get_auth_mounts(client, 'ldap')
                found = False
                if action == "list": print("🏛️  Active LDAP Auth Mounts:")
                
                for m in mounts:
                    try:
                        res = client.read(f"auth/{m}/config")
                        if res and 'data' in res:
                            if action == "read":
                                if "bindpass" in res['data']: res['data']['bindpass'] = "***REDACTED***"
                                print(json.dumps(res['data'], indent=2))
                            else:
                                d = res['data']
                                if action == "list":
                                    url = d.get('url', 'Not Set')
                                    print(f"  ├─ {m}/ (URL: {url})")
                                else:
                                    print(f"🏛️  LDAP Configuration (Mount: {m}/)")
                                    print(f"  ├─ Server URL   : {d.get('url', 'Not Set')}")
                                    print(f"  ├─ Bind DN      : {d.get('binddn', 'Not Set')}")
                                    print(f"  ├─ User Base DN : {d.get('userdn', 'Not Set')} (Attr: {d.get('userattr', 'uid')})")
                                    print(f"  ├─ Group Base DN: {d.get('groupdn', 'Not Set')} (Attr: {d.get('groupattr', 'cn')})")
                            found = True
                        else:
                            if action == "list": print(f"  ├─ {m}/ (Unconfigured)")
                    except: 
                        if action == "list": print(f"  ├─ {m}/ (Access Denied / Unconfigured)")
                        
                if not found and action != "list": print(f"❌ LDAP config not found at '{mount}/'.", file=sys.stderr)
                if not found and action == "list": print("  ℹ️ No LDAP mounts found.")

            elif action in ["create", "update"]:
                payload = {}
                if getattr(args, 'url', None): payload["url"] = args.url
                if getattr(args, 'bind_dn', None): payload["binddn"] = args.bind_dn
                if getattr(args, 'bind_pass', None): payload["bindpass"] = args.bind_pass
                if getattr(args, 'user_dn', None): payload["userdn"] = args.user_dn
                if getattr(args, 'group_dn', None): payload["groupdn"] = args.group_dn
                if getattr(args, 'user_attr', None): payload["userattr"] = args.user_attr
                if getattr(args, 'group_attr', None): payload["groupattr"] = args.group_attr
                try:
                    client.write(f"auth/{mount}/config", **payload)
                    print(f"✅ LDAP Auth configuration successfully updated at '{mount}/'.")
                except Exception as e: print(f"❌ Error updating LDAP config: {e}", file=sys.stderr)

            elif action == "delete":
                try:
                    client.delete(f"auth/{mount}/config")
                    print(f"✅ LDAP Auth configuration deleted at '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

        elif ldap_cmd in ["group", "user"]:
            target = "groups" if ldap_cmd == "group" else "users"
            
            if action == "list":
                mounts = [mount] if args.name_args else get_auth_mounts(client, 'ldap')
                found = False
                for m in mounts:
                    try:
                        keys = client.list(f"auth/{m}/{target}")['data']['keys']
                        if keys:
                            print(f"👥 LDAP {target.capitalize()} in '{m}/':")
                            for k in keys: print(f"  ├─ {k}")
                            found = True
                    except: pass
                if not found: print(f"ℹ️ No LDAP {target} found.")
                    
            elif action in ["read", "info"]:
                try:
                    res = client.read(f"auth/{mount}/{target}/{name}")
                    if res and 'data' in res:
                        if action == "read":
                            print(json.dumps(res['data'], indent=2))
                        else:
                            d = res['data']
                            icon = "🏢" if ldap_cmd == "group" else "👤"
                            print(f"{icon} LDAP {ldap_cmd.capitalize()} Mapping: {name} (Mount: {mount}/)")
                            pols = d.get('policies', [])
                            print(f"  ├─ Policies : {', '.join(pols) if pols else 'None'}")
                            if ldap_cmd == "user":
                                grps = d.get('groups', [])
                                print(f"  ├─ Groups   : {', '.join(grps) if grps else 'None'}")
                    else: print(f"❌ Mapping not found in '{mount}/'.", file=sys.stderr)
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)
                    
            elif action in ["create", "update"]:
                payload = {}
                if getattr(args, "policies", None) is not None:
                    payload["policies"] = [p.strip() for p in args.policies.split(",") if p.strip()]
                if ldap_cmd == "user" and getattr(args, "groups", None) is not None:
                    payload["groups"] = [g.strip() for g in args.groups.split(",") if g.strip()]
                try:
                    client.write(f"auth/{mount}/{target}/{name}", **payload)
                    print(f"✅ LDAP {ldap_cmd} '{name}' mapped successfully in '{mount}/'.")
                except Exception as e: print(f"❌ Error updating mapping: {e}", file=sys.stderr)
                    
            elif action == "delete":
                try:
                    client.delete(f"auth/{mount}/{target}/{name}")
                    print(f"✅ LDAP {ldap_cmd} '{name}' mapping deleted from '{mount}/'.")
                except Exception as e: print(f"❌ Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
