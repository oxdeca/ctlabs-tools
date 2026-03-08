# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_audit.py
# Purpose : Dedicated CLI for Auditing & Graphing Vault Access Paths
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import re
import fnmatch
from .core import HashiVault

# =============================================================================
# HELPER: Vault API Abstractions (Handling Modern vs Legacy Endpoints)
# =============================================================================
def _get_policy_rules(client, policy_name):
    """Safely fetches a policy supporting both modern and legacy Vault API endpoints."""
    try:
        res = client.read(f"sys/policies/acl/{policy_name}")
        if res and 'data' in res and 'policy' in res['data']:
            return res['data']['policy']
    except Exception: pass

    try:
        res = client.read(f"sys/policy/{policy_name}")
        if res and 'data' in res and 'rules' in res['data']:
            return res['data']['rules']
    except Exception: pass

    return None

def _get_policy_list(client):
    """Safely fetches the list of policies from either modern or legacy endpoints."""
    try:
        res = client.list("sys/policies/acl")
        if res and 'data' in res:
            return res['data'].get('keys', [])
    except Exception: pass

    try:
        res = client.sys.list_policies()
        if res and 'data' in res:
            return res['data'].get('keys', [])
    except Exception: pass

    raise Exception("Permission denied to both sys/policies/acl and sys/policy")

# =============================================================================
# HELPER: Path Matching & Parsing
# =============================================================================
def extract_policy_paths(hcl_text):
    """Extracts raw paths and capabilities from Vault HCL."""
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
    return paths

def vault_path_match(policy_path, target_path):
    """Simulates Vault's internal path matching logic (* and +)."""
    regex_str = policy_path.replace('+', '[^/]+').replace('*', '.*')
    try:
        return re.match(f"^{regex_str}$", target_path) is not None
    except re.error:
        return False

# =============================================================================
# HELPER: UI Rendering
# =============================================================================
def render_policy_table(name, paths):
    """Prints a beautifully formatted permission table."""
    print(f"\n📜 VAULT ACL POLICY: {name}")

    if not paths:
        print("  ⚠️ No parsable paths/capabilities found.")
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
                if c == "deny": cap_strs.append(f"{RED}{'ok'.center(6)}{RESET}")
                else: cap_strs.append(f"{GREEN}{'ok'.center(6)}{RESET}")
            else: cap_strs.append(f"{DIM}{'--'.center(6)}{RESET}")
        row += " | ".join(cap_strs)
        print(row)
        
    print("=" * table_width)

def scan_engine_roles(vault, paths):
    """Analyzes policy paths and fetches downstream external bindings."""
    client = vault._get_client()
    found_any = False

    for path in paths.keys():
        # 1. GCP
        gcp_match = re.match(r'^gcp/([^/]+)/(?:token|key)/([^/*]+)', path)
        if gcp_match:
            project, role = gcp_match.groups()
            try:
                data = client.read(f"gcp/{project}/roleset/{role}")
                if data and 'data' in data:
                    d = data['data']
                    found_any = True
                    print(f"\n  ☁️  GCP Roleset: {role} (Project: {project})")
                    print(f"      ├─ SA Email : {d.get('service_account_email', 'Dynamic/Unknown')}")
                    bindings = d.get('bindings', '')
                    if isinstance(bindings, dict):
                        print(f"      ├─ Bindings :")
                        for uri, roles in bindings.items():
                            display_uri = uri.split('googleapis.com/')[-1] if 'googleapis.com/' in uri else uri
                            print(f"      │  ├─ {display_uri}")
                            for r in roles: print(f"      │  │  ├─ {r}")
                    elif bindings: print(f"      ├─ Bindings : Configured (Raw HCL)")
                    else: print(f"      ├─ Bindings : None")
            except Exception: pass

        # 2. K8s
        k8s_match = re.match(r'^k8s/([^/]+)/creds/([^/*]+)', path)
        if k8s_match:
            cluster, role = k8s_match.groups()
            try:
                data = client.read(f"k8s/{cluster}/roles/{role}")
                if data and 'data' in data:
                    d = data['data']
                    found_any = True
                    print(f"\n  ⚓ K8s Role: {role} (Cluster: {cluster})")
                    print(f"      ├─ Type       : {d.get('kubernetes_role_type', 'Unknown')}")
                    ns = d.get('allowed_kubernetes_namespaces', [])
                    print(f"      ├─ Namespaces : {', '.join(ns) if ns else 'None'}")
                    print(f"      ├─ SA Name    : {d.get('service_account_name', 'Dynamic')}")
            except Exception: pass
            
        # 3. PKI
        pki_match = re.match(r'^pki/([^/]+)/issue/([^/*]+)', path)
        if pki_match:
            ca_name, role = pki_match.groups()
            try:
                data = client.read(f"pki/{ca_name}/roles/{role}")
                if data and 'data' in data:
                    d = data['data']
                    found_any = True
                    print(f"\n  🏛️  PKI Role: {role} (CA: {ca_name})")
                    print(f"      ├─ Domains : {', '.join(d.get('allowed_domains', []))}")
                    print(f"      ├─ Max TTL : {d.get('max_ttl', 'System Default')}s")
            except Exception: pass

    if not found_any:
        print("  ℹ️  No specific external secrets engine roles strictly mapped in this policy.")

def scan_upstream_identities(vault, target_policies):
    """Scans the Identity engine to find who has specific policies attached."""
    client = vault._get_client()
    found_any = False
    
    # 1. Scan Groups
    try:
        res = client.list("identity/group/id")
        group_ids = res.get('data', {}).get('keys', []) if res else []
        for gid in group_ids:
            g_data = client.read(f"identity/group/id/{gid}")
            if g_data and 'data' in g_data:
                policies = set(g_data['data'].get('policies', []))
                intersect = policies.intersection(target_policies)
                if intersect:
                    found_any = True
                    name = g_data['data'].get('name', gid)
                    print(f"  🏢 Identity Group : {name} (via {', '.join(intersect)})")
    except Exception: pass

    # 2. Scan Entities
    try:
        res = client.list("identity/entity/id")
        entity_ids = res.get('data', {}).get('keys', []) if res else []
        for eid in entity_ids:
            e_data = client.read(f"identity/entity/id/{eid}")
            if e_data and 'data' in e_data:
                policies = set(e_data['data'].get('policies', []))
                intersect = policies.intersection(target_policies)
                if intersect:
                    found_any = True
                    name = e_data['data'].get('name', eid)
                    print(f"  👤 Identity Entity: {name} (via {', '.join(intersect)})")
    except Exception: pass
    
    # 3. Scan AppRoles
    try:
        res = client.list("auth/approle/role")
        approles = res.get('data', {}).get('keys', []) if res else []
        for role in approles:
            ar_data = client.read(f"auth/approle/role/{role}")
            if ar_data and 'data' in ar_data:
                policies = set(ar_data['data'].get('token_policies', []))
                intersect = policies.intersection(target_policies)
                if intersect:
                    found_any = True
                    print(f"  🤖 AppRole Mount  : {role} (via {', '.join(intersect)})")
    except Exception: pass

    if not found_any:
        print("  ℹ️  No Groups, Entities, or AppRoles currently have this policy attached.")


# =============================================================================
# CORE AUDIT COMMANDS
# =============================================================================

def list_policies(vault, category):
    client = vault._get_client()
    try:
        policies = _get_policy_list(client)
    except Exception as e:
        print(f"❌ Error fetching policies: {e}", file=sys.stderr)
        return
        
    if category == "all":
        print("📜 All Cluster Policies:")
        for p in policies: print(f"  ├─ {p}")
        return
        
    print(f"⏳ Categorizing {len(policies)} policies...")
    sys.stdout.write("\033[F\033[K") # Clear the loading line
    
    auth_pols, access_pols, secret_pols = [], [], []
    
    for p in policies:
        if p in ["root", "default"]: 
            if category == "auth": auth_pols.append(p)
            continue
            
        rules_hcl = _get_policy_rules(client, p)
        if not rules_hcl: continue
            
        paths = extract_policy_paths(rules_hcl)
        is_auth, is_access, is_secret = False, False, False
        
        for path in paths.keys():
            clean_path = path.strip('/')
            if not clean_path: continue
            
            prefix = clean_path.split('/')[0].strip('*+')
            
            # 1. Auth & Internals
            if prefix in ["sys", "auth", "identity"]:
                is_auth = True
            # 2. Pure Static Secrets
            elif prefix in ["kv", "kvv2", "secret", "cubbyhole"]:
                is_secret = True
            # 3. Dynamic Access Brokers (GCP, K8s, PKI, SSH, DBs, etc.)
            else:
                is_access = True
                
        if is_auth: auth_pols.append(p)
        if is_secret: secret_pols.append(p)
        if is_access: access_pols.append(p)
        
    if category == "access":
        print("🌍 Access Policies (Dynamic Identity Brokers - GCP, K8s, SSH):")
        for p in sorted(set(access_pols)): print(f"  ├─ {p}")
    elif category == "secrets":
        print("🔐 Secrets Policies (Static Key-Value Storage):")
        for p in sorted(set(secret_pols)): print(f"  ├─ {p}")
    elif category == "auth":
        print("🛡️  Auth Policies (Vault Admins, Login & Identity Mapping):")
        for p in sorted(set(auth_pols)): print(f"  ├─ {p}")


def list_roles(vault, engine_type, engine_name):
    # 🌟 FIX: Map CLI shortcut 'k8s' to Vault's internal 'kubernetes' type
    if engine_type == "k8s":
        engine_type = "kubernetes"

    client = vault._get_client()
    print("🔍 Scanning mounts for active roles...\n")
    try:
        mounts = client.sys.list_mounted_secrets_engines()['data']
        
        for path, info in mounts.items():
            m_type = info.get('type')
            clean_path = path.strip('/')
            
            if engine_type != "all" and m_type != engine_type:
                continue
                
            mount_basename = clean_path.split('/')[-1]
            if engine_name and mount_basename != engine_name:
                continue
            
            roles = []
            try:
                if m_type == "gcp":
                    res = client.list(f"{clean_path}/roleset")
                    roles = res.get('data', {}).get('keys', []) if res else []
                elif m_type in ["kubernetes", "pki", "ssh"]:
                    res = client.list(f"{clean_path}/roles")
                    roles = res.get('data', {}).get('keys', []) if res else []
                elif m_type == "ldap":
                    res = client.list(f"{clean_path}/role")
                    roles = res.get('data', {}).get('keys', []) if res else []
            except Exception: pass
            
            if roles:
                badge = {"gcp":"☁️", "kubernetes":"⚓", "pki":"🏛️", "ssh":"🌐", "ldap":"👥"}.get(m_type, "⚙️")
                print(f"{badge} {m_type.upper()} Engine: {path}")
                for r in roles: 
                    print(f"  ├─ {r}")
                print("")
    except Exception as e:
        print(f"❌ Error fetching mounts: {e}")

def audit_policy(vault, policy_name, show_upstream=True):
    client = vault._get_client()
    rules_hcl = _get_policy_rules(client, policy_name)
    
    if not rules_hcl:
        print(f"❌ Policy '{policy_name}' not found or lacks readable rules.", file=sys.stderr)
        return
        
    parsed_paths = extract_policy_paths(rules_hcl)
    render_policy_table(policy_name, parsed_paths)
    
    print("\n⚙️  DOWNSTREAM: External Systems & Roles")
    if parsed_paths:
        scan_engine_roles(vault, parsed_paths)
        
    if show_upstream:
        print("\n👥 UPSTREAM: Identities with this policy")
        scan_upstream_identities(vault, {policy_name})

def audit_role(vault, role_name, target_engine_name=None, target_engine_type=None):
    """Reverse-Lookup: Starts with a role, finds policies that grant it, finds users who have policies."""
    
    # 🌟 FIX: Map CLI shortcut 'k8s' to Vault's internal 'kubernetes' type
    if target_engine_type == "k8s":
        target_engine_type = "kubernetes"

    client = vault._get_client()
    
    desc_parts = []
    if target_engine_type: desc_parts.append(f"type '{target_engine_type}'")
    if target_engine_name: desc_parts.append(f"mount '{target_engine_name}'")
    desc = " in " + " and ".join(desc_parts) if desc_parts else " across all engines"
    
    print(f"\n🔎 REVERSE AUDIT: Who has access to role '{role_name}'{desc}?\n" + "="*70)
    
    mounts = client.sys.list_mounted_secrets_engines()['data']
    found_engines = []
    target_paths = []
    
    print("⏳ Locating role across cluster engines...")
    for path, info in mounts.items():
        m_type = info.get('type')
        clean_path = path.strip('/')
        
        mount_parts = clean_path.split('/')
        mount_basename = mount_parts[-1]
        mount_type_prefix = mount_parts[0] if len(mount_parts) > 1 else None

        if target_engine_type and m_type != target_engine_type and mount_type_prefix != target_engine_type:
            continue
            
        if target_engine_name and mount_basename != target_engine_name and clean_path != target_engine_name:
            continue
            
        try:
            if m_type == "gcp":
                res = client.list(f"{clean_path}/roleset")
                if res and role_name in res.get('data', {}).get('keys', []):
                    found_engines.append(("GCP", clean_path))
                    target_paths.extend([f"{clean_path}/token/{role_name}", f"{clean_path}/key/{role_name}"])
            elif m_type == "kubernetes":
                res = client.list(f"{clean_path}/roles")
                if res and role_name in res.get('data', {}).get('keys', []):
                    found_engines.append(("Kubernetes", clean_path))
                    target_paths.append(f"{clean_path}/creds/{role_name}")
            elif m_type == "pki":
                res = client.list(f"{clean_path}/roles")
                if res and role_name in res.get('data', {}).get('keys', []):
                    found_engines.append(("PKI", clean_path))
                    target_paths.extend([f"{clean_path}/issue/{role_name}", f"{clean_path}/sign/{role_name}"])
        except Exception: pass
        
    if not found_engines:
        print(f"❌ Role '{role_name}' could not be found.")
        return
        
    for eng_type, clean_path in found_engines:
        print(f"✅ Found {eng_type} role in engine '{clean_path}/'")
    
    print("\n⏳ Scanning ALL Vault policies for matching capability grants...")
    matching_policies = set()
    
    try:
        all_policies = _get_policy_list(client)
    except Exception:
        all_policies = []
    
    for p in all_policies:
        if p in ["root", "default"]: continue
        rules = _get_policy_rules(client, p)
        if not rules: continue
        
        parsed_paths = extract_policy_paths(rules)
        for pol_path, caps in parsed_paths.items():
            for t_path in target_paths:
                if vault_path_match(pol_path, t_path):
                    if "deny" not in caps and any(c in caps for c in ["read", "update", "create"]):
                        matching_policies.add(p)
                        break
                        
    if not matching_policies:
        print("  ⚠️ No policies grant access to this role.")
        return
        
    print("📜 Policies granting access:")
    for mp in matching_policies: print(f"  ├─ {mp}")
        
    print("\n👥 Identities inheriting these policies:")
    scan_upstream_identities(vault, matching_policies)

def audit_identity(vault, target_name, is_group=False):
    """Forward-Lookup: Resolves an entity/user or group, calculates inherited policies, shows access."""
    client = vault._get_client()
    id_type = "Group" if is_group else "User/Entity"
    print(f"\n🔎 FORWARD AUDIT: Access graph for {id_type} '{target_name}'\n" + "="*70)
    
    policies = set()
    
    if is_group:
        try:
            res = client.read(f"identity/group/name/{target_name}")
            if not res or 'data' not in res: raise Exception("Not found")
            policies.update(res['data'].get('policies', []))
            print(f"🏢 Group ID : {res['data']['id']}")
            print(f"📜 Policies : {', '.join(policies) if policies else 'None'}")
        except Exception:
            print(f"❌ Group '{target_name}' not found.")
            return
    else:
        try:
            res = client.read(f"identity/entity/name/{target_name}")
            if not res or 'data' not in res: raise Exception("Not found")
            
            print(f"👤 Entity ID : {res['data']['id']}")
            
            direct_pol = res['data'].get('policies', [])
            policies.update(direct_pol)
            if direct_pol: print(f"📜 Direct Policies : {', '.join(direct_pol)}")
            
            group_ids = res['data'].get('group_ids', [])
            if group_ids:
                print(f"🏢 Inherited via Groups:")
                for gid in group_ids:
                    try:
                        g_data = client.read(f"identity/group/id/{gid}")
                        if g_data and 'data' in g_data:
                            g_name = g_data['data'].get('name', gid)
                            g_pols = g_data['data'].get('policies', [])
                            policies.update(g_pols)
                            print(f"  ├─ {g_name} (Grants: {', '.join(g_pols) if g_pols else 'None'})")
                    except Exception: pass
            
        except Exception:
            print(f"❌ User/Entity '{target_name}' not found.")
            return

    if not policies:
        print(f"\n⚠️ No policies attached to this {id_type.lower()}. Access is completely restricted.")
        return
        
    print("\n" + "="*70)
    print("🔻 DOWNSTREAM ACCESS (Merged capabilities)")
    print("="*70)
    
    for p in policies:
        if p in ["default", "root"]: continue
        audit_policy(vault, p, show_upstream=False)

# =============================================================================
# CLI ROUTER
# =============================================================================

def get_args():
    parser = argparse.ArgumentParser(description="Vault Access Path Auditor")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. POLICY
    p_policy = subparsers.add_parser("policy", help="Audit ACL Policies")
    p_pol_subs = p_policy.add_subparsers(dest="action", required=True)
    p_pol_list = p_pol_subs.add_parser("list", help="List policies")
    p_pol_list.add_argument("category", nargs="?", choices=["auth", "access", "secrets", "all"], default="all", help="Filter by logical category")
    p_pol_info = p_pol_subs.add_parser("info", help="Audit a specific policy")
    p_pol_info.add_argument("name", help="Policy name")

    # 2. ROLE
    p_role = subparsers.add_parser("role", help="Audit External Roles")
    p_role_subs = p_role.add_subparsers(dest="action", required=True)
    p_role_list = p_role_subs.add_parser("list", help="List active roles")
    p_role_list.add_argument("engine_type", nargs="?", choices=["gcp", "k8s", "pki", "ssh", "ldap", "all"], default="all", help="Filter by engine type")
    p_role_list.add_argument("engine_name", nargs="?", default="", help="Filter by specific mount name")
    p_role_info = p_role_subs.add_parser("info", help="Reverse-audit a specific role")
    p_role_info.add_argument("name_args", nargs="+", help="Supports: [role], [mount] [role], or [type]/[mount]/[role]")

    # 3. ENTITY
    p_entity = subparsers.add_parser("entity", help="Audit Entity Access")
    p_ent_subs = p_entity.add_subparsers(dest="action", required=True)
    p_ent_subs.add_parser("list", help="List entities")
    p_ent_info = p_ent_subs.add_parser("info", help="Audit specific entity")
    p_ent_info.add_argument("name", help="Entity name")

    # 4. USER (Alias for Entity)
    p_user = subparsers.add_parser("user", help="Audit User Access (Alias for Entity)")
    p_usr_subs = p_user.add_subparsers(dest="action", required=True)
    p_usr_subs.add_parser("list", help="List users (entities)")
    p_usr_info = p_usr_subs.add_parser("info", help="Audit specific user")
    p_usr_info.add_argument("name", help="User name")

    # 5. GROUP
    p_group = subparsers.add_parser("group", help="Audit Group Access")
    p_grp_subs = p_group.add_subparsers(dest="action", required=True)
    p_grp_subs.add_parser("list", help="List groups")
    p_grp_info = p_grp_subs.add_parser("info", help="Audit specific group")
    p_grp_info.add_argument("name", help="Group name")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    action = args.action

    if cmd == "policy":
        if action == "list":
            list_policies(vault, args.category)
        elif action == "info":
            name = getattr(args, 'name', '')
            if not name:
                print(f"❌ Error: 'name' is required for the 'info' action.", file=sys.stderr)
                sys.exit(1)
            print(f"\n🔎 AUDITING VAULT ACCESS PATH FOR POLICY: '{name}'\n" + "="*70)
            audit_policy(vault, name)

    elif cmd == "role":
        if action == "list":
            list_roles(vault, args.engine_type, args.engine_name)
        elif action == "info":
            tokens = []
            for arg_str in args.name_args:
                tokens.extend(arg_str.split('/'))
            tokens = [t for t in tokens if t]
            
            eng_type, eng_name, r_name = None, None, None
            
            if len(tokens) >= 3:
                eng_type = tokens[-3]
                eng_name = tokens[-2]
                r_name = tokens[-1]
            elif len(tokens) == 2:
                eng_name = tokens[0]
                r_name = tokens[1]
            elif len(tokens) == 1:
                r_name = tokens[0]
            else:
                print("❌ Error: Invalid role format provided.", file=sys.stderr)
                sys.exit(1)
                
            audit_role(vault, r_name, target_engine_name=eng_name, target_engine_type=eng_type)

    elif cmd in ["entity", "user"]:
        label = "User / Entity" if cmd == "user" else "Identity Entity"
        if action == "list":
            client = vault._get_client()
            try:
                res = client.list("identity/entity/name")
                keys = res.get('data', {}).get('keys', []) if res else []
                if keys:
                    print(f"👤 Existing {label} Records:")
                    for k in keys: print(f"  ├─ {k}")
                else: print(f"ℹ️ No {label.lower()} records found.")
            except Exception as e: print(f"❌ Error fetching records: {e}", file=sys.stderr)
                
        elif action == "info":
            name = getattr(args, 'name', '')
            if not name:
                print("❌ Error: 'name' is required.", file=sys.stderr)
                sys.exit(1)
            audit_identity(vault, name, is_group=False)

    elif cmd == "group":
        if action == "list":
            client = vault._get_client()
            try:
                res = client.list("identity/group/name")
                keys = res.get('data', {}).get('keys', []) if res else []
                if keys:
                    print("🏢 Existing Identity Groups:")
                    for k in keys: print(f"  ├─ {k}")
                else: print("ℹ️ No groups found.")
            except Exception as e: print(f"❌ Error fetching groups: {e}", file=sys.stderr)
                
        elif action == "info":
            name = getattr(args, 'name', '')
            if not name:
                print("❌ Error: 'name' is required.", file=sys.stderr)
                sys.exit(1)
            audit_identity(vault, name, is_group=True)

if __name__ == "__main__":
    main()
