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
# COMMANDS
# =============================================================================

def list_cluster_inventory(vault, item_type):
    client = vault._get_client()
    
    if item_type == "policies":
        print("📜 All Cluster Policies:")
        try:
            policies = client.sys.list_policies()['data']['keys']
            for p in policies: print(f"  ├─ {p}")
        except Exception as e:
            print(f"❌ Error fetching policies: {e}")
            
    elif item_type == "roles":
        print("🔍 Scanning all mounts for active roles...\n")
        try:
            mounts = client.sys.list_mounted_secrets_engines()['data']
            
            for path, info in mounts.items():
                m_type = info.get('type')
                clean_path = path.strip('/')
                
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
                    for r in roles: print(f"  ├─ {r}")
                    print("")
        except Exception as e:
            print(f"❌ Error fetching mounts: {e}")

def audit_policy(vault, policy_name, show_upstream=True):
    client = vault._get_client()
    try:
        res = client.read(f"sys/policy/{policy_name}")
        if not res or 'data' not in res or 'rules' not in res['data']:
            print(f"❌ Policy '{policy_name}' not found.", file=sys.stderr)
            return
        rules_hcl = res['data']['rules']
    except Exception as e:
        print(f"❌ Error fetching policy: {e}", file=sys.stderr)
        return
        
    parsed_paths = extract_policy_paths(rules_hcl)
    render_policy_table(policy_name, parsed_paths)
    
    print("\n⚙️  DOWNSTREAM: External Systems & Roles")
    if parsed_paths:
        scan_engine_roles(vault, parsed_paths)
        
    if show_upstream:
        print("\n👥 UPSTREAM: Identities with this policy")
        scan_upstream_identities(vault, {policy_name})

def audit_role(vault, role_name):
    """Reverse-Lookup: Starts with a role, finds policies that grant it, finds users who have policies."""
    client = vault._get_client()
    print(f"\n🔎 REVERSE AUDIT: Who has access to role '{role_name}'?\n" + "="*70)
    
    # 1. Find where this role lives
    mounts = client.sys.list_mounted_secrets_engines()['data']
    found_engine = None
    target_paths = []
    
    print("⏳ Locating role across all cluster engines...")
    for path, info in mounts.items():
        m_type = info.get('type')
        clean_path = path.strip('/')
        
        try:
            if m_type == "gcp":
                res = client.list(f"{clean_path}/roleset")
                if res and role_name in res.get('data', {}).get('keys', []):
                    found_engine = ("GCP", clean_path)
                    target_paths = [f"{clean_path}/token/{role_name}", f"{clean_path}/key/{role_name}"]
            elif m_type == "kubernetes":
                res = client.list(f"{clean_path}/roles")
                if res and role_name in res.get('data', {}).get('keys', []):
                    found_engine = ("Kubernetes", clean_path)
                    target_paths = [f"{clean_path}/creds/{role_name}"]
            elif m_type == "pki":
                res = client.list(f"{clean_path}/roles")
                if res and role_name in res.get('data', {}).get('keys', []):
                    found_engine = ("PKI", clean_path)
                    target_paths = [f"{clean_path}/issue/{role_name}", f"{clean_path}/sign/{role_name}"]
        except Exception: pass
        
    if not found_engine:
        print(f"❌ Role '{role_name}' could not be found in any standard secrets engine.")
        return
        
    print(f"✅ Found {found_engine[0]} role in engine '{found_engine[1]}/'")
    
    # 2. Find policies granting access
    print("\n⏳ Scanning ALL Vault policies for matching capability grants...")
    matching_policies = set()
    all_policies = client.sys.list_policies()['data']['keys']
    
    for p in all_policies:
        if p in ["root", "default"]: continue
        try:
            rules = client.read(f"sys/policy/{p}")['data']['rules']
            parsed_paths = extract_policy_paths(rules)
            
            for pol_path, caps in parsed_paths.items():
                for t_path in target_paths:
                    if vault_path_match(pol_path, t_path):
                        if "deny" not in caps and any(c in caps for c in ["read", "update", "create"]):
                            matching_policies.add(p)
                            break
        except Exception: pass
        
    if not matching_policies:
        print("  ⚠️ No policies grant access to this role.")
        return
        
    print("📜 Policies granting access:")
    for mp in matching_policies: print(f"  ├─ {mp}")
        
    # 3. Find identities holding those policies
    print("\n👥 Identities inheriting these policies:")
    scan_upstream_identities(vault, matching_policies)

def audit_identity(vault, target_name, is_group=False):
    """Forward-Lookup: Resolves an entity or group, calculates inherited policies, shows access."""
    client = vault._get_client()
    print(f"\n🔎 FORWARD AUDIT: Access graph for {'Group' if is_group else 'Entity'} '{target_name}'\n" + "="*70)
    
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
            print(f"❌ Entity '{target_name}' not found.")
            return

    if not policies:
        print("\n⚠️ No policies attached to this identity. Access is completely restricted.")
        return
        
    print("\n" + "="*70)
    print("🔻 DOWNSTREAM ACCESS (Merged capabilities)")
    print("="*70)
    
    for p in policies:
        if p in ["default", "root"]: continue
        audit_policy(vault, p, show_upstream=False)

def get_args():
    parser = argparse.ArgumentParser(description="Vault Access Path Auditor")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. POLICY
    p_policy = subparsers.add_parser("policy", help="Audit ACL Policies")
    p_policy.add_argument("action", choices=["list", "info"], help="Action to perform")
    p_policy.add_argument("name", nargs="?", default="", help="Policy name (required for info)")

    # 2. ROLE
    p_role = subparsers.add_parser("role", help="Audit External Roles")
    p_role.add_argument("action", choices=["list", "info"], help="Action to perform")
    p_role.add_argument("name", nargs="?", default="", help="Role name (required for info)")

    # 3. ENTITY
    p_entity = subparsers.add_parser("entity", help="Audit Entity Access")
    p_entity.add_argument("action", choices=["list", "info"], help="Action to perform")
    p_entity.add_argument("name", nargs="?", default="", help="Entity name (required for info)")

    # 4. GROUP
    p_group = subparsers.add_parser("group", help="Audit Group Access")
    p_group.add_argument("action", choices=["list", "info"], help="Action to perform")
    p_group.add_argument("name", nargs="?", default="", help="Group name (required for info)")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    action = args.action
    name = getattr(args, 'name', '')

    if action == "info" and not name:
        print(f"❌ Error: 'name' is required for the 'info' action.", file=sys.stderr)
        sys.exit(1)

    # -------------------------------------------------------------------------
    # 1. POLICY
    # -------------------------------------------------------------------------
    if cmd == "policy":
        if action == "list":
            list_cluster_inventory(vault, "policies")
        elif action == "info":
            print(f"\n🔎 AUDITING VAULT ACCESS PATH FOR POLICY: '{name}'\n" + "="*70)
            audit_policy(vault, name)

    # -------------------------------------------------------------------------
    # 2. ROLE
    # -------------------------------------------------------------------------
    elif cmd == "role":
        if action == "list":
            list_cluster_inventory(vault, "roles")
        elif action == "info":
            audit_role(vault, name)

    # -------------------------------------------------------------------------
    # 3. ENTITY
    # -------------------------------------------------------------------------
    elif cmd == "entity":
        if action == "list":
            client = vault._get_client()
            try:
                res = client.list("identity/entity/name")
                keys = res.get('data', {}).get('keys', []) if res else []
                if keys:
                    print("👤 Existing Identity Entities:")
                    for k in keys: print(f"  ├─ {k}")
                else:
                    print("ℹ️ No entities found.")
            except Exception as e:
                print(f"❌ Error fetching entities: {e}", file=sys.stderr)
                
        elif action == "info":
            audit_identity(vault, name, is_group=False)

    # -------------------------------------------------------------------------
    # 4. GROUP
    # -------------------------------------------------------------------------
    elif cmd == "group":
        if action == "list":
            client = vault._get_client()
            try:
                res = client.list("identity/group/name")
                keys = res.get('data', {}).get('keys', []) if res else []
                if keys:
                    print("🏢 Existing Identity Groups:")
                    for k in keys: print(f"  ├─ {k}")
                else:
                    print("ℹ️ No groups found.")
            except Exception as e:
                print(f"❌ Error fetching groups: {e}", file=sys.stderr)
                
        elif action == "info":
            audit_identity(vault, name, is_group=True)

if __name__ == "__main__":
    main()
