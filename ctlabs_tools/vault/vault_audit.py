# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_audit.py
# Purpose : Dedicated CLI for Auditing & Graphing Vault Access Paths
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import re
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

    print(f"\n📜 1. VAULT ACL POLICY: {name}")

    if not paths:
        print("  ⚠️ No parsable paths/capabilities found.")
        return paths

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
        
    print("=" * table_width + "\n")
    return paths

def scan_engine_roles(vault, paths):
    """Analyzes the policy paths and fetches the downstream Engine Roles."""
    print("⚙️  2. DOWNSTREAM ENGINE ROLES (External Bindings)")
    client = vault._get_client()
    found_any = False

    for path in paths.keys():
        # 1. Check for GCP Roleset
        gcp_match = re.match(r'^gcp/([^/]+)/(?:token|key)/([^/*]+)', path)
        if gcp_match:
            project, role = gcp_match.groups()
            try:
                data = client.read(f"gcp/{project}/roleset/{role}")
                if data and 'data' in data:
                    d = data['data']
                    found_any = True
                    print(f"  ☁️  GCP Roleset: {role} (Project: {project})")
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
                    print("")
            except Exception: pass

        # 2. Check for K8s Roles
        k8s_match = re.match(r'^k8s/([^/]+)/creds/([^/*]+)', path)
        if k8s_match:
            cluster, role = k8s_match.groups()
            try:
                data = client.read(f"k8s/{cluster}/roles/{role}")
                if data and 'data' in data:
                    d = data['data']
                    found_any = True
                    print(f"  ⚓ K8s Role: {role} (Cluster: {cluster})")
                    print(f"      ├─ Type       : {d.get('kubernetes_role_type', 'Unknown')}")
                    ns = d.get('allowed_kubernetes_namespaces', [])
                    print(f"      ├─ Namespaces : {', '.join(ns) if ns else 'None'}")
                    print(f"      ├─ SA Name    : {d.get('service_account_name', 'Dynamic')}")
                    print("")
            except Exception: pass
            
        # 3. Check for PKI Roles
        pki_match = re.match(r'^pki/([^/]+)/issue/([^/*]+)', path)
        if pki_match:
            ca_name, role = pki_match.groups()
            try:
                data = client.read(f"pki/{ca_name}/roles/{role}")
                if data and 'data' in data:
                    d = data['data']
                    found_any = True
                    print(f"  🏛️  PKI Role: {role} (CA: {ca_name})")
                    print(f"      ├─ Allowed Domains : {', '.join(d.get('allowed_domains', []))}")
                    print(f"      ├─ Max TTL         : {d.get('max_ttl', 'System Default')}s")
                    print("")
            except Exception: pass

    if not found_any:
        print("  ℹ️  No specific external secrets engine roles detected in this policy.\n")

def scan_upstream_identities(vault, policy_name):
    """Scans the Identity engine and AppRoles to find who has this policy attached."""
    print("👥 3. UPSTREAM IDENTITIES (Who has this policy?)")
    client = vault._get_client()
    found_any = False
    
    # 1. Scan Identity Groups
    try:
        res = client.list("identity/group/id")
        group_ids = res.get('data', {}).get('keys', []) if res else []
        for gid in group_ids:
            g_data = client.read(f"identity/group/id/{gid}")
            if g_data and 'data' in g_data:
                policies = g_data['data'].get('policies', [])
                if policy_name in policies:
                    found_any = True
                    name = g_data['data'].get('name', gid)
                    print(f"  🏢 Identity Group : {name}")
    except Exception: pass

    # 2. Scan Identity Entities (Users)
    try:
        res = client.list("identity/entity/id")
        entity_ids = res.get('data', {}).get('keys', []) if res else []
        for eid in entity_ids:
            e_data = client.read(f"identity/entity/id/{eid}")
            if e_data and 'data' in e_data:
                policies = e_data['data'].get('policies', [])
                if policy_name in policies:
                    found_any = True
                    name = e_data['data'].get('name', eid)
                    print(f"  👤 Identity Entity: {name}")
    except Exception: pass
    
    # 3. Scan AppRoles (Machine Auth)
    try:
        res = client.list("auth/approle/role")
        approles = res.get('data', {}).get('keys', []) if res else []
        for role in approles:
            ar_data = client.read(f"auth/approle/role/{role}")
            if ar_data and 'data' in ar_data:
                policies = ar_data['data'].get('token_policies', [])
                if policy_name in policies:
                    found_any = True
                    print(f"  🤖 AppRole Mount  : {role}")
    except Exception as e: 
        if "404" not in str(e): pass # Approle might not be mounted

    if not found_any:
        print("  ℹ️  No Groups, Entities, or AppRoles currently have this policy attached.")
    print("")

def get_args():
    parser = argparse.ArgumentParser(description="Vault Access Path Auditor")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_policy = subparsers.add_parser("policy", help="Audit an ACL Policy end-to-end")
    p_policy.add_argument("name", help="The name of the Vault ACL policy to audit")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    if args.command == "policy":
        policy_name = args.name
        
        # Step 1: Fetch Policy
        client = vault._get_client()
        try:
            res = client.read(f"sys/policy/{policy_name}")
            if not res or 'data' not in res or 'rules' not in res['data']:
                print(f"❌ Policy '{policy_name}' not found.", file=sys.stderr)
                sys.exit(1)
                
            rules_hcl = res['data']['rules']
        except Exception as e:
            print(f"❌ Error fetching policy: {e}", file=sys.stderr)
            sys.exit(1)
            
        print(f"\n🔎 AUDITING VAULT ACCESS PATH FOR: '{policy_name}'")
        print("=" * 80)
        
        # Step 2: Render Policy & Extract Paths
        parsed_paths = print_policy_table(policy_name, rules_hcl)
        
        # Step 3: Scan Downstream (Engines)
        if parsed_paths:
            scan_engine_roles(vault, parsed_paths)
            
        # Step 4: Scan Upstream (Identities)
        print("⏳ Scanning Identity Engine (this may take a few seconds)...")
        # Overwrite the console line to make it look clean
        sys.stdout.write("\033[F\033[K")
        scan_upstream_identities(vault, policy_name)
        
if __name__ == "__main__":
    main()
