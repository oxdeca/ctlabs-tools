# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_k8s.py
# Purpose : Dedicated CLI for Kubernetes Secrets Engine (JIT K8s Access)
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import os
import subprocess
import time
import base64
from .core import HashiVault

def run_kubectl(cmd_list, capture=False, ignore_errors=False, quiet=False):
    """Silently runs a kubectl command."""
    try:
        res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        if capture: return res.stdout.strip()
        return True
    except FileNotFoundError:
        print(f"\n❌ Environment Error: 'kubectl' command not found.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if ignore_errors: return False
        if not quiet:
            print(f"\n❌ Kubectl Command Failed: {' '.join(cmd_list)}\nError output: {e.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

def get_cached_server(cluster_name):
    """Retrieves a locally cached K8s API server URL."""
    cache_file = os.path.expanduser("~/.ctlabs_vault/k8s_servers.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f).get(cluster_name)
        except Exception: pass
    return None

def save_cached_server(cluster_name, server_url):
    """Saves the K8s API server URL to local cache so the user doesn't have to type it again."""
    cache_file = os.path.expanduser("~/.ctlabs_vault/k8s_servers.json")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    try:
        data = {}
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                data = json.load(f)
        data[cluster_name] = server_url
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"⚠️ Could not cache server URL: {e}", file=sys.stderr)

def print_k8s_rules_table(rules_json_str):
    """Parses raw K8s JSON rules and prints a beautifully formatted ASCII table."""
    try:
        rules = json.loads(rules_json_str)
    except json.JSONDecodeError:
        print("  ├─ Rules       : ⚠️ Invalid JSON format in Vault")
        return
        
    if not rules:
        print("  ├─ Rules       : None")
        return
        
    print("  ├─ Rules       :")
    
    # 1. Extract the columns
    rows = []
    for r in rules:
        resources = ", ".join(r.get("resources", ["<none>"]))
        
        # Clean up API Groups (an empty string in K8s means the 'core' API group)
        api_groups_raw = r.get("apiGroups", ["<none>"])
        api_groups_clean = [g if g != "" else '"" (core)' for g in api_groups_raw]
        api_groups = ", ".join(api_groups_clean)
        
        verbs = ", ".join(r.get("verbs", ["<none>"]))
        rows.append([resources, api_groups, verbs])
        
    # 2. Calculate dynamic column widths
    w_res = max(len("Resources"), max((len(r[0]) for r in rows), default=0))
    w_api = max(len("API Groups"), max((len(r[1]) for r in rows), default=0))
    w_verbs = max(len("Verbs"), max((len(r[2]) for r in rows), default=0))
    
    table_width = w_res + w_api + w_verbs + 6 # Padding & separators
    
    GREEN = "\033[92m"
    RESET = "\033[0m"
    PREFIX = "  │  "
    
    # 3. Render the table inside the tree
    print(f"{PREFIX}{'=' * table_width}")
    print(f"{PREFIX}{'Resources'.ljust(w_res)} | {'API Groups'.ljust(w_api)} | {'Verbs'.ljust(w_verbs)}")
    print(f"{PREFIX}{'-' * table_width}")
    
    for row in rows:
        print(f"{PREFIX}{row[0].ljust(w_res)} | {row[1].ljust(w_api)} | {GREEN}{row[2].ljust(w_verbs)}{RESET}")
        
    print(f"{PREFIX}{'=' * table_width}")


def get_args():
    parser = argparse.ArgumentParser(description="Vault Kubernetes Secrets Engine Manager")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. EXEC (JIT Execution)
    p_exec = subparsers.add_parser("exec", help="Run a kubectl command with JIT credentials")
    p_exec.add_argument("cluster", help="The K8s cluster identifier (e.g., prod-cluster)")
    p_exec.add_argument("role", help="The Vault K8s Secret Role to assume")
    p_exec.add_argument("namespace", help="The K8s namespace to inject the token into")
    p_exec.add_argument("--server", help="Override the K8s API server URL (e.g., for NAT/Port-forwarding)")
    p_exec.add_argument("exec_cmd", nargs='*', help="The command to execute (prefix with '--')")

    # 2. ENGINE (Bootstrap)
    p_engine = subparsers.add_parser("engine", help="Manage K8s Secrets Engines")
    p_engine.add_argument("action", choices=["create", "delete", "list", "read", "info", "update"], help="Action to perform")
    p_engine.add_argument("cluster", nargs="?", default="", help="Cluster identifier (mounts at k8s/<cluster>)")
    p_engine.add_argument("--sa-name", default="vault-k8s-master", help="Master Service Account name")
    p_engine.add_argument("--host", help="Update K8s API Host")
    p_engine.add_argument("--jwt", help="Update SA JWT Token")

    # 3. ROLE (Access Profiles)
    p_role = subparsers.add_parser("role", help="Manage K8s Secrets Roles")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_role.add_argument("cluster", nargs="?", default="", help="Cluster identifier")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--namespaces", default=None, help="Comma-separated allowed namespaces (Overrides YAML if provided)")
    p_role.add_argument("--rules", help="Path to a JSON or YAML file containing K8s RBAC rules to dynamically generate")

    # 4. INFO (Introspection)
    p_info = subparsers.add_parser("info", help="Introspect the active JIT Kubernetes token in your current shell")

    # 5. LEASES (Management)
    p_leases = subparsers.add_parser("leases", help="Manage dynamic Kubernetes leases/tokens")
    leases_subs = p_leases.add_subparsers(dest="action", required=True)
    p_leases_list = leases_subs.add_parser("list", help="List active leases (provide a cluster name, or leave blank for all)")
    p_leases_list.add_argument("cluster", nargs="?", help="The cluster name (optional)")
    p_leases_revoke = leases_subs.add_parser("revoke", help="Revoke leases")
    p_leases_revoke.add_argument("cluster", help="The cluster name")
    p_leases_revoke.add_argument("--id", help="Revoke a specific lease ID")
    p_leases_revoke.add_argument("--force", action="store_true", help="Force revoke ALL leases for this cluster")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # 1. EXEC (JIT Wrapper)
    # -------------------------------------------------------------------------
    if cmd == "exec":
        mount_point = f"k8s/{args.cluster}"
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        print(f"🔍 Inspecting admin role '{args.role}'...", file=sys.stderr)
        role_config = vault.read_k8s_secret_role(args.role, mount_point)
        
        if not role_config:
            print(f"❌ Error: Vault role '{args.role}' does not exist in '{mount_point}/'.", file=sys.stderr)
            sys.exit(1)

        is_cluster_role = (role_config.get("kubernetes_role_type") == "ClusterRole")
        allows_all_ns = ("*" in role_config.get("allowed_kubernetes_namespaces", []))
        auto_cluster_wide = is_cluster_role and allows_all_ns

        print(f"🔒 Fetching secure K8s token for role '{args.role}' in namespace '{args.namespace}'...", file=sys.stderr)
        token = vault.get_k8s_secret_token(
            role_name=args.role, 
            k8s_namespace=args.namespace, 
            mount_point=mount_point,
            cluster_wide=auto_cluster_wide 
        )
        if not token: sys.exit(1)

        kube_host = None
        env_var_name = f"VAULT_K8S_SERVER_{args.cluster.upper().replace('-', '_')}"
        
        if args.server:
            kube_host = args.server
            if not kube_host.startswith("http"):
                kube_host = f"https://{kube_host}"
            print(f"💾 Caching server override for future use: {kube_host}", file=sys.stderr)
            save_cached_server(args.cluster, kube_host)
        else:
            kube_host = os.environ.get(env_var_name)
            if kube_host:
                print(f"🌐 Using server from environment variable ({env_var_name}): {kube_host}", file=sys.stderr)
            if not kube_host:
                kube_host = get_cached_server(args.cluster)
                if kube_host:
                    print(f"🌐 Using cached server override: {kube_host}", file=sys.stderr)
            if not kube_host:
                kube_host = vault.get_k8s_engine_host(mount_point=mount_point)
                
        if not kube_host:
            print(f"❌ Error: Could not determine K8s API host from Vault engine '{mount_point}'.", file=sys.stderr)
            sys.exit(1)

        if command_list[0] == "kubectl":
            command_list.insert(1, f"--server={kube_host}")
            command_list.insert(2, f"--token={token}")
            command_list.insert(3, f"--namespace={args.namespace}")
            command_list.insert(4, "--insecure-skip-tls-verify=true")
        else:
            os.environ["K8S_AUTH_TOKEN"] = token
            os.environ["KUBERNETES_MASTER"] = kube_host
            os.environ["KUBERNETES_NAMESPACE"] = args.namespace

        display_cmd = []
        for arg in command_list:
            if arg.startswith("--token="):
                display_cmd.append("--token=***REDACTED***")
            else:
                display_cmd.append(arg)
                
        print(f"🚀 Executing: {' '.join(display_cmd)}\n" + "-"*40, file=sys.stderr)
        
        if command_list == ["bash"]:
            import tempfile
            rc_content = f"""
if [ -f ~/.bashrc ]; then source ~/.bashrc; fi
export PS1="\\[\\e[32m\\][JIT: {args.namespace}]\\[\\e[m\\] \\w \\$ "
alias kc='kubectl --server="{kube_host}" --token="{token}" --namespace="{args.namespace}" --insecure-skip-tls-verify=true'
echo "🔒 Vault JIT Kubernetes Session Active!"
echo "👉 Use the 'kc' command instead of kubectl (e.g., kc get pods)"
echo "⏳ Type 'vault-k8s info' to check token TTL, or 'exit' to close."
"""
            fd, rc_path = tempfile.mkstemp(suffix=".bashrc")
            with os.fdopen(fd, 'w') as f:
                f.write(rc_content)
                
            command_list = ["bash", "--rcfile", rc_path]
            
            try:
                exit_code = subprocess.run(command_list, env=os.environ).returncode
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

    # ---------------------------------------------------------------------
    # LEASES
    # ---------------------------------------------------------------------
    elif cmd == "leases":
        action = args.action

        if action == "list":
            if args.cluster:
                mounts = [f"k8s/{args.cluster}"]
                print(f"🔍 Searching for active leases in '{mounts[0]}/'...")
            else:
                print("🔍 Searching for active leases across ALL K8s engines...")
                raw_engines = vault.list_engines(backend_type="kubernetes")
                mounts = [m.rstrip('/') for m in (raw_engines or []) if m.startswith("k8s/")]
                
            if not mounts:
                print("✅ No Kubernetes engines found.")
            else:
                found_any = False
                for mount in mounts:
                    roles = vault.list_leases(f"{mount}/creds/")
                    if roles:
                        print(f"\n📁 Engine: {mount}/")
                        for role in roles:
                            lease_ids = vault.list_leases(f"{mount}/creds/{role}")
                            for lid in lease_ids:
                                full_lease_id = f"{mount}/creds/{role}{lid}"
                                print(f"  ├─ {full_lease_id}")
                                found_any = True
                                
                if not found_any:
                    print("✅ No active K8s leases found.")
                        
        elif action == "revoke":
            mount_point = f"k8s/{args.cluster}"
            
            if getattr(args, "id", None):
                print(f"🗑️ Revoking specific lease '{args.id}'...")
                if vault.revoke_lease(args.id):
                    print("✅ Lease successfully revoked.")
            elif getattr(args, "force", False):
                print(f"🔥 Force revoking ALL leases under '{mount_point}'...")
                if vault.force_revoke_prefix(mount_point):
                    print("✅ All cluster leases forcefully wiped.")
            else:
                print("⚠️ You must provide either a specific '--id <lease_id>' or use '--force' to wipe the cluster.")

    # -------------------------------------------------------------------------
    # 2. ENGINE MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action
        cluster = args.cluster
        
        if action == "list":
            engines = vault.list_engines(backend_type="kubernetes")
            if engines:
                print("🌐 Active K8s Secrets Engines:")
                for e in engines: 
                    if e.startswith("k8s/"): print(f"  ├─ {e}")
            else:
                print("ℹ️ No K8s Secrets Engines mounted.")
            sys.exit(0)

        if not cluster:
            print("❌ Error: Cluster identifier required.", file=sys.stderr)
            sys.exit(1)

        mount_point = f"k8s/{cluster}"
        sa_namespace = "kube-system"
        sa_name = args.sa_name
        secret_name = f"{sa_name}-token"

        if action == "create":
            print(f"🚀 Initializing Zero-Touch K8s Engine at '{mount_point}/'...")
            kube_dir = os.path.expanduser("~/.kube")
            temp_kube_file = os.path.join(kube_dir, f"config-gke-{cluster}")
            used_temp_kubeconfig = False
            
            if os.path.exists(temp_kube_file):
                print(f"🌉 Detected temporary GKE kubeconfig! Routing kubectl through the bridge...", file=sys.stderr)
                os.environ["KUBECONFIG"] = temp_kube_file
                used_temp_kubeconfig = True

            print(f"  ├─ Creating K8s Service Account '{sa_name}'...")
            run_kubectl(["kubectl", "create", "serviceaccount", sa_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
            print(f"  ├─ Binding to cluster-admin...")
            run_kubectl(["kubectl", "create", "clusterrolebinding", f"{sa_name}-admin-binding", "--clusterrole=cluster-admin", f"--serviceaccount={sa_namespace}:{sa_name}"], ignore_errors=True, quiet=True)
            
            print(f"  ├─ Generating long-lived Secret for Vault...")
            secret_yaml = f"""
apiVersion: v1
kind: Secret
metadata:
  name: {secret_name}
  namespace: {sa_namespace}
  annotations:
    kubernetes.io/service-account.name: {sa_name}
type: kubernetes.io/service-account-token
"""
            try:
                subprocess.run(["kubectl", "apply", "-f", "-"], input=secret_yaml, text=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                print(f"\n❌ Kubectl Error: Could not apply Secret. Are you connected to the cluster?\n{e.stderr.strip()}", file=sys.stderr)
                sys.exit(1)
            
            print(f"  ├─ Fetching Cluster Credentials...")
            time.sleep(2)
            
            b64_token = run_kubectl(["kubectl", "get", "secret", secret_name, "-n", sa_namespace, "-o", "jsonpath={.data.token}"], capture=True)
            b64_ca = run_kubectl(["kubectl", "get", "secret", secret_name, "-n", sa_namespace, "-o", "jsonpath={.data.ca\.crt}"], capture=True)
            kube_host = run_kubectl(["kubectl", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"], capture=True)
            
            if not b64_token or not kube_host:
                print("❌ Failed to retrieve cluster credentials.", file=sys.stderr)
                sys.exit(1)
                
            jwt_token = base64.b64decode(b64_token).decode('utf-8')
            try:
                ca_pem = base64.b64decode(b64_ca).decode('utf-8')
            except Exception as e:
                print(f"❌ Error decoding CA certificate: {e}", file=sys.stderr)
                sys.exit(1)
            
            print(f"  ├─ Configuring Vault Engine...")
            if vault.setup_k8s_secrets_engine(mount_point=mount_point, host=kube_host, ca_cert=ca_pem, jwt=jwt_token):
                print(f"🎉 Kubernetes Secrets Engine ready at '{mount_point}/'!")

            if used_temp_kubeconfig:
                print(f"🔥 Burning the bridge: Destroying temporary kubeconfig...")
                try:
                    os.remove(temp_kube_file)
                    print(f"✅ Temporary credentials for '{cluster}' securely deleted from disk.")
                except OSError as e:
                    print(f"⚠️ Could not delete temporary kubeconfig: {e}", file=sys.stderr)
                    
            print(f"🎉 Kubernetes Engine '{mount_point}/' is fully operational!")
            
        elif action == "delete":
            print(f"🧹 Tearing down engine at '{mount_point}/'...")
            if vault.teardown_k8s_secrets_engine(mount_point=mount_point):
                print(f"  ├─ Cleaning up K8s resources...")
                run_kubectl(["kubectl", "delete", "serviceaccount", sa_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
                run_kubectl(["kubectl", "delete", "clusterrolebinding", f"{sa_name}-admin-binding"], ignore_errors=True, quiet=True)
                run_kubectl(["kubectl", "delete", "secret", secret_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
                print("🎉 Engine destroyed!")
            else:
                print("❌ Engine teardown aborted due to errors.")

        elif action == "read":
            config = vault.read_k8s_engine_config(mount_point=mount_point)
            if config:
                if "service_account_jwt" in config and config["service_account_jwt"]:
                    config["service_account_jwt"] = "*** REDACTED ***"
                print(json.dumps(config, indent=2))
            else:
                print(f"❌ Config not found at '{mount_point}/'.")
                
        elif action == "info":
            config = vault.read_k8s_engine_config(mount_point=mount_point)
            if config:
                print(f"🏛️  K8s Engine: {mount_point}/")
                print(f"  ├─ API Host    : {config.get('kubernetes_host', 'Unknown')}")
                has_ca = bool(config.get('kubernetes_ca_cert'))
                print(f"  ├─ CA Cert     : {'Configured ✅' if has_ca else 'Missing ⚠️'}")
                has_jwt = bool(config.get('service_account_jwt'))
                print(f"  ├─ Master JWT  : {'Configured ✅ (*** REDACTED ***)' if has_jwt else 'Missing ⚠️'}")
            else:
                print(f"❌ Config not found at '{mount_point}/'.")
                
        elif action == "update":
            print(f"⚙️ Updating K8s Engine Config for '{mount_point}/'...")
            jwt_token = args.jwt
            kube_host = args.host

            if not jwt_token and not kube_host:
                print(f"🔄 Auto-fetching fresh credentials from current kubectl context...")
                b64_token = run_kubectl(["kubectl", "get", "secret", secret_name, "-n", sa_namespace, "-o", "jsonpath={.data.token}"], capture=True, ignore_errors=True)
                if not b64_token:
                    print(f"❌ Failed to retrieve token. Does the '{sa_name}' service account still exist in the cluster?", file=sys.stderr)
                    sys.exit(1)
                jwt_token = base64.b64decode(b64_token).decode('utf-8')
                print("✅ Successfully extracted fresh JWT from the cluster.")

            if vault.update_k8s_engine_config(mount_point, host=kube_host, jwt=jwt_token):
                print("🎉 Successfully updated K8s Engine Config in Vault!")

    # -------------------------------------------------------------------------
    # 3. ROLE MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        cluster = args.cluster
        role_name = args.role_name
        
        if action == "list":
            if cluster:
                engines_to_check = [f"k8s/{cluster}"]
            else:
                print("🔍 Searching across all active K8s engines...")
                engines = vault.list_engines(backend_type="kubernetes") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("k8s/")]

            if not engines_to_check:
                print("ℹ️ No Kubernetes secrets engines currently mounted.")
                sys.exit(0)

            found_any = False
            for mount in engines_to_check:
                roles = vault.list_k8s_secret_roles(mount_point=mount)
                if roles:
                    found_any = True
                    print(f"\n👥 Active Roles at '{mount}/':")
                    for r in roles: 
                        print(f"  ├─ {r}")
                        
            if not found_any:
                print("\nℹ️ No roles found.")
            sys.exit(0)

        if not cluster:
            print("❌ Error: Cluster identifier required (e.g., vault-k8s role read prod-cluster my-role).", file=sys.stderr)
            sys.exit(1)

        mount_point = f"k8s/{cluster}"
        
        if not role_name:
            print("❌ Error: Role name is required for this action.", file=sys.stderr)
            sys.exit(1)

        if action == "read":
            data = vault.read_k8s_secret_role(name=role_name, mount_point=mount_point)
            if data: print(json.dumps(data, indent=2))
            else: print(f"❌ Role '{role_name}' not found.")
            
        elif action == "info":
            data = vault.read_k8s_secret_role(name=role_name, mount_point=mount_point)
            if data:
                print(f"👥 K8s Role: {role_name}")
                print(f"  ├─ Engine      : {mount_point}/")
                print(f"  ├─ Type        : {data.get('kubernetes_role_type', 'Unknown')}")
                ns = data.get('allowed_kubernetes_namespaces', [])
                print(f"  ├─ Namespaces  : {', '.join(ns) if ns else 'None'}")
                print(f"  ├─ SA Name     : {data.get('service_account_name', 'Dynamic')}")
                print(f"  ├─ Default TTL : {data.get('default_ttl', 'System Default')}s")
                print(f"  ├─ Max TTL     : {data.get('max_ttl', 'System Default')}s")
                
                # 🌟 Render the new RBAC Rules Table!
                rules_str = data.get("generated_role_rules")
                if rules_str:
                    print_k8s_rules_table(rules_str)
                else:
                    print("  ├─ Rules       : None (Uses pre-existing ServiceAccount/Role)")
            else:
                print(f"❌ Role '{role_name}' not found.")
            
        elif action == "delete":
            if vault.delete_k8s_secret_role(name=role_name, mount_point=mount_point):
                print(f"✅ Deleted K8s role '{role_name}' from '{mount_point}/'.")
            
        elif action in ["create", "update"]:
            if not args.rules:
                print("❌ Error: --rules <path_to_json_or_yaml> is required.", file=sys.stderr)
                sys.exit(1)
                
            try:
                with open(args.rules, 'r') as f:
                    rules_payload = f.read()
                    
                if args.rules.endswith(('.yaml', '.yml')):
                    try:
                        import yaml
                        yaml.safe_load(rules_payload)
                    except ImportError:
                        pass
                    except Exception as e:
                        print(f"❌ Invalid YAML syntax in {args.rules}:\n{e}", file=sys.stderr)
                        sys.exit(1)
                elif args.rules.endswith('.json'):
                    try:
                        json.loads(rules_payload)
                    except Exception as e:
                        print(f"❌ Invalid JSON syntax in {args.rules}:\n{e}", file=sys.stderr)
                        sys.exit(1)
                        
            except Exception as e:
                print(f"❌ Error reading rules file: {e}", file=sys.stderr)
                sys.exit(1)
                
            print(f"🚀 Creating K8s Role '{role_name}' in '{mount_point}/'...")
            if vault.create_k8s_secret_role(name=role_name, mount_point=mount_point, allowed_namespaces=args.namespaces, rules_payload=rules_payload):
                print(f"✅ K8s Secret Role '{role_name}' successfully created/updated.")

    # -------------------------------------------------------------------------
    # 4. INFO (Introspection)
    # -------------------------------------------------------------------------
    elif cmd == "info":
        token = os.environ.get("K8S_AUTH_TOKEN")
        master = os.environ.get("KUBERNETES_MASTER", "Unknown")
        
        if not token:
            print("❌ No active JIT session found. Run 'vault-k8s exec ... -- bash' to start one.", file=sys.stderr)
            sys.exit(1)
            
        try:
            payload_b64 = token.split('.')[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            sa_data = payload.get("kubernetes.io", {}).get("serviceaccount", {})
            sa_name = sa_data.get("name", "Unknown")
            namespace = payload.get("kubernetes.io", {}).get("namespace", "Unknown")
            exp_time = payload.get("exp", 0)
            
            now = int(time.time())
            time_remaining = exp_time - now
            
            if time_remaining > 0:
                mins = time_remaining // 60
                time_str = f"{mins} minutes ({time_remaining}s)"
            else:
                time_str = "EXPIRED ⚠️"
                
            print("🔍 Introspecting K8s Token...")
            print(f"👤 Authenticated as : {sa_name}")
            print(f"📂 Namespace        : {namespace}")
            print(f"🌐 Cluster API      : {master}")
            print(f"⏳ Time Remaining   : {time_str}")
            
        except Exception as e:
            print(f"❌ Error reading token format: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
