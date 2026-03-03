# -----------------------------------------------------------------------------
# File    : ctlabs-tools/vault/vault_k8s.py
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


def get_args():
    parser = argparse.ArgumentParser(description="Vault Kubernetes Secrets Engine Manager")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. EXEC (JIT Execution)
    p_exec = subparsers.add_parser("exec", help="Run a kubectl command with JIT credentials")
    p_exec.add_argument("cluster", help="The K8s cluster identifier (e.g., prod-cluster)")
    p_exec.add_argument("role", help="The Vault K8s Secret Role to assume")
    p_exec.add_argument("namespace", help="The K8s namespace to inject the token into")
    p_exec.add_argument("--server", help="Override the K8s API server URL (e.g., for NAT/Port-forwarding)") # 🧠 NEW FLAG
    p_exec.add_argument("exec_cmd", nargs='*', help="The command to execute (prefix with '--')")

    # 2. ENGINE (Bootstrap)
    p_engine = subparsers.add_parser("engine", help="Manage K8s Secrets Engines")
    # 🌟 Added read, info, and update to the choices
    p_engine.add_argument("action", choices=["create", "delete", "list", "read", "info", "update"], help="Action to perform")
    p_engine.add_argument("cluster", nargs="?", default="", help="Cluster identifier (mounts at k8s/<cluster>)")
    p_engine.add_argument("--sa-name", default="vault-k8s-master", help="Master Service Account name")
    
    # 🌟 Added flags for the update command
    p_engine.add_argument("--host", help="Update K8s API Host")
    p_engine.add_argument("--jwt", help="Update SA JWT Token")

    # 3. ROLE (Access Profiles)
    p_role = subparsers.add_parser("role", help="Manage K8s Secrets Roles")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list"], help="Action to perform")
    p_role.add_argument("cluster", nargs="?", default="", help="Cluster identifier")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--namespaces", default=None, help="Comma-separated allowed namespaces (Overrides YAML if provided)")
    p_role.add_argument("--rules", help="Path to a JSON or YAML file containing K8s RBAC rules to dynamically generate")

    # 4. INFO (Introspection)
    p_info = subparsers.add_parser("info", help="Introspect the active JIT Kubernetes token in your current shell")

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

        # 1. Fetch the Token
        print(f"🔍 Inspecting admin role '{args.role}'...", file=sys.stderr)
        role_config = vault.read_k8s_secret_role(args.role, mount_point)
        
        if not role_config:
            print(f"❌ Error: Vault role '{args.role}' does not exist.", file=sys.stderr)
            sys.exit(1)

        # 🧠 SMART UX: The tool enforces the Admin's design automatically!
        is_cluster_role = (role_config.get("kubernetes_role_type") == "ClusterRole")
        allows_all_ns = ("*" in role_config.get("allowed_kubernetes_namespaces", []))
        
        # Vault ONLY allows ClusterRoleBindings if the admin authorized '*' namespaces
        auto_cluster_wide = is_cluster_role and allows_all_ns

        print(f"🔒 Fetching secure K8s token for role '{args.role}' in namespace '{args.namespace}'...", file=sys.stderr)
        token = vault.get_k8s_secret_token(
            role_name=args.role, 
            k8s_namespace=args.namespace, 
            mount_point=mount_point,
            cluster_wide=auto_cluster_wide  # Automatically set based on the Vault Role!
        )
        if not token: sys.exit(1)

        # 2. 🧠 SMART OVERRIDE: Check CLI -> Check Env -> Check Cache -> Check Vault
        kube_host = None
        env_var_name = f"VAULT_K8S_SERVER_{args.cluster.upper().replace('-', '_')}"
        
        if args.server:
            # 1. CLI Flag provided (Format it and save it for next time!)
            kube_host = args.server
            if not kube_host.startswith("http"):
                kube_host = f"https://{kube_host}"
                
            print(f"💾 Caching server override for future use: {kube_host}", file=sys.stderr)
            save_cached_server(args.cluster, kube_host)
            
        else:
            # 2. Try Environment Variable (e.g., VAULT_K8S_SERVER_PROD_CLUSTER)
            kube_host = os.environ.get(env_var_name)
            if kube_host:
                print(f"🌐 Using server from environment variable ({env_var_name}): {kube_host}", file=sys.stderr)
                
            # 3. Try Local Cache
            if not kube_host:
                kube_host = get_cached_server(args.cluster)
                if kube_host:
                    print(f"🌐 Using cached server override: {kube_host}", file=sys.stderr)

            # 4. Fallback to Vault's internal config
            if not kube_host:
                kube_host = vault.get_k8s_engine_host(mount_point=mount_point)
                
        if not kube_host:
            print(f"❌ Error: Could not determine K8s API host from Vault engine '{mount_point}'.", file=sys.stderr)
            sys.exit(1)

        # 3. Inject into kubectl
        if command_list[0] == "kubectl":
            command_list.insert(1, f"--server={kube_host}")
            command_list.insert(2, f"--token={token}")
            command_list.insert(3, f"--namespace={args.namespace}")
            command_list.insert(4, "--insecure-skip-tls-verify=true")
        else:
            os.environ["K8S_AUTH_TOKEN"] = token
            os.environ["KUBERNETES_MASTER"] = kube_host
            os.environ["KUBERNETES_NAMESPACE"] = args.namespace

        # 🧠 SECURITY: Redact the token from the console output to prevent credential leakage
        display_cmd = []
        for arg in command_list:
            if arg.startswith("--token="):
                display_cmd.append("--token=***REDACTED***")
            else:
                display_cmd.append(arg)
                
        print(f"🚀 Executing: {' '.join(display_cmd)}\n" + "-"*40, file=sys.stderr)
        
        # 🧠 SMART BASH INJECTION: Auto-configure the 'kc' alias if the user requests a bash shell
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
                os.remove(rc_path) # Clean up the temp file when they exit
                sys.exit(exit_code)
            except Exception as e:
                print(f"❌ Error starting shell: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Execute normal non-bash commands silently
            try:
                sys.exit(subprocess.run(command_list, env=os.environ).returncode)
            except FileNotFoundError:
                print(f"\n❌ Error: Command not found: {command_list[0]}", file=sys.stderr)
                sys.exit(1)

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
                for e in engines: print(f"  ├─ {e}")
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

            # 🌉 NEW: Auto-Detect and Consume GKE Bridge Credentials
            kube_dir = os.path.expanduser("~/.kube")
            temp_kube_file = os.path.join(kube_dir, f"config-gke-{cluster}")
            used_temp_kubeconfig = False
            
            if os.path.exists(temp_kube_file):
                print(f"🌉 Detected temporary GKE kubeconfig! Routing kubectl through the bridge...", file=sys.stderr)
                # Inject it into the local script environment. 
                # This safely scopes it ONLY to the subprocesses run by this script!
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
            time.sleep(2) # Allow K8s controller time to populate token
            
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

            # 🧹 NEW: Burn the bridge after successful setup
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
            vault.teardown_k8s_secrets_engine(mount_point=mount_point)
            print(f"  ├─ Cleaning up K8s resources...")
            run_kubectl(["kubectl", "delete", "serviceaccount", sa_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
            run_kubectl(["kubectl", "delete", "clusterrolebinding", f"{sa_name}-admin-binding"], ignore_errors=True, quiet=True)
            run_kubectl(["kubectl", "delete", "secret", secret_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
            print("🎉 Engine destroyed!")

        elif action in ["read", "info"]:
            print(f"🔍 Reading K8s Engine Config for '{mount_point}/'...")
            config = vault.read_k8s_engine_config(mount_point=mount_point)
            if config:
                # Mask the JWT so it doesn't spill onto the screen by default
                if "service_account_jwt" in config and config["service_account_jwt"]:
                    config["service_account_jwt"] = "*** REDACTED ***"
                print(json.dumps(config, indent=2))
            else:
                print("❌ Config not found or engine not configured.")
                
        elif action == "update":
            print(f"⚙️ Updating K8s Engine Config for '{mount_point}/'...")
            if not args.host and not args.jwt:
                print("❌ Error: Provide --host or --jwt to update.")
                sys.exit(1)
                
            if vault.update_k8s_engine_config(mount_point, host=args.host, jwt=args.jwt):
                print("✅ Successfully updated K8s Engine Config!")

    # -------------------------------------------------------------------------
    # 3. ROLE MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        cluster = args.cluster
        role_name = args.role_name
        
        # 🌟 NEW: If action is list, do the smart loop!
        if action == "list":
            if cluster:
                engines_to_check = [f"k8s/{cluster}"]
            else:
                print("🔍 Searching across all active K8s engines...")
                engines = vault.list_engines(backend_type="kubernetes") or []
                engines_to_check = [e.strip('/') for e in engines]

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

        # 🧠 Enforce cluster name for all OTHER role actions (create, update, read, delete)
        if not cluster:
            print("❌ Error: Cluster identifier required (e.g., vault-k8s role read prod-cluster my-role).", file=sys.stderr)
            sys.exit(1)

        mount_point = f"k8s/{cluster}"
        
        # Enforce role_name for everything EXCEPT list
        if not role_name:
            print("❌ Error: Role name is required for this action.", file=sys.stderr)
            sys.exit(1)

        if action == "read":
            data = vault.read_k8s_secret_role(name=role_name, mount_point=mount_point)
            if data: print(json.dumps(data, indent=2))
            
        elif action == "delete":
            if vault.delete_k8s_secret_role(name=role_name, mount_point=mount_point):
                print(f"✅ Deleted K8s role '{role_name}'.")
            
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
                
            print(f"🚀 Creating K8s Role '{role_name}'...")
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
            # A JWT is three parts separated by dots: header.payload.signature
            # We only care about the payload (the middle part)
            payload_b64 = token.split('.')[1]
            
            # Python's base64 requires correct padding to decode properly
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            # Extract the native Kubernetes claims
            sa_data = payload.get("kubernetes.io", {}).get("serviceaccount", {})
            sa_name = sa_data.get("name", "Unknown")
            namespace = payload.get("kubernetes.io", {}).get("namespace", "Unknown")
            exp_time = payload.get("exp", 0)
            
            # Calculate time remaining
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