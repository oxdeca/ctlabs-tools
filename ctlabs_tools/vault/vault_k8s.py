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
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, help="The command to execute (prefix with '--')")

    # 2. ENGINE (Bootstrap)
    p_engine = subparsers.add_parser("engine", help="Manage K8s Secrets Engines")
    p_engine.add_argument("action", choices=["create", "delete", "list"], help="Action to perform")
    p_engine.add_argument("cluster", nargs="?", default="", help="Cluster identifier (mounts at k8s/<cluster>)")
    p_engine.add_argument("--sa-name", default="vault-k8s-master", help="Master Service Account name")

    # 3. ROLE (Access Profiles)
    p_role = subparsers.add_parser("role", help="Manage K8s Secrets Roles")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list"], help="Action to perform")
    p_role.add_argument("cluster", nargs="?", default="", help="Cluster identifier")
    p_role.add_argument("role_name", nargs="?", default="", help="Name of the role")
    p_role.add_argument("--namespaces", default="*", help="Comma-separated allowed namespaces")
    p_role.add_argument("--rules", help="Path to a JSON or YAML file containing K8s RBAC rules to dynamically generate")

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
        print(f"🔒 Fetching secure K8s token for role '{args.role}' in namespace '{args.namespace}'...", file=sys.stderr)
        token = vault.get_k8s_secret_token(role_name=args.role, k8s_namespace=args.namespace, mount_point=mount_point)
        if not token: sys.exit(1)

        # 2. 🧠 SMART OVERRIDE: Use user-provided server, or fallback to Vault's config
        if args.server:
            kube_host = args.server
            print(f"🌐 Using overridden API server: {kube_host}", file=sys.stderr)
        else:
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

        # 🧠 SECURITY: Redact the token from the console output to prevent credential leakage
        display_cmd = []
        for arg in command_list:
            if arg.startswith("--token="):
                display_cmd.append("--token=***REDACTED***")
            else:
                display_cmd.append(arg)
                
        print(f"🚀 Executing: {' '.join(display_cmd)}\n" + "-"*40, file=sys.stderr)
        
        # Execute the REAL command (with the real token) silently
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

            # 🧠 FIX: Decode the CA certificate from Base64 to PEM
            try:
                ca_pem = base64.b64decode(b64_ca).decode('utf-8')
            except Exception as e:
                print(f"❌ Error decoding CA certificate: {e}", file=sys.stderr)
                sys.exit(1)
            
            print(f"  ├─ Configuring Vault Engine...")
            # Use the decoded 'ca_pem' instead of 'b64_ca'
            if vault.setup_k8s_secrets_engine(mount_point=mount_point, host=kube_host, ca_cert=ca_pem, jwt=jwt_token):
                print(f"🎉 Kubernetes Secrets Engine ready at '{mount_point}/'!")
            
        elif action == "delete":
            print(f"🧹 Tearing down engine at '{mount_point}/'...")
            vault.teardown_k8s_secrets_engine(mount_point=mount_point)
            print(f"  ├─ Cleaning up K8s resources...")
            run_kubectl(["kubectl", "delete", "serviceaccount", sa_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
            run_kubectl(["kubectl", "delete", "clusterrolebinding", f"{sa_name}-admin-binding"], ignore_errors=True, quiet=True)
            run_kubectl(["kubectl", "delete", "secret", secret_name, "-n", sa_namespace], ignore_errors=True, quiet=True)
            print("🎉 Engine destroyed!")

    # -------------------------------------------------------------------------
    # 3. ROLE MANAGEMENT
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        cluster = args.cluster
        role_name = args.role_name
        mount_point = f"k8s/{cluster}" if cluster else "k8s"

        if action == "list":
            keys = vault.list_k8s_secret_roles(mount_point=mount_point)
            if keys:
                print(f"👥 Active Roles at '{mount_point}/':")
                for k in keys: print(f"  ├─ {k}")
            else:
                print(f"ℹ️ No roles found.")
            sys.exit(0)

        if not cluster or not role_name:
            print("❌ Error: Cluster identifier and role_name are required.", file=sys.stderr)
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
                    
                # 🧠 SMART VALIDATION: Check syntax before sending to Vault
                if args.rules.endswith(('.yaml', '.yml')):
                    try:
                        import yaml # Requires 'pyyaml' to be installed
                        yaml.safe_load(rules_payload)
                    except ImportError:
                        pass # Silently skip validation if PyYAML isn't installed
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


if __name__ == "__main__":
    main()