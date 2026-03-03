# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_gcp.py
# Purpose : Dedicated CLI for GCP Dynamic Secrets & Identity Management
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import os
import subprocess
import time
from .core import HashiVault

def run_gcloud(cmd_list, capture_json=False, ignore_errors=False, quiet=False, retries=1, retry_delay=5):
    """Silently runs a gcloud command with built-in polling/retry logic and smart auth detection."""
    for attempt in range(1, retries + 1):
        try:
            res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
            if capture_json:
                return res.stdout.strip()
            return True
        except FileNotFoundError:
            print(f"\n❌ Environment Error: '{cmd_list[0]}' command not found.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            stderr_text = e.stderr.lower()
            
            # 🔥 SMART UX: Fail fast on authentication errors
            if "reauthentication failed" in stderr_text or "gcloud auth login" in stderr_text:
                print(f"\n🔐 GCP Authentication Error: Your gcloud session has expired or is missing.", file=sys.stderr)
                print(f"👉 Fix this by running: gcloud auth login", file=sys.stderr)
                sys.exit(1)
                
            if attempt < retries:
                if not quiet:
                    cmd_name = cmd_list[1] if len(cmd_list) > 1 else "command"
                    print(f"  ⏳ GCP not ready. Retrying '{cmd_name}' in {retry_delay}s (Attempt {attempt}/{retries})...")
                time.sleep(retry_delay)
                continue
            if ignore_errors:
                return False
            print(f"\n❌ GCP Command Failed: {' '.join(cmd_list)}\nError output: {e.stderr.strip()}", file=sys.stderr)
            sys.exit(1)

def get_args():
    parser = argparse.ArgumentParser(description="Vault GCP Identity & Engine Manager")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout in seconds")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO
    p_info = subparsers.add_parser("info", help="Introspect the current GCP session/token")
    p_info.add_argument("token", nargs="?", default="", help="Optional token string (defaults to env var)")

    # 2. EXEC
    p_exec = subparsers.add_parser("exec", help="Run a command with JIT GCP credentials")
    p_exec.add_argument("project", help="The GCP Project ID (where the Vault engine is mounted)")
    p_exec.add_argument("roleset", nargs="?", default="terraform-runner", help="Roleset name (default: terraform-runner)")
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, help="The command to execute (prefix with '--')")

    # 3. ENGINE (Legacy Project-level setup)
    p_engine = subparsers.add_parser("engine", help="Manage GCP Secrets Engines")
    # 🌟 Added read, info, update
    p_engine.add_argument("action", choices=["create", "delete", "list", "read", "info", "update"])
    p_engine.add_argument("project", nargs="?", default="", help="GCP Project ID")
    
    # 🌟 Added update flags
    p_engine.add_argument("--ttl", help="Update default lease TTL (e.g., '1h')")
    p_engine.add_argument("--max-ttl", help="Update max lease TTL (e.g., '24h')")

    # 4. ROLESET
    p_role = subparsers.add_parser("role", help="Manage GCP rolesets (team service accounts)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list"], help="Action to perform")
    p_role.add_argument("project", nargs="?", default="", help="GCP Project ID")
    p_role.add_argument("roleset_name", nargs="?", default="", help="Name of the roleset")
    p_role.add_argument("--roles", default="roles/editor", help="Comma-separated roles (for simple create)")
    p_role.add_argument("--bindings", help="Path to YAML/HCL bindings file (for advanced/cross-project)")
    p_role.add_argument("--master-sa", default="", help="Custom Vault Master SA email (used for cross-project auto-patching)")
    p_role.add_argument("--folder", help="Target a Folder ID instead of the Project (e.g., 123456789)")

    # 5. BOOTSTRAP (New Folder-Level Setup)
    p_bootstrap = subparsers.add_parser("bootstrap", help="Configure Vault GCP engine with Folder-level permissions (Least Privilege)")
    p_bootstrap.add_argument("--project", required=True, help="The GCP Project ID where the Vault Broker SA will live")
    p_bootstrap.add_argument("--folder-id", help="Optional: Scopes Vault's permissions to this GCP Folder ID")

    # 6. CLEANUP (New Teardown)
    p_cleanup = subparsers.add_parser("cleanup", help="Revoke Vault's GCP access and delete the broker SA")
    p_cleanup.add_argument("--project", required=True, help="The GCP Project ID where the Vault Broker SA lives")
    p_cleanup.add_argument("--folder-id", help="Optional: The GCP Folder ID where Vault's permissions were scoped")

    # 7. GKE CREDENTIALS (Zero-Dependency Kubeconfig)
    p_gke = subparsers.add_parser("get-gke-credentials", help="Fetch GKE cluster credentials via REST API (No gcloud required)")
    p_gke.add_argument("project", help="The GCP Project ID")
    p_gke.add_argument("location", help="GCP Location (e.g., us-central1)")
    p_gke.add_argument("cluster", help="GKE Cluster Name")
    p_gke.add_argument("--roleset", default="gke-admin", help="The Vault GCP Roleset (suggested: gke-admin for bootstrapping)")

    # 🌟 NEW: Leases Management for GCP
    p_leases = subparsers.add_parser("leases", help="Manage dynamic GCP OAuth tokens and Service Account keys")
    leases_subs = p_leases.add_subparsers(dest="action", required=True)

    # list
    p_leases_list = leases_subs.add_parser("list", help="List all active GCP leases")
    p_leases_list.add_argument("--mount", default="gcp", help="The GCP engine mount point (default: gcp)")

    # revoke
    p_leases_revoke = leases_subs.add_parser("revoke", help="Revoke GCP leases")
    p_leases_revoke.add_argument("--id", help="Revoke a specific lease ID")
    p_leases_revoke.add_argument("--mount", default="gcp", help="The GCP engine mount point (default: gcp)")
    p_leases_revoke.add_argument("--force", action="store_true", help="Force wipe all leases under this mount")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # INFO
    # -------------------------------------------------------------------------
    if cmd == "info":
        token = args.token or os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN")
        if not token:
            print("❌ Error: No token provided and $GOOGLE_OAUTH_ACCESS_TOKEN is not set.", file=sys.stderr)
            sys.exit(1)
            
        print("🔍 Introspecting GCP Token...", file=sys.stderr)
        metadata = vault.get_gcp_token_info(token)
        if metadata and "expires_in" in metadata:
            email = metadata.get("email", "Vault Managed Account (Scope hidden)")
            expires_in = int(metadata.get("expires_in", 3600))
            print(f"👤 Authenticated as : {email}")
            print(f"⏳ Time Remaining  : {expires_in // 60} minutes ({expires_in}s)")
            if "scope" in metadata: print(f"🌐 Granted Scopes  : {metadata['scope']}")
            sys.exit(0)
        else:
            print(f"⚠️ Token validation failed: {metadata.get('error', metadata)}", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        mount_point = f"gcp/{args.project}"
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        print(f"🔒 Fetching secure token for '{args.roleset}' from '{mount_point}'...", file=sys.stderr)
        token = vault.get_gcp_token(roleset_name=args.roleset, mount_point=mount_point)
        if not token: sys.exit(1)

        os.environ["GOOGLE_OAUTH_ACCESS_TOKEN"] = token
        os.environ["CLOUDSDK_AUTH_ACCESS_TOKEN"] = token
        print(f"🚀 Executing: {' '.join(command_list)}\n" + "-"*40, file=sys.stderr)
        try:
            sys.exit(subprocess.run(command_list, env=os.environ).returncode)
        except FileNotFoundError:
            print(f"\n❌ Error: Command not found: {command_list[0]}", file=sys.stderr)
            sys.exit(1)

    # ---------------------------------------------------------------------
    # LEASES (GCP)
    # ---------------------------------------------------------------------
    elif cmd == "leases":
        action = args.action
        mount_point = args.mount.strip('/')
        
        if action == "list":
            print(f"🔍 Searching for active leases in '{mount_point}/'...")
            found_any = False
            
            # GCP leases live under either 'token/' or 'key/' depending on the roleset type
            for token_type in ["token/", "key/"]:
                rolesets = vault.list_leases(f"{mount_point}/{token_type}")
                if rolesets:
                    for roleset in rolesets:
                        lease_ids = vault.list_leases(f"{mount_point}/{token_type}{roleset}")
                        for lid in lease_ids:
                            print(f"  ├─ {mount_point}/{token_type}{roleset}{lid}")
                            found_any = True
                            
            if not found_any:
                print("✅ No active GCP leases found.")
                
        elif action == "revoke":
            if getattr(args, "id", None):
                print(f"🗑️ Revoking specific lease '{args.id}'...")
                if vault.revoke_lease(args.id):
                    print("✅ GCP lease successfully revoked.")
            elif getattr(args, "force", False):
                print(f"🔥 Force revoking ALL leases under '{mount_point}/'...")
                if vault.force_revoke_prefix(mount_point):
                    print("✅ All GCP leases forcefully wiped.")
            else:
                print("⚠️ You must provide either '--id <lease_id>' or use '--force' to wipe the engine.")

    # -------------------------------------------------------------------------
    # BOOTSTRAP (Folder/Project Scoped Identity Broker)
    # -------------------------------------------------------------------------
    elif cmd == "bootstrap":
        project = args.project
        folder_id = args.folder_id
        sa_name = "vault-gcp-broker"
        sa_email = f"{sa_name}@{project}.iam.gserviceaccount.com"
        mount_point = f"gcp/{project}"

        print(f"🚀 Initializing Vault GCP Broker in project: {project}...")
        
        print(f"  ├─ Enabling necessary GCP Services...")
        run_gcloud(["gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "iamcredentials.googleapis.com", "--project", project], retries=2)

        print(f"  ├─ Creating Service Account '{sa_name}'...")
        run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Broker", "--project", project], ignore_errors=True)

        # Define base roles needed for Service Account generation
        base_roles = [
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountKeyAdmin"
        ]

        if folder_id:
            print(f"  ├─ 📁 Scoping Vault's access to FOLDER: {folder_id}...")
            # Add Folder-specific admin roles
            folder_roles = base_roles + [
                "roles/resourcemanager.projectIamAdmin", # Manage projects inside the folder
                "roles/resourcemanager.folderIamAdmin"   # Manage the folder's own IAM (Needed for xpnAdmin)
            ]
            for role in folder_roles:
                run_gcloud(["gcloud", "resource-manager", "folders", "add-iam-policy-binding", folder_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)
        else:
            print(f"  ├─ 📄 Scoping Vault's access locally to PROJECT: {project}...")
            # Add Project-specific admin roles
            project_roles = base_roles + ["roles/resourcemanager.projectIamAdmin"]
            for role in project_roles:
                run_gcloud(["gcloud", "projects", "add-iam-policy-binding", project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

        print("  ├─ 🔑 Generating JSON Key in-memory and updating Vault...")
        # Using capture_json=True to grab the key without ever writing it to disk!
        creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project], capture_json=True)

        if vault.setup_gcp_engine(creds_json=creds_json, mount_point=mount_point):
            print(f"🎉 Vault GCP Broker is configured and ready at '{mount_point}/'!")
        else:
            print(f"❌ Failed to configure Vault engine.", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # CLEANUP (Teardown Scoped Identity Broker)
    # -------------------------------------------------------------------------
    elif cmd == "cleanup":
        project = args.project
        folder_id = args.folder_id
        sa_name = "vault-gcp-broker"
        sa_email = f"{sa_name}@{project}.iam.gserviceaccount.com"
        mount_point = f"gcp/{project}"

        print(f"🧹 Starting Vault GCP Broker cleanup for project: {project}...")

        base_roles = [
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountKeyAdmin"
        ]

        if folder_id:
            print(f"  ├─ 📁 Removing Vault's access from FOLDER: {folder_id}...")
            folder_roles = base_roles + ["roles/resourcemanager.projectIamAdmin", "roles/resourcemanager.folderIamAdmin"]
            for role in folder_roles:
                run_gcloud(["gcloud", "resource-manager", "folders", "remove-iam-policy-binding", folder_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], ignore_errors=True, quiet=True)
        else:
            print(f"  ├─ 📄 Removing Vault's access from PROJECT: {project}...")
            project_roles = base_roles + ["roles/resourcemanager.projectIamAdmin"]
            for role in project_roles:
                run_gcloud(["gcloud", "projects", "remove-iam-policy-binding", project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], ignore_errors=True, quiet=True)

        print(f"  ├─ 🗑️ Deleting Service Account '{sa_name}'...")
        run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", project, "--quiet"], ignore_errors=True)

        print(f"  ├─ 🧹 Tearing down Vault engine at '{mount_point}/'...")
        vault.teardown_gcp_engine(mount_point=mount_point)

        print("✅ Cleanup complete. Vault's GCP access has been fully revoked.")

    # -------------------------------------------------------------------------
    # ENGINE (Legacy)
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action
        project = args.project
        
        if action == "list":
            engines = vault.list_engines(backend_type="gcp")
            if engines:
                print("🌐 Active GCP Secrets Engines:")
                for e in engines: print(f"  ├─ {e}")
            else:
                print("ℹ️ No GCP Secrets Engines mounted.")
            sys.exit(0)

        if not project:
            print("❌ Error: Project ID required for this action.", file=sys.stderr)
            sys.exit(1)

        mount_point = f"gcp/{project}"
        # 🌟 FIX: Safely grab sa_name with a default fallback to prevent AttributeError
        sa_name = getattr(args, "sa_name", "vault-admin")
        sa_email = f"{sa_name}@{project}.iam.gserviceaccount.com"

        if action in ["create", "update"]:
            print(f"🚀 Initializing Zero-Touch GCP Engine at '{mount_point}/'...")
            run_gcloud(["gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "iamcredentials.googleapis.com", "--project", project], retries=3)
            print(f"  ├─ Creating Service Account '{args.sa_name}'...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", args.sa_name, "--display-name=Vault GCP Master", "--project", project], retries=2, ignore_errors=True)
            print(f"  ├─ Granting IAM Permissions...")
            for role in ["roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin", "roles/resourcemanager.projectIamAdmin"]:
                run_gcloud(["gcloud", "projects", "add-iam-policy-binding", project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)
            print(f"  ├─ Generating JSON Key in-memory...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project], capture_json=True)
            if vault.setup_gcp_engine(creds_json=creds_json, mount_point=mount_point):
                print(f"🎉 GCP Backend ready at '{mount_point}/'!")

        elif action == "delete":
            print(f"🧹 Tearing down engine at '{mount_point}/'...")
            vault.teardown_gcp_engine(mount_point=mount_point)
            run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", project, "--quiet"], ignore_errors=True)
            print("🎉 Engine destroyed!")

        elif action in ["read", "info"]:
            print(f"🔍 Reading GCP Engine Config for '{mount_point}/'...")
            config = vault.read_gcp_engine_config(mount_point=mount_point)
            if config:
                print(json.dumps(config, indent=2))
            else:
                print("❌ Config not found.")
                
        elif action == "update":
            print(f"⚙️ Updating GCP Engine Config for '{mount_point}/'...")
            if vault.update_gcp_engine_config(mount_point, ttl=args.ttl, max_ttl=args.max_ttl):
                print("✅ Successfully updated GCP Engine TTLs!")

    # -------------------------------------------------------------------------
    # ROLESET
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        project = args.project
        roleset_name = args.roleset_name
        mount_point = f"gcp/{project}" if project else "gcp"

        if action == "list":
            # 1. Determine which engines to check
            if project:
                engines_to_check = [f"gcp/{project}"]
            else:
                print("🔍 Searching across all active GCP engines...")
                engines = vault.list_engines(backend_type="gcp") or []
                engines_to_check = [e.strip('/') for e in engines]

            if not engines_to_check:
                print("ℹ️ No GCP secrets engines currently mounted.")
                sys.exit(0)

            # 2. Iterate and list
            found_any = False
            for mount in engines_to_check:
                roles = vault.list_gcp_rolesets(mount_point=mount)
                if roles:
                    found_any = True
                    print(f"\n👥 Active Rolesets at '{mount}/':")
                    for r in roles: 
                        print(f"  ├─ {r}")
                        
            if not found_any:
                print("\nℹ️ No rolesets found.")
            sys.exit(0)

        if not project or not roleset_name:
            print("❌ Error: Project and roleset_name are required.", file=sys.stderr)
            sys.exit(1)

        if action == "read":
            data = vault.read_gcp_roleset(name=roleset_name, mount_point=mount_point)
            if data: print(json.dumps(data, indent=2))
            
        elif action == "delete":
            vault.delete_gcp_roleset(name=roleset_name, mount_point=mount_point)
            
        elif action in ["create", "update"]:
            bindings_hcl = ""
            
            # 🧠 SMART UX: YAML Parser + Automatic Cross-Project IAM Patcher
            if args.bindings:
                try:
                    with open(args.bindings, 'r') as f:
                        if args.bindings.endswith(('.yaml', '.yml')):
                            import yaml
                            config = yaml.safe_load(f)
                            
                            # Determine Master SA for patching
                            master_sa = args.master_sa or f"vault-gcp-broker@{project}.iam.gserviceaccount.com"
                            
                            for res_type, uri_path in {'projects': 'projects', 'folders': 'folders', 'organizations': 'organizations'}.items():
                                for item in config.get(res_type, []):
                                    target_name = item['name']
                                    
                                    # 🔥 AUTO-PATCHER: If YAML references a different project, run gcloud to grant Vault rights automatically!
                                    if res_type == 'projects' and target_name != project:
                                        print(f"  ⚡ Auto-Patching external project '{target_name}' to allow Vault access...")
                                        run_gcloud([
                                            "gcloud", "projects", "add-iam-policy-binding", target_name,
                                            f"--member=serviceAccount:{master_sa}",
                                            "--role=roles/resourcemanager.projectIamAdmin"
                                        ], quiet=True, ignore_errors=True)

                                    roles_str = ", ".join([f'"{r.strip()}"' for r in item.get('roles', [])])
                                    bindings_hcl += f'\nresource "//cloudresourcemanager.googleapis.com/{uri_path}/{target_name}" {{\n  roles = [{roles_str}]\n}}\n'
                            print(f"📄 Parsed YAML bindings.")
                        else:
                            bindings_hcl = f.read()
                except Exception as e:
                    print(f"❌ Error reading bindings: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                roles_list = [f'"{r.strip()}"' for r in args.roles.split(",")]
                
                # 🧠 SMART BINDING: Target Folder if provided, else target the Project
                if args.folder:
                    resource_uri = f"//cloudresourcemanager.googleapis.com/folders/{args.folder}"
                    print(f"📁 Binding permissions at the FOLDER level (Folder ID: {args.folder})")
                else:
                    resource_uri = f"//cloudresourcemanager.googleapis.com/projects/{project}"
                    print(f"🏗️ Binding permissions at the PROJECT level ({project})")
                    
                bindings_hcl = f'\nresource "{resource_uri}" {{\n  roles = [{", ".join(roles_list)}]\n}}\n'
                
            print(f"🚀 Creating Roleset '{roleset_name}'...")
            vault.create_gcp_roleset(name=roleset_name, project_id=project, bindings_hcl=bindings_hcl, mount_point=mount_point)

    # -------------------------------------------------------------------------
    # GKE CREDENTIALS (Zero-Dependency API Call)
    # -------------------------------------------------------------------------
    elif cmd == "get-gke-credentials":
        project = args.project
        location = args.location
        cluster = args.cluster
        mount_point = f"gcp/{project}"
        
        print(f"🔒 Fetching ephemeral GCP token for roleset '{args.roleset}'...", file=sys.stderr)
        gcp_token = vault.get_gcp_token(roleset_name=args.roleset, mount_point=mount_point)
        if not gcp_token:
            sys.exit(1)
            
        print(f"🌐 Querying Google Container REST API for cluster details...", file=sys.stderr)
        import urllib.request
        import urllib.error
        import ssl
        
        url = f"https://container.googleapis.com/v1/projects/{project}/locations/{location}/clusters/{cluster}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {gcp_token}"})
        
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, context=ctx) as response:
                data = json.loads(response.read().decode())
                
            endpoint = data.get("endpoint")
            ca_cert = data.get("masterAuth", {}).get("clusterCaCertificate")
            
            if not endpoint or not ca_cert:
                print("❌ Error: Cluster endpoint or CA cert not found in API response.", file=sys.stderr)
                sys.exit(1)
                
            # Construct a raw, dependency-free kubeconfig
            kubeconfig = f"""apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: {ca_cert}
    server: https://{endpoint}
  name: {cluster}
contexts:
- context:
    cluster: {cluster}
    user: {cluster}-user
  name: {cluster}-context
current-context: {cluster}-context
users:
- name: {cluster}-user
  user:
    token: {gcp_token}
"""
            # Write to a sandboxed file so we don't destroy the user's default config
            kube_dir = os.path.expanduser("~/.kube")
            os.makedirs(kube_dir, exist_ok=True)
            kube_file = os.path.join(kube_dir, f"config-gke-{cluster}")
            
            with open(kube_file, "w") as f:
                f.write(kubeconfig)
                
            print(f"✅ GKE Credentials successfully generated! (No gcloud needed)")
            print(f"👉 1. Activate it  : export KUBECONFIG={kube_file}")
            print(f"👉 2. Test it      : kubectl get nodes")
            print(f"👉 3. Mount to Vault: vault-k8s engine create {cluster}")
            
        except urllib.error.HTTPError as e:
            error_body = e.read().decode()
            print(f"❌ GCP API Error ({e.code}): {error_body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error communicating with GKE API: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
