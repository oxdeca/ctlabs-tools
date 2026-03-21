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

def resolve_gcp_folder_id(input_str, org_id=None): 
    """
    Looks up a GCP Folder ID from a potential Display Name.
    Requires org_id if input_str is a display name.
    """
    if input_str and input_str.strip().isdigit():
        return input_str.strip()
    
    # Check for required context
    if not org_id:
        print(f"  ⚠️ Cannot resolve Display Name '{input_str}': Missing --organization context.", file=sys.stderr)
        return input_str # Fallback to original string

    print(f"  🔍 Resolving GCP Folder Display Name '{input_str}' inside Organization '{org_id}'...", file=sys.stderr)
    cmd = [
        "gcloud", "resource-manager", "folders", "list",
        f"--organization={org_id}", # 🌟 UPDATED: Context added!
        f'--filter=displayName:"{input_str}"',
        "--format=json"
    ]
    
    json_result = run_gcloud(cmd, capture_json=True, ignore_errors=True, quiet=True)
    
    # (Existing parsing logic remains the same below)
    if json_result:
        try:
            folder_list = json.loads(json_result)
            if folder_list:
                numeric_id = folder_list[0]['name'].split('folders/')[-1]
                print(f"  ✅ Resolved Display Name '{input_str}' to Folder ID '{numeric_id}'.", file=sys.stderr)
                return numeric_id
        except Exception:
            pass
            
    print(f"  ⚠️ Could not resolve Display Name '{input_str}' (Lookup failed). Passing string directly...", file=sys.stderr)
    return input_str

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

    # 3. ENGINE (Bootstrapping the Secrets Engine)
    p_engine = subparsers.add_parser("engine", help="Manage Vault GCP Secrets Engines (Broker Setup)")
    p_engine.add_argument("action", choices=["create", "delete", "list", "read", "info", "update"])
    p_engine.add_argument("project", nargs="?", default="", help="GCP Project ID for Broker SA placement (and default mount point: gcp/<project>)")
    p_engine.add_argument("--sa-name", default="vault-gcp-broker", help="Custom name for the Broker SA (defaults to vault-gcp-broker)")
    p_engine.add_argument("--folder", help="SCOPE: Target a Folder ID (scopes Master SA to the folder level)")
    p_engine.add_argument("--project-only", action="store_true", help="SCOPE: Strict least-privilege (scopes Master SA only locally to its project)")
    p_engine.add_argument("--billing-accounts", help="Optional: Comma-separated list of Billing Account IDs (requires Billing Admin permissions)")
    p_engine.add_argument("--organization", help="Optional Organization ID (Required if using Folder Display Names)")
    p_engine.add_argument("--ttl", help="Update default lease TTL (e.g., '1h')")

    # 4. ROLESET
    p_role = subparsers.add_parser("role", help="Manage GCP rolesets (team service accounts)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_role.add_argument("project", nargs="?", default="", help="GCP Project ID")
    p_role.add_argument("roleset_name", nargs="?", default="", help="Name of the roleset")
    p_role.add_argument("--roles", default="roles/editor", help="Comma-separated roles (for simple create)")
    p_role.add_argument("--bindings", help="Path to YAML/HCL bindings file (for advanced/cross-project)")
    p_role.add_argument("--master-sa", default="", help="Custom Vault Master SA email (used for cross-project auto-patching)")
    p_role.add_argument("--folder", help="Target a Folder ID instead of the Project (e.g., 123456789)")

    # 5. CLEANUP (New Teardown)
    p_cleanup = subparsers.add_parser("cleanup", help="Revoke Vault's GCP access and delete the broker SA")
    p_cleanup.add_argument("--project", required=True, help="The GCP Project ID where the Vault Broker SA lives")
    p_cleanup.add_argument("--folder-id", help="Optional: The GCP Folder ID where Vault's permissions were scoped")

    # 6. GKE CREDENTIALS (Zero-Dependency Kubeconfig)
    p_gke = subparsers.add_parser("get-gke-credentials", help="Fetch GKE cluster credentials via REST API (No gcloud required)")
    p_gke.add_argument("project", help="The GCP Project ID")
    p_gke.add_argument("location", help="GCP Location (e.g., us-central1)")
    p_gke.add_argument("cluster", help="GKE Cluster Name")
    p_gke.add_argument("--roleset", default="gke-admin", help="The Vault GCP Roleset (suggested: gke-admin for bootstrapping)")

    # 7. LEASES (Management)
    p_leases = subparsers.add_parser("leases", help="Manage dynamic GCP OAuth tokens and Service Account keys")
    leases_subs = p_leases.add_subparsers(dest="action", required=True)
    p_leases_list = leases_subs.add_parser("list", help="List active GCP leases")
    p_leases_list.add_argument("project", nargs="?", default="", help="The GCP Project ID (leave blank to search all)")
    p_leases_revoke = leases_subs.add_parser("revoke", help="Revoke GCP leases")
    p_leases_revoke.add_argument("project", help="The GCP Project ID")
    p_leases_revoke.add_argument("--id", help="Revoke a specific lease ID")
    p_leases_revoke.add_argument("--force", action="store_true", help="Force wipe all leases under this project")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # 1. INFO
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
    # 2. EXEC
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

    # -------------------------------------------------------------------------
    # 3. ENGINE MANAGEMENT (Unified Broker Setup)
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action
        
        if action == "list":
            # (Keep your existing list_engines logic here)
            pass

        project = args.project
        if not project:
            sys.exit("❌ Error: Project ID required.", file=sys.stderr)

        sa_name = args.sa_name # Unified flag!
        sa_email = f"{sa_name}@{project}.iam.gserviceaccount.com"
        mount_point = f"gcp/{project}"

        if action == "create":
            print(f"🚀 Initializing Unified GCP Broker in project: {project}...")
            print(f"  ├─ Logical Path: {mount_point}/")
            
            # (Enable Necessary Services...)
            print(f"  ├─ Enabling necessary GCP Services...")
            run_gcloud(["gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "iamcredentials.googleapis.com", "--project", project], retries=2)

            # (Create the Service Account...)
            print(f"  ├─ Creating Service Account '{sa_name}'...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Broker", "--project", project], ignore_errors=True)

            # (Base roles Vault always needs...)
            base_roles = [
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin"
            ]

            # 🌟 STEP 3: Smart Scoping based on arguments
            if args.folder:
                print(f"  ├─ SCOPE: Scoping Vault's access to FOLDER: {args.folder}...")
                resolved_folder_id = resolve_gcp_folder_id(args.folder, args.organization)
                
                folder_roles = base_roles + [
                    "roles/resourcemanager.projectIamAdmin",
                    "roles/resourcemanager.folderIamAdmin"
                ]
                for role in folder_roles:
                    run_gcloud(["gcloud", "resource-manager", "folders", "add-iam-policy-binding", resolved_folder_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

            elif args.project_only:
                print(f"  ├─ SCOPE: Sandboxing Vault strictly to PROJECT: {project}...")
                project_roles = base_roles + ["roles/resourcemanager.projectIamAdmin"]
                for role in project_roles:
                    run_gcloud(["gcloud", "projects", "add-iam-policy-binding", project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

            else:
                sys.exit("\n❌ SCOPE REQUIRED: Must provide either '--folder <id>' for modern architecture, or '--project-only' for least-privilege sandboxing.")

            # 🌟 STEP 4: THE BILLING FIX 🌟
            if getattr(args, 'billing_accounts', None):
                print(f"  ├─ 💳 Assigning Billing Admin role to Vault Broker SA...")
                billing_ids = [b.strip() for b in args.billing_accounts.split(",")]
                for billing_id in billing_ids:
                    # Note: gcloud beta is required for billing account IAM
                    run_gcloud([
                        "gcloud", "beta", "billing", "accounts", "add-iam-policy-binding", billing_id,
                        f"--member=serviceAccount:{sa_email}",
                        "--role=roles/billing.admin"
                    ], ignore_errors=True)
                    print(f"  │  ├─ Granted access to Billing Account: {billing_id}")

            # (Generate JSON Key and write to Vault...)
            print("  ├─ 🔑 Generating JSON Key and updating Vault...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project], capture_json=True)

            if vault.setup_gcp_engine(creds_json=creds_json, mount_point=mount_point):
                print(f"🎉 Vault GCP Broker Engine configured successfully at '{mount_point}/'!")
            else:
                sys.exit("❌ Failed to configure Vault engine.", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 4. ROLESET
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        project = args.project
        roleset_name = args.roleset_name
        mount_point = f"gcp/{project}" if project else "gcp"

        if action == "list":
            if project:
                engines_to_check = [f"gcp/{project}"]
            else:
                print("🔍 Searching across all active GCP engines...")
                engines = vault.list_engines(backend_type="gcp") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("gcp/")]

            if not engines_to_check:
                print("ℹ️ No GCP secrets engines currently mounted.")
                sys.exit(0)

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
            else: print(f"❌ Roleset '{roleset_name}' not found.")
            
        elif action == "info":
            data = vault.read_gcp_roleset(name=roleset_name, mount_point=mount_point)
            if data:
                print(f"👥 GCP Roleset: {roleset_name}")
                print(f"  ├─ Engine      : {mount_point}/")
                print(f"  ├─ Secret Type : {data.get('secret_type', 'access_token')}")
                print(f"  ├─ Project     : {data.get('project', project)}")
                
                # 🌟 Added the SA Email output
                sa_email = data.get('service_account_email', 'Dynamic/Unknown')
                print(f"  ├─ SA Email    : {sa_email}")
                
                scopes = data.get('token_scopes', [])
                if scopes:
                    print(f"  ├─ Scopes      : {', '.join(scopes)}")
                    
                # 🌟 Safely format the bindings into a neat tree
                bindings = data.get('bindings', '')
                if bindings:
                    if isinstance(bindings, str):
                        lines = len(bindings.strip().split('\n'))
                        print(f"  ├─ Bindings    : Configured ({lines} lines of raw HCL)")
                    elif isinstance(bindings, dict):
                        print(f"  ├─ Bindings    :")
                        for uri, roles in bindings.items():
                            # Clean up the URI to just show projects/foo or folders/bar
                            display_uri = uri.split('googleapis.com/')[-1] if 'googleapis.com/' in uri else uri
                            print(f"  │  ├─ {display_uri}")
                            for role in roles:
                                print(f"  │  │  ├─ {role}")
                    elif isinstance(bindings, list):
                        print(f"  ├─ Bindings    : Configured ({len(bindings)} items)")
                    else:
                        print(f"  ├─ Bindings    : Configured")
                else:
                    print(f"  ├─ Bindings    : None")
            else:
                print(f"❌ Roleset '{roleset_name}' not found.")
            
        elif action == "delete":
            vault.delete_gcp_roleset(name=roleset_name, mount_point=mount_point)
            
        elif action in ["create", "update"]:
            bindings_hcl = ""
            
            if args.bindings:
                try:
                    with open(args.bindings, 'r') as f:
                        if args.bindings.endswith(('.yaml', '.yml')):
                            import yaml
                            config = yaml.safe_load(f)
                            
                            master_sa = args.master_sa or f"vault-gcp-broker@{project}.iam.gserviceaccount.com"
                            
                            # Map the YAML key to its specific GCP API domain and URI path
                            resource_maps = {
                                'projects': ('cloudresourcemanager.googleapis.com', 'projects'),
                                'folders': ('cloudresourcemanager.googleapis.com', 'folders'),
                                'organizations': ('cloudresourcemanager.googleapis.com', 'organizations'),
                                'billingAccounts': ('cloudbilling.googleapis.com', 'billingAccounts') # <-- Added Billing
                            }
                            
                            for res_type, (api_domain, uri_path) in resource_maps.items():
                                for item in config.get(res_type, []):
                                    target_name = item['name']
                                    
                                    # Keep your existing auto-patching logic for cross-project access
                                    if res_type == 'projects' and target_name != project:
                                        print(f"  ⚡ Auto-Patching external project '{target_name}' to allow Vault access...")
                                        run_gcloud([
                                            "gcloud", "projects", "add-iam-policy-binding", target_name,
                                            f"--member=serviceAccount:{master_sa}",
                                            "--role=roles/resourcemanager.projectIamAdmin"
                                        ], quiet=True, ignore_errors=True)
                            
                                    roles_str = ", ".join([f'"{r.strip()}"' for r in item.get('roles', [])])
                                    # Use the dynamic api_domain instead of hardcoding cloudresourcemanager
                                    bindings_hcl += f'\nresource "//{api_domain}/{uri_path}/{target_name}" {{\n  roles = [{roles_str}]\n}}\n'
                            print(f"📄 Parsed YAML bindings.")
                        else:
                            bindings_hcl = f.read()
                except Exception as e:
                    print(f"❌ Error reading bindings: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                roles_list = [f'"{r.strip()}"' for r in args.roles.split(",")]
                
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
    # 5. CLEANUP
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
    # 6. GKE CREDENTIALS (Zero-Dependency API Call)
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

    # ---------------------------------------------------------------------
    # 7. LEASES
    # ---------------------------------------------------------------------
    elif cmd == "leases":
        action = args.action
        
        if action == "list":
            if args.project:
                engines_to_check = [f"gcp/{args.project}"]
            else:
                print("🔍 Searching across all active GCP engines...")
                engines = vault.list_engines(backend_type="gcp") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("gcp/")]

            if not engines_to_check:
                print("ℹ️ No GCP Engines currently mounted.")
                sys.exit(0)

            found_any = False
            for m in engines_to_check:
                for token_type in ["token/", "key/"]:
                    rolesets = vault.list_leases(f"{m}/{token_type}")
                    if rolesets:
                        for roleset in rolesets:
                            lease_ids = vault.list_leases(f"{m}/{token_type}{roleset}")
                            if lease_ids:
                                if not found_any: print("")
                                print(f"📁 Active Leases in {m}/{token_type}{roleset}:")
                                for lid in lease_ids:
                                    print(f"  ├─ {m}/{token_type}{roleset}{lid}")
                                    found_any = True
                                
            if not found_any:
                print("✅ No active GCP leases found.")
                
        elif action == "revoke":
            mount_point = f"gcp/{args.project}"
            
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

if __name__ == "__main__":
    main()
