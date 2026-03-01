# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_secret.py
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import os
import subprocess
import time
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Secret Data Manager")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout in seconds")
    
    # Create the subparser router
    subparsers = parser.add_subparsers(dest="command", required=True, help="Action to perform")

    # 1. BACKEND MANAGER
    p_backend = subparsers.add_parser("backend", help="Manage dynamic secret engines")
    p_backend.add_argument("provider", choices=["gcp"], help="The backend provider (e.g., gcp)")
    p_backend.add_argument("action", choices=["create", "destroy", "list"], help="The action to perform")
    p_backend.add_argument("project_id", nargs="?", default="", help="GCP Project ID (required for create/destroy)")
    p_backend.add_argument("--sa-name", default="vault-gcp-master", help="Master Service Account name (default: vault-gcp-master)")
    p_backend.add_argument("--roleset-name", default="terraform-runner", help="Name of the dynamic roleset (default: terraform-runner)")

    # 1.5 ROLESET MANAGER
    p_roleset = subparsers.add_parser("roleset", help="Manage GCP rolesets (team service accounts)")
    p_roleset.add_argument("action", choices=["create", "read", "list", "delete"], help="The action to perform")
    p_roleset.add_argument("path", help="The engine path (e.g., gcp/my-project)")
    p_roleset.add_argument("roleset_name", nargs="?", default="", help="Name of the roleset (required for create/read/delete)")
    p_roleset.add_argument("--roles", default="roles/editor", help="Comma-separated GCP roles to grant (used with 'create')")

    # 2. RAW API
    p_raw = subparsers.add_parser("raw", help="Read raw JSON from any Vault API path")
    p_raw.add_argument("path", help="The exact Vault API path")

    # 3. GET-TOKEN (Dynamic Identity)
    p_token = subparsers.add_parser("get-token", help="Generate dynamic OAuth tokens")
    p_token.add_argument("path", help="The engine path (e.g., gcp/my-project)")
    p_token.add_argument("roleset", nargs="?", default="", help="Optional roleset name (defaults to terraform-runner)")

    # 4 INFO (Introspect active tokens)
    p_info = subparsers.add_parser("info", help="Get information about active sessions/tokens")
    p_info.add_argument("provider", choices=["gcp"], help="The provider to inspect (e.g., gcp)")
    p_info.add_argument("token", nargs="?", default="", help="Optional token string (defaults to env var)")

    # 5. LEASES (Dynamic Identity)
    p_leases = subparsers.add_parser("leases", help="List active leases/tokens")
    p_leases.add_argument("path", help="The engine path (e.g., gcp/my-project)")
    p_leases.add_argument("roleset", nargs="?", default="", help="Optional roleset name")

    # 6. WRITE (Static Secrets)
    p_write = subparsers.add_parser("write", help="Write a static secret payload")
    p_write.add_argument("path", help="The Vault path (e.g., kvv2/apps/my-secret)")
    p_write.add_argument("--data", required=True, help="JSON string of the secret data")

    # 7. READ (Static Secrets)
    p_read = subparsers.add_parser("read", help="Read a static secret payload")
    p_read.add_argument("path", help="The Vault path (e.g., kvv2/apps/my-secret)")

    # 8. LIST (Static Secrets)
    p_list = subparsers.add_parser("list", help="List folders or secret keys")
    p_list.add_argument("path", help="The Vault path (e.g., kvv2/apps)")

    # 9. SEARCH (Static Secrets)
    p_search = subparsers.add_parser("search", help="Search folders, secrets, and payload keys")
    p_search.add_argument("path", help="The base Vault path to search")
    p_search.add_argument("pattern", help="Regex pattern to search for")

    return parser.parse_args()


def run_gcloud(cmd_list, capture_json=False, ignore_errors=False, quiet=False, retries=1, retry_delay=5):
    """Silently runs a gcloud command with built-in polling/retry logic."""
    for attempt in range(1, retries + 1):
        try:
            res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
            if capture_json:
                return res.stdout.strip()
            return True
        except FileNotFoundError:
            # Catch missing executables beautifully
            print(f"\n❌ Environment Error: '{cmd_list[0]}' command not found.", file=sys.stderr)
            print("Please ensure the Google Cloud SDK is installed and available in your PATH.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            if attempt < retries:
                if not quiet:
                    cmd_name = cmd_list[1] if len(cmd_list) > 1 else "command"
                    print(f"  ⏳ GCP not ready. Retrying '{cmd_name}' in {retry_delay}s (Attempt {attempt}/{retries})...")
                time.sleep(retry_delay)
                continue
            
            if ignore_errors:
                if not quiet:
                    error_line = e.stderr.strip().splitlines()[0] if e.stderr else "Unknown error"
                    print(f"  ⚠️ Ignored GCP Error: {error_line}", file=sys.stderr)
                return False
                
            print(f"\n❌ GCP Command Failed: {' '.join(cmd_list)}", file=sys.stderr)
            print(f"Error output: {e.stderr.strip()}", file=sys.stderr)
            sys.exit(1)

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    
    if not vault.ensure_valid_token():
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # 1. ISOLATED COMMANDS (No standard path splitting required)
    # -------------------------------------------------------------------------
    
    if cmd == "raw":
        data = vault.read_raw_path(args.path)
        if data:
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {args.path}")
        sys.exit(0)

    if cmd == "backend":
        provider = args.provider
        action = args.action

        # 🧠 SMART SANITIZER: Clean up accidental 'gcp/' prefixes or trailing slashes
        project_id = args.project_id
        if project_id:
            if project_id.startswith("gcp/"):
                project_id = project_id[4:]
            project_id = project_id.strip("/")
            
        if action in ["create", "destroy"] and not project_id:
            print(f"❌ Error: Project ID is required for '{action}'. Example: vault-secret backend {provider} {action} <project_id>", file=sys.stderr)
            sys.exit(1)

        if action == "list":
            engines = vault.list_engines(backend_type=provider)
            if engines is None:
                sys.exit(1)
            if not engines:
                print(f"ℹ️ No '{provider}' Secrets Engines are currently mounted.")
            else:
                print(f"🌐 Active '{provider}' Secrets Engines:")
                for e in engines:
                    print(f"  ├─ {e}")
            sys.exit(0)

        custom_mount = f"gcp/{project_id}"
        sa_name = args.sa_name
        sa_email = f"{sa_name}@{project_id}.iam.gserviceaccount.com"

        if action == "create":
            print(f"🚀 Initializing Zero-Touch GCP Secrets Engine at '{custom_mount}/'...")
            print(f"  ├─ Enabling Required GCP APIs (IAM, Resource Manager, Credentials)...")
            run_gcloud(["gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "iamcredentials.googleapis.com", "--project", project_id], retries=3)

            print(f"  ├─ Creating Service Account '{sa_name}' in GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Master", "--project", project_id], retries=5)
            
            print(f"  ├─ Granting IAM Permissions (Polling for GCP synchronization)...")
            roles_to_grant = [
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin",
                "roles/resourcemanager.projectIamAdmin"
            ]
            for role in roles_to_grant:
                run_gcloud(["gcloud", "projects", "add-iam-policy-binding", project_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True, retries=12)
            
            print(f"  ├─ Generating JSON Key in-memory...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project_id], capture_json=True, retries=3)
            
            print(f"  ├─ Configuring Vault Engine at '{custom_mount}/'...")
            if not vault.setup_gcp_engine(creds_json=creds_json, mount_point=custom_mount):
                print("❌ Aborting setup due to Vault engine configuration failure.", file=sys.stderr)
                sys.exit(1)
            
            roleset_name = args.roleset_name
            print(f"  ├─ Creating '{roleset_name}' roleset...")
            bindings_hcl = f"""
              resource "//cloudresourcemanager.googleapis.com/projects/{project_id}" {{
                roles = ["roles/editor"]
              }}
            """
            if not vault.create_gcp_roleset(name=roleset_name, project_id=project_id, bindings_hcl=bindings_hcl, mount_point=custom_mount):
                print("❌ Aborting setup due to Vault roleset creation failure.", file=sys.stderr)
                sys.exit(1)
            
            print(f"\n🎉 GCP Backend successfully created at '{custom_mount}/'!")
            sys.exit(0)

        elif action == "destroy":
            print(f"🧹 Tearing down GCP Secrets Engine at '{custom_mount}/'...")
            print(f"  ├─ Unmounting Vault engine...")
            vault.teardown_gcp_engine(mount_point=custom_mount)
            print(f"  ├─ Deleting Master Service Account '{sa_name}' from GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", project_id, "--quiet"], ignore_errors=True)
            print("\n🎉 Backend successfully destroyed! No orphaned resources left behind.")
            sys.exit(0)
    
    if cmd == "roleset":
        action = args.action
        path = args.path.strip("/")
        roleset_name = args.roleset_name
        
        if action in ["create", "read", "delete"] and not roleset_name:
            print(f"❌ Error: 'roleset_name' is required for the '{action}' action.", file=sys.stderr)
            sys.exit(1)

        if action == "list":
            keys = vault.list_gcp_rolesets(mount_point=path)
            if keys:
                print(f"👥 Active Rolesets at '{path}/':")
                for k in keys:
                    print(f"  ├─ {k}")
            else:
                print(f"ℹ️ No rolesets found at '{path}/'.")
                
        elif action == "read":
            data = vault.read_gcp_roleset(name=roleset_name, mount_point=path)
            if data:
                print(json.dumps(data, indent=2))
            else:
                print(f"⚠️ Roleset '{roleset_name}' not found.")
                
        elif action == "delete":
            vault.delete_gcp_roleset(name=roleset_name, mount_point=path)
            
        elif action == "create":
            # Extract the project ID from the path (e.g., gcp/ctlabs-prj-123 -> ctlabs-prj-123)
            project_id = path.split('/')[-1]
            roles_list = [f'"{r.strip()}"' for r in args.roles.split(",")]
            
            # Dynamically build the HCL bindings
            bindings_hcl = f"""
              resource "//cloudresourcemanager.googleapis.com/projects/{project_id}" {{
                roles = [{", ".join(roles_list)}]
              }}
            """
            print(f"🚀 Creating/Updating Roleset '{roleset_name}'...")
            vault.create_gcp_roleset(name=roleset_name, project_id=project_id, bindings_hcl=bindings_hcl, mount_point=path)
            
        sys.exit(0)

    # -------------------------------------------------------------------------
    # 2. GCP DYNAMIC COMMANDS (Custom Path Logic)
    # -------------------------------------------------------------------------
    if cmd in ["get-token", "leases"]:
        path = args.path
        if path.startswith("gcp/"):
            parts = path.split('/')
            if len(parts) >= 3:
                roleset_name = parts[-1]
                dynamic_mount = path.rsplit('/', 1)[0]
            else:
                dynamic_mount = path
                roleset_name = args.roleset if args.roleset else "terraform-runner"
            
            if cmd == "get-token":
                token = vault.get_gcp_token(roleset_name=roleset_name, mount_point=dynamic_mount)
                if token:
                    print(f'export GOOGLE_OAUTH_ACCESS_TOKEN="{token}"')
                    print(f'export CLOUDSDK_AUTH_ACCESS_TOKEN="{token}"')
                    print(f"# ✅ Dynamically generated GCP Token at '{dynamic_mount}/'!", file=sys.stderr)
                    
                    metadata = vault.get_gcp_token_info(token)
                    if metadata and "expires_in" in metadata:
                        email = metadata.get("email", f"Vault Managed Account ({roleset_name})")
                        expires_in = int(metadata.get("expires_in", 3600))
                        mins = expires_in // 60
                        print(f"# 👤 Authenticated as: {email}", file=sys.stderr)
                        print(f"# ⏳ Valid for exactly {mins} minutes ({expires_in}s).", file=sys.stderr)
                    elif metadata and "error" in metadata:
                        print(f"# ⚠️ Could not fetch token details from Google: {metadata['error']}", file=sys.stderr)
                    else:
                        print(f"# ⚠️ Unexpected response from Google: {metadata}", file=sys.stderr)                
                else:
                    sys.exit(1)
                sys.exit(0)
                
            elif cmd == "leases":
                lookup_path = f"{dynamic_mount}/token/{roleset_name}"
                keys = vault.list_leases(prefix=lookup_path)
                if keys:
                    print(f"📋 Active leases for '{lookup_path}':")
                    for k in keys:
                        print(f"  ├─ {k}")
                else:
                    print(f"ℹ️ No active leases found for '{lookup_path}' (or permission denied).")
                sys.exit(0)
                
        else:
            if cmd == "leases" and (path.startswith("auth/") or path == "auth"):
                print("ℹ️  Vault Architecture Note:\n   Human and Machine logins generate 'Tokens', not 'Leases'.\n   Try running: vault-secret raw auth/token/accessors/")
                sys.exit(0)
                
            print(f"❌ Error: '{cmd}' currently only supports GCP rolesets via this script.", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 2.5 INFO COMMAND
    # -------------------------------------------------------------------------
    if cmd == "info":
        provider = args.provider
        
        if provider == "gcp":
            # Smart fallback: Use provided argument OR the environment variable
            token = args.token or os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN")
            
            if not token:
                print("❌ Error: No token provided and $GOOGLE_OAUTH_ACCESS_TOKEN is not set in this terminal.", file=sys.stderr)
                sys.exit(1)
                
            print("🔍 Introspecting GCP Token with Google...", file=sys.stderr)
            metadata = vault.get_gcp_token_info(token)
            
            if metadata and "expires_in" in metadata:
                email = metadata.get("email", "Vault Managed Account (Scope hidden)")
                expires_in = int(metadata.get("expires_in", 3600))
                mins = expires_in // 60
                
                print(f"👤 Authenticated as : {email}")
                print(f"⏳ Time Remaining  : {mins} minutes ({expires_in}s)")
                if "scope" in metadata:
                    print(f"🌐 Granted Scopes  : {metadata['scope']}")
                sys.exit(0)
                
            elif metadata and "error" in metadata:
                print(f"⚠️ Token validation failed: {metadata['error']}", file=sys.stderr)
                sys.exit(1)
            else:
                print(f"⚠️ Unexpected response from Google: {metadata}", file=sys.stderr)
                sys.exit(1)

    # -------------------------------------------------------------------------
    # 3. STANDARD KV SECRETS COMMANDS
    # -------------------------------------------------------------------------
    
    # We enforce mount_point/secret_path routing here!
    path = args.path
    parts = path.split('/', 1)
    if len(parts) < 2:
        print("❌ Error: Path must include the mount point (e.g., kvv2/my-secret)", file=sys.stderr)
        sys.exit(1)
        
    mount_point, secret_path = parts[0], parts[1]

    if cmd == "write":
        try:
            secret_dict = json.loads(args.data)
        except json.JSONDecodeError:
            print("❌ Error: --data must be a valid JSON string.")
            sys.exit(1)
            
        if vault.write_secret(path=secret_path, secret_data=secret_dict, mount_point=mount_point):
            print(f"✅ Successfully wrote data to {path}")

    elif cmd == "read":
        known_raw_mounts = ["sys", "auth", "identity", "pki", "transit"]
        if mount_point in known_raw_mounts:
            data = vault.read_raw_path(path)
        else:
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data is None:
                data = vault.read_raw_path(path)

        if data:
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {path}")

    elif cmd == "list":
        keys = vault.list_secrets(path=secret_path, mount_point=mount_point)
        if keys:
            print(f"📂 Folders/Secrets at {path}/:")
            for k in keys:
                print(f"  ├─ {k}")
        else:
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data:
                print(f"🔑 Keys inside secret payload at '{path}':")
                for k in data.keys():
                    print(f"  ├─ {k}")
            else:
                print(f"ℹ️ No paths or secrets found at {path}")

    elif cmd == "search":
        pattern = args.pattern
        print(f"🔍 Safely scanning for pattern '{pattern}' under {path}/ ...")
        found_any = False
        
        for found_path, matched_keys, path_matches, is_folder in vault.search_secrets(base_path=secret_path, search_pattern=pattern, mount_point=mount_point):
            if is_folder:
                print(f"  📁 {mount_point}/{found_path} ➜ [Folder Match]")
            else:
                match_types = []
                if path_matches: match_types.append("Path Match")
                if matched_keys: match_types.append(f"Key Matches: {', '.join(matched_keys)}")
                
                details = " | ".join(match_types)
                print(f"  📄 {mount_point}/{found_path} ➜ [{details}]")
                
            found_any = True
            
        if not found_any:
            print(f"⚠️ Could not find any paths or keys matching the pattern '{pattern}'.")


if __name__ == "__main__":
    main()
