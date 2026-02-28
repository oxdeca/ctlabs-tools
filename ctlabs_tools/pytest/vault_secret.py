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
    parser.add_argument("command", choices=["write", "read", "list", "search", "get-creds", "leases", "raw", "backend"], help="Action to perform")
    parser.add_argument("arg1", nargs="?", default="", help="Vault path (e.g., kvv2/apps) OR backend provider")
    parser.add_argument("arg2", nargs="?", default="", help="Backend action ('create'/'destroy') OR Search pattern")
    parser.add_argument("arg3", nargs="?", default="", help="GCP Project ID (for backend gcp create/destroy)")
    
    
    parser.add_argument("--data", help="JSON string of the secret data")
    parser.add_argument("--pattern", help="Regex pattern to search for")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout in seconds")
    
    return parser.parse_args()

def run_gcloud(cmd_list, capture_json=False, ignore_errors=False, quiet=False):
    """Silently runs a gcloud command and halts if it fails (unless ignored)."""
    try:
        res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        if capture_json:
            return res.stdout.strip()
        return True
    except subprocess.CalledProcessError as e:
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
    
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    # -------------------------------------------------------------------------
    # BACKEND MANAGER
    # -------------------------------------------------------------------------
    if args.command == "backend":
        provider = args.arg1.lower()
        action = args.arg2.lower()
        project_id = args.arg3  # Automatically grabbed from the command line!
        
        if provider != "gcp":
            print("❌ Error: Unsupported backend provider. Currently only 'gcp' is supported.", file=sys.stderr)
            sys.exit(1)
            
        if action not in ["create", "destroy"]:
            print("❌ Error: Action must be 'create' or 'destroy'. Example: vault-secret backend gcp create <project_id>", file=sys.stderr)
            sys.exit(1)
            
        if not project_id:
            print("❌ Error: Project ID is required. Example: vault-secret backend gcp create <project_id>", file=sys.stderr)
            sys.exit(1)

        # 🧠 SMART MOUNT: Automatically map the mount point to gcp/<project_id>
        custom_mount = f"gcp/{project_id}"
        sa_name = "vault-gcp-master"
        sa_email = f"{sa_name}@{project_id}.iam.gserviceaccount.com"

        if action == "create":
            print(f"🚀 Initializing Zero-Touch GCP Secrets Engine at '{custom_mount}/'...")
            
            print(f"  ├─ Creating Service Account '{sa_name}' in GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Master", "--project", project_id])
            
            print(f"  ├─ Granting IAM Permissions (Polling for GCP synchronization)...")
            
            # 🧠 SMART POLLING: Loop through all required roles and poll GCP until each one is accepted
            roles_to_grant = [
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin",
                "roles/resourcemanager.projectIamAdmin"
            ]
            
            for role in roles_to_grant:
                iam_success = False
                for attempt in range(1, 13):
                    if run_gcloud(["gcloud", "projects", "add-iam-policy-binding", project_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], ignore_errors=True, quiet=True):
                        iam_success = True
                        break
                    
                    # Only print the retry message if it failed
                    print(f"  ⏳ GCP IAM settling... Retrying {role.split('/')[1]} in 5s (Attempt {attempt}/12)")
                    time.sleep(5)
                    
                if not iam_success:
                    print(f"❌ Error: Failed to grant {role} within 60 seconds.", file=sys.stderr)
                    sys.exit(1)
            
            print(f"  ├─ Generating JSON Key in-memory...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project_id], capture_json=True)
            
            print(f"  ├─ Configuring Vault Engine at '{custom_mount}/'...")
            if not vault.setup_gcp_engine(creds_json=creds_json, mount_point=custom_mount):
                print("❌ Aborting setup due to Vault engine configuration failure.", file=sys.stderr)
                sys.exit(1)
            
            print(f"  ├─ Creating 'terraform-runner' roleset...")
            bindings_hcl = f"""
              resource "//cloudresourcemanager.googleapis.com/projects/{project_id}" {{
                roles = ["roles/editor"]
              }}
            """
            
            if not vault.create_gcp_roleset(name="terraform-runner", project_id=project_id, bindings_hcl=bindings_hcl, mount_point=custom_mount):
                print("❌ Aborting setup due to Vault roleset creation failure.", file=sys.stderr)
                sys.exit(1)
            
            print(f"\n🎉 GCP Backend successfully created at '{custom_mount}/'!")
            sys.exit(0)

        elif action == "destroy":
            # UPDATED PRINT & METHOD CALL: Pass the custom_mount
            print(f"🧹 Tearing down GCP Secrets Engine at '{custom_mount}/'...")
            print(f"  ├─ Unmounting Vault engine...")
            vault.teardown_gcp_engine(mount_point=custom_mount)
            print(f"  ├─ Deleting Master Service Account '{sa_name}' from GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", project_id, "--quiet"], ignore_errors=True)
            print("\n🎉 Backend successfully destroyed! No orphaned resources left behind.")
            sys.exit(0)

    # -------------------------------------------------------------------------
    # VALIDATION: All standard commands require a valid path
    # -------------------------------------------------------------------------
    path = args.arg1
    if not path:
        print("❌ Error: 'path' is required for this command.", file=sys.stderr)
        sys.exit(1)

    if args.command == "raw":
        data = vault.read_raw_path(path)
        if data:
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {path}")
        sys.exit(0)

    # Split the mount point from the secret path
    parts = path.split('/', 1)
    if len(parts) < 2:
        print("❌ Error: Path must include the mount point (e.g., kvv2/my-secret)", file=sys.stderr)
        sys.exit(1)
        
    mount_point, secret_path = parts[0], parts[1]

    # -------------------------------------------------------------------------
    # EXISTING COMMANDS
    # -------------------------------------------------------------------------
    if args.command == "write":
        if not args.data:
            print("❌ Error: --data JSON string is required to write a secret.")
            sys.exit(1)
        try:
            secret_dict = json.loads(args.data)
        except json.JSONDecodeError:
            print("❌ Error: --data must be a valid JSON string.")
            sys.exit(1)
            
        if vault.write_secret(path=secret_path, secret_data=secret_dict, mount_point=mount_point):
            print(f"✅ Successfully wrote data to {path}")

    elif args.command == "read":
        # 3. SMART ROUTING: Auto-detect system paths vs KV paths
        known_raw_mounts = ["sys", "auth", "identity", "pki", "transit"]
        
        if mount_point in known_raw_mounts:
            data = vault.read_raw_path(path)
        else:
            # Try KV engine first, gracefully fallback to raw if the user is probing a weird mount
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data is None:
                data = vault.read_raw_path(path)

        if data:
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {path}")

    elif args.command == "list":
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

    elif args.command == "search":
        # 4. PATTERN ALIAS: Take it from the flag OR the positional argument
        pattern = args.pattern or args.arg2
        if not pattern:
            print("❌ Error: A search pattern is required. (e.g., vault-secret search kvv2/apps winter)")
            sys.exit(1)
            
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

    # 5. GET-CREDS
    elif args.command == "get-creds":
        if path.startswith("gcp/"):
            # Split from the right: "gcp/my-project/terraform-runner" -> Mount: "gcp/my-project", Roleset: "terraform-runner"
            roleset_name = path.split('/')[-1]
            dynamic_mount = path.rsplit('/', 1)[0]
            
            token = vault.get_gcp_token(roleset_name=roleset_name, mount_point=dynamic_mount)
            if token:
                print(f'export GOOGLE_OAUTH_ACCESS_TOKEN="{token}"')
                print(f"# ✅ Dynamically generated GCP Token for roleset '{roleset_name}' at '{dynamic_mount}/'!", file=sys.stderr)
                print("# ⏳ This token will automatically expire in 1 hour.", file=sys.stderr)
            else:
                print(f"# ❌ Failed to fetch GCP token for '{path}'.", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"❌ Error: 'get-creds' currently only supports GCP rolesets via this script.", file=sys.stderr)
            sys.exit(1)

    # 6. LEASES
    elif args.command == "leases":
        if path.startswith("auth/") or mount_point == "auth":
            print("ℹ️  Vault Architecture Note:")
            print("   Human and Machine logins (Userpass, LDAP, AppRole) generate 'Tokens', not 'Leases'.")
            print("   To view active logins, you must list Token Accessors.")
            print("\n   Try running: vault-secret raw auth/token/accessors/")
            sys.exit(0)

        # Smart format for GCP token paths
        if path.startswith("gcp/"):
            roleset_name = path.split('/')[-1]
            dynamic_mount = path.rsplit('/', 1)[0]
            lookup_path = f"{dynamic_mount}/token/{roleset_name}"
        else:
            lookup_path = path

        keys = vault.list_leases(prefix=lookup_path)
        
        if keys:
            print(f"📋 Active leases for '{lookup_path}':")
            for k in keys:
                print(f"  ├─ {k}")
        else:
            print(f"ℹ️ No active leases found for '{lookup_path}' (or permission denied).")

if __name__ == "__main__":
    main()
