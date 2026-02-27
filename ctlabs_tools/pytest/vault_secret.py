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
    
    # 1. Replaced setup/teardown with the unified "backend" command
    parser.add_argument("command", choices=["write", "read", "list", "search", "gcp", "raw", "backend"], help="Action to perform")
    
    # 2. Flexible positional arguments to handle both "kvv2/path" OR "gcp create"
    parser.add_argument("arg1", nargs="?", default="", help="Vault path (e.g., kvv2/apps) OR backend provider (e.g., gcp)")
    parser.add_argument("arg2", nargs="?", default="", help="Backend action: 'create' or 'destroy' (only used with 'backend' command)")
    
    parser.add_argument("--data", help="JSON string of the secret data (required for write)")
    parser.add_argument("--pattern", help="Regex pattern to search for (used with search)")
    
    # 3. Dedicated flag for the backend manager
    parser.add_argument("--project-id", help="GCP Project ID (required for backend gcp create/destroy)")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout in seconds (default: 90)")
    
    return parser.parse_args()

def run_gcloud(cmd_list, capture_json=False, ignore_errors=False):
    """Silently runs a gcloud command and halts if it fails (unless ignored)."""
    try:
        res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        if capture_json:
            return res.stdout.strip()
        return True
    except subprocess.CalledProcessError as e:
        if ignore_errors:
            print(f"  ⚠️ Ignored GCP Error: {e.stderr.strip().splitlines()[0]}", file=sys.stderr)
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
    # NEW: Elegant Noun-Verb Backend Manager
    # -------------------------------------------------------------------------
    if args.command == "backend":
        provider = args.arg1.lower()
        action = args.arg2.lower()
        
        if provider != "gcp":
            print("❌ Error: Unsupported backend provider. Currently only 'gcp' is supported.", file=sys.stderr)
            sys.exit(1)
            
        if action not in ["create", "destroy"]:
            print("❌ Error: Action must be 'create' or 'destroy'. Example: vault-secret backend gcp create", file=sys.stderr)
            sys.exit(1)
            
        if not args.project_id:
            print("❌ Error: --project-id is required for backend management.", file=sys.stderr)
            sys.exit(1)

        sa_name = "vault-gcp-master"
        sa_email = f"{sa_name}@{args.project_id}.iam.gserviceaccount.com"

        # --- CREATE ACTION ---
        if action == "create":
            print(f"🚀 Initializing Zero-Touch GCP Secrets Engine...")
            
            print(f"  ├─ Creating Service Account '{sa_name}' in GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Master", "--project", args.project_id])
            
            print(f"  ├─ Granting IAM Permissions to Service Account...")
            run_gcloud(["gcloud", "projects", "add-iam-policy-binding", args.project_id, f"--member=serviceAccount:{sa_email}", "--role=roles/iam.serviceAccountAdmin", "--condition=None"])
            run_gcloud(["gcloud", "projects", "add-iam-policy-binding", args.project_id, f"--member=serviceAccount:{sa_email}", "--role=roles/iam.serviceAccountKeyAdmin", "--condition=None"])
            
            print(f"  ├─ Generating JSON Key in-memory...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", args.project_id], capture_json=True)
            
            print(f"  ├─ Configuring Vault Engine...")
            if not vault.setup_gcp_engine(creds_json=creds_json):
                print("❌ Aborting setup due to Vault engine configuration failure.", file=sys.stderr)
                sys.exit(1)
            
            print(f"  ├─ Creating 'terraform-runner' roleset...")
            bindings_hcl = f"""
              resource "//cloudresourcemanager.googleapis.com/projects/{args.project_id}" {{
                roles = ["roles/editor"]
              }}
            """
            if not vault.create_gcp_roleset(name="terraform-runner", project_id=args.project_id, bindings_hcl=bindings_hcl):
                print("❌ Aborting setup due to Vault roleset creation failure.", file=sys.stderr)
                sys.exit(1)
            
            print("\n🎉 GCP Backend successfully created!")
            sys.exit(0)

        # --- DESTROY ACTION ---
        elif action == "destroy":
            print(f"🧹 Tearing down GCP Secrets Engine & orphaned resources...")
            
            print(f"  ├─ Unmounting Vault engine...")
            vault.teardown_gcp_engine()
            
            print(f"  ├─ Deleting Master Service Account '{sa_name}' from GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", args.project_id, "--quiet"], ignore_errors=True)
            
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
            print(f"✅ Successfully wrote data to {args.path}")

    elif args.command == "read":
        data = vault.read_secret(path=secret_path, mount_point=mount_point)
        if data:
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {args.path}")

    elif args.command == "list":
        keys = vault.list_secrets(path=secret_path, mount_point=mount_point)
        if keys:
            print(f"📂 Folders/Secrets at {args.path}/:")
            for k in keys:
                print(f"  ├─ {k}")
        else:
            # Smart fallback: If list returns empty, it might be a secret. Try reading it!
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data:
                print(f"🔑 Keys inside secret payload at '{args.path}':")
                for k in data.keys():
                    print(f"  ├─ {k}")
            else:
                print(f"ℹ️ No paths or secrets found at {args.path}")

    elif args.command == "search":
        if not args.pattern:
            print("❌ Error: --pattern is required when using the search command.")
            sys.exit(1)
            
        print(f"🔍 Safely scanning for pattern '{args.pattern}' under {args.path}/ ...")
        
        found_any = False
        
        for found_path, matched_keys, path_matches, is_folder in vault.search_secrets(base_path=secret_path, search_pattern=args.pattern, mount_point=mount_point):
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
            print(f"⚠️ Could not find any paths or keys matching the pattern '{args.pattern}'.")

    elif args.command == "gcp":
        token = vault.get_gcp_token(roleset_name=secret_path, mount_point=mount_point)
        
        if token:
            print(f'export GOOGLE_OAUTH_ACCESS_TOKEN="{token}"')
            print(f"# ✅ Dynamically generated GCP Token for roleset '{secret_path}'!", file=sys.stderr)
            print("# ⏳ This token will automatically expire in 1 hour.", file=sys.stderr)
        else:
            print(f"# ❌ Failed to fetch GCP token for roleset '{secret_path}'.", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
