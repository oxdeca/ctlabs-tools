# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_secret.py
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import os
import subprocess
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Secret Data Manager")
    parser.add_argument("command", choices=["write", "read", "list", "search", "gcp", "raw", "setup"], help="Action to perform")
    parser.add_argument("path", nargs="?", default="", help="Vault KVv2 path. Not required for setup.")
    
    parser.add_argument("--data", help="JSON string of the secret data (required for write)")
    parser.add_argument("--pattern", help="Regex pattern to search for (used with search)")
    
    # NEW: Only requires the project ID now!
    parser.add_argument("--add-backend", choices=["gcp"], help="Initialize a new backend engine (used with setup)")
    parser.add_argument("--project-id", help="GCP Project ID (e.g., ctlabs-0815-123abc-05b-03)")
    
    return parser.parse_args()

def run_gcloud(cmd_list, capture_json=False):
    """Silently runs a gcloud command and halts if it fails."""
    try:
        # If we need the JSON, we capture stdout. Otherwise, we let it run silently.
        res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        if capture_json:
            # gcloud sometimes prints warnings to stderr, so we strictly parse stdout for the JSON
            return res.stdout.strip()
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ GCP Command Failed: {' '.join(cmd_list)}", file=sys.stderr)
        print(f"Error output: {e.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

def main():
    args = get_args()
    vault = HashiVault()
    
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    # -------------------------------------------------------------------------
    # NEW: Zero-Touch Setup Command
    # -------------------------------------------------------------------------
    if args.command == "setup":
        if args.add_backend == "gcp":
            if not args.project_id:
                print("❌ Error: --project-id is required to set up the GCP backend.", file=sys.stderr)
                sys.exit(1)
                
            sa_name = "vault-gcp-master"
            sa_email = f"{sa_name}@{args.project_id}.iam.gserviceaccount.com"
            
            print(f"🚀 Initializing Zero-Touch GCP Secrets Engine...")
            
            # 1. Create the Service Account in GCP
            print(f"  ├─ Creating Service Account '{sa_name}' in GCP...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Master", "--project", args.project_id])
            
            # 2. Grant Permissions
            print(f"  ├─ Granting IAM Permissions to Service Account...")
            run_gcloud(["gcloud", "projects", "add-iam-policy-binding", args.project_id, f"--member=serviceAccount:{sa_email}", "--role=roles/iam.serviceAccountAdmin", "--condition=None"])
            run_gcloud(["gcloud", "projects", "add-iam-policy-binding", args.project_id, f"--member=serviceAccount:{sa_email}", "--role=roles/iam.serviceAccountKeyAdmin", "--condition=None"])
            
            # 3. Generate the Key directly into Python RAM (Using '-' as the output file)
            print(f"  ├─ Generating JSON Key in-memory...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", args.project_id], capture_json=True)
            
            # 4. Configure Vault Engine
            print(f"  ├─ Configuring Vault Engine...")
            if not vault.setup_gcp_engine(creds_json=creds_json):
                print("❌ Aborting setup due to Vault engine configuration failure.", file=sys.stderr)
                sys.exit(1)
            
            # 5. Create the Roleset
            print(f"  ├─ Creating 'terraform-runner' roleset...")
            bindings_hcl = f"""
              resource "//cloudresourcemanager.googleapis.com/projects/{args.project_id}" {{
                roles = ["roles/editor"]
              }}
            """
            if not vault.create_gcp_roleset(name="terraform-runner", project_id=args.project_id, bindings_hcl=bindings_hcl):
                print("❌ Aborting setup due to Vault roleset creation failure.", file=sys.stderr)
                sys.exit(1)
            
            print("\n🎉 GCP Backend successfully configured using Zero-Touch provisioning!")
            print("Your Vault cluster is now managing dynamic Google Cloud credentials.")
            sys.exit(0)
            
        else:
            print("❌ Error: Please specify a backend to setup, e.g., --add-backend gcp", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # VALIDATION: All other commands require a valid path
    # -------------------------------------------------------------------------
    if not args.path:
        print("❌ Error: 'path' is required for this command.", file=sys.stderr)
        sys.exit(1)

    if args.command == "raw":
        # Raw commands use the exact path without splitting mount points
        data = vault.read_raw_path(args.path)
        if data:
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {args.path}")
        sys.exit(0)

    # For standard Vault operations, split the mount point from the secret path
    parts = args.path.split('/', 1)
    if len(parts) < 2:
        print("❌ Error: Path must include the mount point (e.g., kvv2/my-secret)")
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
