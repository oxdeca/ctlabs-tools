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

def run_gcloud(cmd_list, capture_json=False, ignore_errors=False, quiet=False, retries=1, retry_delay=5):
    """Silently runs a gcloud command with built-in polling/retry logic."""
    for attempt in range(1, retries + 1):
        try:
            res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
            if capture_json:
                return res.stdout.strip()
            return True
        except subprocess.CalledProcessError as e:
            # If we have retries left, wait and loop again
            if attempt < retries:
                if not quiet:
                    cmd_name = cmd_list[1] if len(cmd_list) > 1 else "command"
                    print(f"  ⏳ GCP not ready. Retrying '{cmd_name}' in {retry_delay}s (Attempt {attempt}/{retries})...")
                time.sleep(retry_delay)
                continue
            
            # If we are out of retries, handle the error
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
    # Commands
    # -------------------------------------------------------------------------

    #
    # backend
    #
    if args.command == "backend":
        provider = args.arg1.lower()
        action = args.arg2.lower()
        project_id = args.arg3  # Automatically grabbed from the command line!
        
        if provider != "gcp":
            print("❌ Error: Unsupported backend provider. Currently only 'gcp' is supported.", file=sys.stderr)
            sys.exit(1)
            
        # 1. ADDED 'list' to the allowed actions
        if action not in ["create", "destroy", "list"]:
            print("❌ Error: Action must be 'create', 'destroy', or 'list'.", file=sys.stderr)
            sys.exit(1)
            
        # 2. Made project_id strictly required ONLY for create/destroy
        if action in ["create", "destroy"] and not project_id:
            print(f"❌ Error: Project ID is required for '{action}'. Example: vault-secret backend gcp {action} <project_id>", file=sys.stderr)
            sys.exit(1)

        # 3. NEW LIST ACTION
        if action == "list":
            # Pass the dynamically captured 'provider' (e.g., 'gcp', 'aws', 'database')
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

        # 🧠 SMART MOUNT: Automatically map the mount point to gcp/<project_id>
        custom_mount = f"gcp/{project_id}"
        sa_name = "vault-gcp-master"
        sa_email = f"{sa_name}@{project_id}.iam.gserviceaccount.com"

        if action == "create":
            print(f"🚀 Initializing Zero-Touch GCP Secrets Engine at '{custom_mount}/'...")
            
            print(f"  ├─ Enabling Required GCP APIs (IAM, Resource Manager, Credentials)...")
            # Turn on the APIs, give it 3 retries just in case GCP is stuttering
            run_gcloud(["gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "iamcredentials.googleapis.com", "--project", project_id], retries=3)

            print(f"  ├─ Creating Service Account '{sa_name}' in GCP...")
            # Automatically retry 5 times if the project is still waking up
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Master", "--project", project_id], retries=5)
            
            print(f"  ├─ Granting IAM Permissions (Polling for GCP synchronization)...")
            roles_to_grant = [
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin",
                "roles/resourcemanager.projectIamAdmin"
            ]
            
            # The manual loops are gone! run_gcloud handles the polling for us.
            for role in roles_to_grant:
                run_gcloud(["gcloud", "projects", "add-iam-policy-binding", project_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True, retries=12)
            
            print(f"  ├─ Generating JSON Key in-memory...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", project_id], capture_json=True, retries=3)
            
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

    #
    # write
    #
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

    #
    # read
    #
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

    #
    # list
    #
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

    #
    # search
    #
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

    #
    # get-creds
    #
    elif args.command in ["get-creds"]:
        if path.startswith("gcp/"):
            parts = path.split('/')
            
            if len(parts) >= 3:
                roleset_name = parts[-1]
                dynamic_mount = path.rsplit('/', 1)[0]
            else:
                dynamic_mount = path
                roleset_name = args.arg2 if args.arg2 else "terraform-runner"
            
            # 1. Pure generation
            token = vault.get_gcp_token(roleset_name=roleset_name, mount_point=dynamic_mount)
            
            if token:
                print(f'export GOOGLE_OAUTH_ACCESS_TOKEN="{token}"')
                print(f"# ✅ Dynamically generated GCP Token at '{dynamic_mount}/'!", file=sys.stderr)
                # 2. Pure introspection
                metadata = vault.get_gcp_token_info(token)
                
                if metadata and "expires_in" in metadata:
                    email = metadata.get("email", f"Vault Managed Account ({roleset_name})")
                    expires_in = int(metadata.get("expires_in", 3600))
                    mins = expires_in // 60
                    
                    print(f"# 👤 Authenticated as: {email}", file=sys.stderr)
                    print(f"# ⏳ Valid for exactly {mins} minutes ({expires_in}s).", file=sys.stderr)
                    
                elif metadata and "error" in metadata:
                    # Print exactly why the introspection failed!
                    print(f"# ⚠️ Could not fetch token details from Google: {metadata['error']}", file=sys.stderr)
                else:
                    # Print the raw dictionary if Google changed their API payload
                    print(f"# ⚠️ Unexpected response from Google: {metadata}", file=sys.stderr)                
            else:
                sys.exit(1)
        else:
            print(f"❌ Error: 'get-creds' currently only supports GCP rolesets via this script.", file=sys.stderr)
            sys.exit(1)

    #
    # leases
    #
    elif args.command == "leases":
        if path.startswith("auth/") or mount_point == "auth":
            print("ℹ️  Vault Architecture Note:")
            print("   Human and Machine logins (Userpass, LDAP, AppRole) generate 'Tokens', not 'Leases'.")
            print("   To view active logins, you must list Token Accessors.")
            print("\n   Try running: vault-secret raw auth/token/accessors/")
            sys.exit(0)

        # Apply the exact same smart roleset routing to GCP leases
        if path.startswith("gcp/"):
            parts = path.split('/')
            if len(parts) >= 3:
                roleset_name = parts[-1]
                dynamic_mount = path.rsplit('/', 1)[0]
            else:
                dynamic_mount = path
                roleset_name = args.arg2 if args.arg2 else "terraform-runner"
                
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
