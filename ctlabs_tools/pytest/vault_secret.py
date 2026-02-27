# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_secret.py
# -----------------------------------------------------------------------------
import argparse
import sys
import json
import os
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Secret Data Manager")
    parser.add_argument("command", choices=["write", "read", "list", "search", "gcp", "raw", "setup"], help="Action to perform")
    parser.add_argument("path", nargs="?", default="", help="Vault KVv2 path (e.g., kvv2/apps/my-service). Not required for setup.")
    
    parser.add_argument("--data", help="JSON string of the secret data (required for write)")
    parser.add_argument("--pattern", help="Regex pattern to search for (used with search)")
    
    # Removed --vault-url, keeping only the GCP specific arguments
    parser.add_argument("--add-backend", choices=["gcp"], help="Initialize a new backend engine (used with setup)")
    parser.add_argument("--project-id", help="GCP Project ID (e.g., my-company-prod)")
    parser.add_argument("--project-num", help="GCP Project Number (e.g., 123456789012)")
    
    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault()
    
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    # -------------------------------------------------------------------------
    # NEW: Handle "setup" command
    # -------------------------------------------------------------------------
    if args.command == "setup":
        if args.add_backend == "gcp":
            if not all([args.project_id, args.project_num]):
                print("❌ Error: --project-id and --project-num are required to set up the GCP backend.", file=sys.stderr)
                sys.exit(1)
                
            # Dynamically grab the Vault URL from the environment or the hvac client
            vault_url = os.getenv("VAULT_ADDR")
            if not vault_url:
                client = vault._get_client()
                vault_url = client.url if client else None
                
            if not vault_url:
                print("❌ Error: Could not determine Vault URL. Please set VAULT_ADDR in your environment.", file=sys.stderr)
                sys.exit(1)
                
            print(f"🚀 Initializing GCP Workload Identity Federation on Vault at {vault_url}...")
            
            pool_name = "vault-wif-pool"
            provider_name = "vault-wif-provider"
            sa_email = f"vault-master-sa@{args.project_id}.iam.gserviceaccount.com"
            audience = f"//iam.googleapis.com/projects/{args.project_num}/locations/global/workloadIdentityPools/{pool_name}/providers/{provider_name}"
            
            bindings_hcl = f"""
              resource "//cloudresourcemanager.googleapis.com/projects/{args.project_id}" {{
                roles = ["roles/editor"]
              }}
            """
            
            # 1. OIDC Configuration
            vault.configure_oidc_issuer(issuer_url=vault_url)
            
            # 2. Enable & Configure GCP Engine for WIF
            vault.setup_gcp_wif_engine(audience=audience, sa_email=sa_email)
            
            # 3. Create the default terraform-runner roleset
            vault.create_gcp_roleset(name="terraform-runner", project_id=args.project_id, bindings_hcl=bindings_hcl)
            
            print("\n🎉 GCP Backend successfully configured!")
            print("Next steps:")
            print("  1. Export Vault's keys: vault-secret raw identity/oidc/.well-known/keys > vault-keys.json")
            print("  2. Upload them to GCP Workload Identity Provider using gcloud.")
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
