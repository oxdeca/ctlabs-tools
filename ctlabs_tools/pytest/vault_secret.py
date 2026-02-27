# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_secret.py
# -----------------------------------------------------------------------------
import argparse
import sys
import json
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Secret Data Manager")
    parser.add_argument("command", choices=["write", "read", "list", "search", "gcp", "raw"], help="Action to perform")
    parser.add_argument("path", help="Vault KVv2 path (e.g., kvv2/apps/my-service)")
    parser.add_argument("--data", help="JSON string of the secret data (required for write)")
    parser.add_argument("--pattern", help="Regex pattern to search for (used with search)")
    
    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault()
    
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    parts = args.path.split('/', 1)
    if len(parts) < 2:
        print("❌ Error: Path must include the mount point (e.g., kvv2/my-secret)")
        sys.exit(1)
        
    mount_point, secret_path = parts[0], parts[1]

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
        
        # Unpack the 4 variables yielded by our smarter generator
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
        # Using the helper method we added earlier
        token = vault.get_gcp_token(roleset_name=secret_path, mount_point=mount_point)
        
        if token:
            # Output the export command to stdout for shell evaluation
            print(f'export GOOGLE_OAUTH_ACCESS_TOKEN="{token}"')
            
            # Output human-friendly text to stderr so `eval` ignores it
            print(f"# ✅ Dynamically generated GCP Token for roleset '{secret_path}'!", file=sys.stderr)
            print("# ⏳ This token will automatically expire in 1 hour.", file=sys.stderr)
        else:
            print(f"# ❌ Failed to fetch GCP token for roleset '{secret_path}'.", file=sys.stderr)
            sys.exit(1)

    elif args.command == "raw":
        # We don't split the path for raw reads, we just pass the whole thing
        data = vault.read_raw_path(args.path)
        if data:
            # We print just the JSON data, perfectly formatted for GCP!
            print(json.dumps(data, indent=2))
        else:
            print(f"⚠️ No data found at {args.path}")

if __name__ == "__main__":
    main()