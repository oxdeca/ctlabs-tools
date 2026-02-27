# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_secret.py
# -----------------------------------------------------------------------------
import argparse
import sys
import json
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Secret Data Manager")
    parser.add_argument("command", choices=["write", "read", "list", "search"], help="Action to perform")
    parser.add_argument("path", help="Vault KVv2 path (e.g., kvv2/apps/my-service)")
    parser.add_argument("--data", help="JSON string of the secret data (required for write)")
    parser.add_argument("--key", help="The specific key to search for inside secret payloads (used with search)")
    
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
        if not args.key:
            print("❌ Error: --key is required when using the search command.")
            sys.exit(1)
            
        print(f"🔍 Safely scanning for key '{args.key}' under {args.path}/ ...")
        
        found_any = False
        # The generator will print results instantly as it finds them
        for found_path in vault.search_secret_keys(base_path=secret_path, search_key=args.key, mount_point=mount_point):
            print(f"  ✅ Found in: {mount_point}/{found_path}")
            found_any = True
            
        if not found_any:
            print(f"⚠️ Could not find any secret containing the key '{args.key}'.")


if __name__ == "__main__":
    main()