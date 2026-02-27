# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_secret.py
# Purpose : CLI for creating and updating actual secret data in Vault
# -----------------------------------------------------------------------------

import argparse
import sys
import json
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Secret Data Manager")
    parser.add_argument("command", choices=["write", "read", "list"], help="Action to perform")
    parser.add_argument("path", help="Vault KVv2 path (e.g., kvv2/apps/my-service)")
    parser.add_argument("--data", help="JSON string of the secret data (required for write)")
    
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
        if keys is not None:
            if not keys:
                print(f"ℹ️ No secrets found under {args.path}/")
            else:
                print(f"📂 Keys at {args.path}/:")
                for k in keys:
                    print(f"  ├─ {k}")

if __name__ == "__main__":
    main()
