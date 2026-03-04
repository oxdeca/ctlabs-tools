# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_secret.py
# Purpose : Dedicated CLI for Vault KV Secrets & Raw Data Management
# -----------------------------------------------------------------------------
import argparse
import sys
import json
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault Static Secret Data Manager")
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # RAW API
    p_raw = subparsers.add_parser("raw", help="Read raw JSON from any Vault API path")
    p_raw.add_argument("path", help="The exact Vault API path")

    # WRITE
    p_write = subparsers.add_parser("write", help="Write a static secret payload")
    p_write.add_argument("path", help="The Vault path (e.g., kvv2/apps/my-secret)")
    p_write.add_argument("--data", required=True, help="JSON string of the secret data")

    # READ
    p_read = subparsers.add_parser("read", help="Read a static secret payload")
    p_read.add_argument("path", help="The Vault path (e.g., kvv2/apps/my-secret)")

    # LIST
    p_list = subparsers.add_parser("list", help="List folders or secret keys")
    p_list.add_argument("path", help="The Vault path (e.g., kvv2/apps)")

    # SEARCH
    p_search = subparsers.add_parser("search", help="Search folders, secrets, and payload keys")
    p_search.add_argument("path", help="The base Vault path to search")
    p_search.add_argument("pattern", help="Regex pattern to search for")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    if cmd == "raw":
        data = vault.read_raw_path(args.path)
        if data: print(json.dumps(data, indent=2))
        else: print(f"⚠️ No data found at {args.path}")
        sys.exit(0)

    # 🌟 NEW SMART PARSING BLOCK
    parts = args.path.split('/', 1)
    
    if len(parts) == 1:
        # Allow both 'list' and 'search' to run on the root mount point without a slash!
        if cmd in ["list", "search"]:
            mount_point = parts[0]
            secret_path = ""
        else:
            print("❌ Error: For read/write, path must include the mount point (e.g., kvv2/my-secret)")
            sys.exit(1)
    else:
        mount_point = parts[0]
        secret_path = parts[1]

    if cmd == "write":
        try:
            secret_dict = json.loads(args.data)
        except json.JSONDecodeError:
            print("❌ Error: --data must be a valid JSON string.")
            sys.exit(1)
            
        if vault.write_secret(path=secret_path, secret_data=secret_dict, mount_point=mount_point):
            print(f"✅ Successfully wrote data to {args.path}")

    elif cmd == "read":
        if mount_point in ["sys", "auth", "identity", "pki", "transit"]:
            data = vault.read_raw_path(args.path)
        else:
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data is None: data = vault.read_raw_path(args.path)

        if data: print(json.dumps(data, indent=2))
        else: print(f"⚠️ No data found at {args.path}")

    elif cmd == "list":
        keys = vault.list_secrets(path=secret_path, mount_point=mount_point)
        if keys:
            display_path = f"{mount_point}/{secret_path}" if secret_path else f"{mount_point}/"
            print(f"📂 Folders/Secrets at {display_path}:")
            for k in keys: print(f"  ├─ {k}")
        else:
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data:
                print(f"🔑 Keys inside secret payload at '{args.path}':")
                for k in data.keys(): print(f"  ├─ {k}")
            else:
                print(f"ℹ️ No paths or secrets found at {args.path}")

    elif cmd == "search":
        display_path = f"{mount_point}/{secret_path}" if secret_path else f"{mount_point}/"
        print(f"🔍 Scanning for '{args.pattern}' under {display_path} ...")
        found = False
        for found_path, matched_keys, path_matches, is_folder in vault.search_secrets(base_path=secret_path, search_pattern=args.pattern, mount_point=mount_point):
            if is_folder:
                print(f"  📁 {mount_point}/{found_path} ➜ [Folder]")
            else:
                types = []
                if path_matches: types.append("Path Match")
                if matched_keys: types.append(f"Key Matches: {', '.join(matched_keys)}")
                print(f"  📄 {mount_point}/{found_path} ➜ [{' | '.join(types)}]")
            found = True
        if not found:
            print(f"⚠️ Nothing found matching '{args.pattern}'.")

if __name__ == "__main__":
    main()
