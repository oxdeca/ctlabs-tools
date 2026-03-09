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
    p_raw.add_argument("path_args", nargs="+", help="The exact Vault API path")

    # WRITE
    p_write = subparsers.add_parser("write", help="Write a static secret payload")
    p_write.add_argument("path_args", nargs="+", help="Supports: <mount>/<path> or <mount> <path>")
    p_write.add_argument("--data", required=True, help="JSON string of the secret data")

    # READ
    p_read = subparsers.add_parser("read", help="Read a static secret payload or a specific key")
    p_read.add_argument("path_args", nargs="+", help="Supports: <mount>/<path>, <mount> <path> <key>, or <mount>/<path>/<key>")

    # LIST
    p_list = subparsers.add_parser("list", help="List folders or secret keys")
    p_list.add_argument("path_args", nargs="+", help="Supports: <mount>/<path> or <mount> <path>")

    # SEARCH
    p_search = subparsers.add_parser("search", help="Search folders, secrets, and payload keys")
    p_search.add_argument("path_args", nargs="+", help="The base Vault path to search")
    p_search.add_argument("pattern", help="Regex pattern to search for")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # 🌟 SMART TOKEN PARSER
    # This takes any combination of spaces and slashes and normalizes them into a standard path
    raw_tokens = []
    for arg in args.path_args:
        raw_tokens.extend([t for t in arg.split('/') if t])
    raw_path = "/".join(raw_tokens)

    if cmd == "raw":
        data = vault.read_raw_path(raw_path)
        if data: print(json.dumps(data, indent=2))
        else: print(f"⚠️ No data found at {raw_path}")
        sys.exit(0)

    parts = raw_path.split('/', 1)
    
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
            print(f"✅ Successfully wrote data to {raw_path}")

    elif cmd == "read":
        if mount_point in ["sys", "auth", "identity", "pki", "transit"]:
            data = vault.read_raw_path(raw_path)
            if data: print(json.dumps(data, indent=2))
            else: print(f"⚠️ No data found at {raw_path}")
        else:
            # 🚀 ATTEMPT 1: Assume the full path points directly to a secret
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            
            if data is not None:
                # The path was a full secret, print the whole JSON payload
                print(json.dumps(data, indent=2))
            else:
                # 🚀 ATTEMPT 2 (Fallback): Assume the last word in the path is actually a KEY
                if '/' in secret_path:
                    parent_path, key = secret_path.rsplit('/', 1)
                    parent_data = vault.read_secret(path=parent_path, mount_point=mount_point)
                    
                    if parent_data is not None and key in parent_data:
                        val = parent_data[key]
                        # If the key points to a simple string/int, print it raw so bash can capture it!
                        if isinstance(val, (dict, list)):
                            print(json.dumps(val, indent=2))
                        else:
                            print(val)
                    else:
                        # 🚀 ATTEMPT 3 (Deep Fallback): Check if it's a raw engine path (like metadata)
                        raw_data = vault.read_raw_path(raw_path)
                        if raw_data:
                            print(json.dumps(raw_data, indent=2))
                        else:
                            print(f"⚠️ No secret or key '{key}' found at {raw_path}")
                else:
                    # Single token secret path fallback
                    raw_data = vault.read_raw_path(raw_path)
                    if raw_data:
                        print(json.dumps(raw_data, indent=2))
                    else:
                        print(f"⚠️ No data found at {raw_path}")

    elif cmd == "list":
        keys = vault.list_secrets(path=secret_path, mount_point=mount_point)
        if keys:
            display_path = f"{mount_point}/{secret_path}" if secret_path else f"{mount_point}/"
            print(f"📂 Folders/Secrets at {display_path}:")
            for k in keys: print(f"  ├─ {k}")
        else:
            data = vault.read_secret(path=secret_path, mount_point=mount_point)
            if data:
                print(f"🔑 Keys inside secret payload at '{raw_path}':")
                for k in data.keys(): print(f"  ├─ {k}")
            else:
                print(f"ℹ️ No paths or secrets found at {raw_path}")

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
