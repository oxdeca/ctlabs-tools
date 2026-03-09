# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_totp.py
# Purpose : Dedicated CLI for Vault TOTP Secrets Engine
# -----------------------------------------------------------------------------
import argparse
import sys
import os
import json
import base64
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault TOTP Secrets Engine Manager")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. ENGINE
    p_engine = subparsers.add_parser("engine", help="Manage TOTP Secrets Engines")
    p_engine.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_engine.add_argument("mount_name", nargs="?", default="totp", help="Mount path name (default: totp)")

    # 2. KEY
    p_key = subparsers.add_parser("key", help="Manage TOTP Keys")
    p_key.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_key.add_argument("name", nargs="?", default="", help="Name of the TOTP key")
    p_key.add_argument("--mount", default="totp", help="Engine mount path (default: totp)")
    p_key.add_argument("--generate", action="store_true", help="Auto-generate the TOTP key material inside Vault")
    p_key.add_argument("--export", action="store_true", help="Return the provisioning URL and save a QR code PNG (only used with --generate)")
    p_key.add_argument("--out-dir", default=".", help="Directory to save the QR code image if exported (default: ./)")
    p_key.add_argument("--key-string", help="Explicit base64 or PEM encoded key (if not using --generate)")
    p_key.add_argument("--url", help="A standard otpauth:// URL to import an existing key")
    p_key.add_argument("--issuer", default="Vault", help="Issuer name to display in the authenticator app")
    p_key.add_argument("--account-name", help="Account name to display in the authenticator app (e.g., user@domain.com)")
    p_key.add_argument("--period", type=int, default=30, help="Time validity period in seconds (default: 30)")
    p_key.add_argument("--digits", type=int, default=6, choices=[6, 8], help="Number of digits in the code (default: 6)")
    p_key.add_argument("--algorithm", default="SHA1", choices=["SHA1", "SHA256", "SHA512"], help="Hashing algorithm")

    # 3. CODE (Generate a TOTP code)
    p_code = subparsers.add_parser("code", help="Generate a current TOTP code")
    p_code.add_argument("name", help="Name of the TOTP key")
    p_code.add_argument("--mount", default="totp", help="Engine mount path (default: totp)")

    # 4. VERIFY (Verify a TOTP code)
    p_verify = subparsers.add_parser("verify", help="Verify a TOTP code provided by a user")
    p_verify.add_argument("name", help="Name of the TOTP key")
    p_verify.add_argument("code", help="The TOTP code to verify")
    p_verify.add_argument("--mount", default="totp", help="Engine mount path (default: totp)")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command
    client = vault._get_client()

    # -------------------------------------------------------------------------
    # 1. ENGINE (TOTP Engine Mounts)
    # -------------------------------------------------------------------------
    if cmd == "engine":
        action = args.action
        mount = getattr(args, 'mount_name', 'totp').strip('/')
        
        if action == "list":
            try:
                secret_mounts = client.sys.list_mounted_secrets_engines()['data']
                engines = [p for p, info in secret_mounts.items() if info['type'] == 'totp']
                
                if engines:
                    print("🌐 Active TOTP Secrets Engines:")
                    for e in engines: 
                        print(f"  ├─ {e}")
                else:
                    print("ℹ️ No TOTP Engines mounted.")
            except Exception as e:
                print(f"❌ Error listing engines: {e}", file=sys.stderr)
            sys.exit(0)
            
        if not mount:
            print("❌ Error: Mount name is required.", file=sys.stderr)
            sys.exit(1)

        if action == "create":
            print(f"🚀 Enabling TOTP Engine at '{mount}/'...")
            try:
                current_mounts = client.sys.list_mounted_secrets_engines()['data']
                if f"{mount}/" not in current_mounts:
                    client.sys.enable_secrets_engine('totp', path=mount)
                    print(f"🎉 TOTP Engine successfully enabled at '{mount}/'")
                else:
                    print(f"ℹ️ Engine is already mounted at '{mount}/'")
            except Exception as e:
                print(f"❌ Error setting up TOTP engine: {e}", file=sys.stderr)
                
        elif action == "read" or action == "info":
            try:
                config_res = client.sys.read_mount_configuration(path=mount)
                if config_res and 'data' in config_res:
                    if action == "read":
                        print(json.dumps(config_res['data'], indent=2))
                    else:
                        print(f"🏛️ TOTP Engine Mount: {mount}/")
                        print(f"  ├─ Default Lease TTL : {config_res['data'].get('default_lease_ttl', 'System Default')}")
                        print(f"  ├─ Max Lease TTL     : {config_res['data'].get('max_lease_ttl', 'System Default')}")
                else:
                    print(f"❌ Could not read config for '{mount}/'")
            except Exception as e:
                print(f"❌ Error reading TOTP engine config: {e}", file=sys.stderr)

        elif action == "update":
            print("ℹ️ Update action requires sys/mount tuning. Destroy and recreate, or update keys instead.")

        elif action == "delete":
            print(f"🧹 Tearing down TOTP engine at '{mount}/'...")
            try:
                client.sys.disable_secrets_engine(path=mount)
                print(f"🎉 TOTP Engine destroyed!")
            except Exception as e:
                print(f"❌ Error deleting engine: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 2. KEY
    # -------------------------------------------------------------------------
    elif cmd == "key":
        action = args.action
        mount = getattr(args, 'mount', 'totp').strip('/')
        name = getattr(args, 'name', '')
        
        if action == "list":
            try:
                res = client.list(f"{mount}/keys")
                keys = res.get('data', {}).get('keys', []) if res else []
                if keys:
                    print(f"🔑 Active TOTP Keys at '{mount}/':")
                    for k in keys: print(f"  ├─ {k}")
                else:
                    print(f"ℹ️ No TOTP keys found at '{mount}/'.")
            except Exception as e:
                if "404" not in str(e): print(f"❌ Error listing TOTP keys: {e}", file=sys.stderr)
                else: print(f"ℹ️ No TOTP keys found at '{mount}/'.")
            sys.exit(0)
            
        if not name:
            print(f"❌ Error: Key name is required for '{action}'.", file=sys.stderr)
            sys.exit(1)

        if action in ["create", "update"]:
            payload = {
                "issuer": args.issuer,
                "period": args.period,
                "algorithm": args.algorithm,
                "digits": args.digits
            }
            if args.account_name: payload["account_name"] = args.account_name
            if args.generate:
                payload["generate"] = True
                payload["export"] = args.export
            elif args.key_string:
                payload["key"] = args.key_string
            elif args.url:
                payload["url"] = args.url
            else:
                print("❌ Error: You must provide --generate, --key-string, or --url to create a key.", file=sys.stderr)
                sys.exit(1)

            print(f"🚀 {action.capitalize()}ing TOTP Key '{name}' in '{mount}/'...")
            try:
                res = client.write(f"{mount}/keys/{name}", **payload)
                print(f"✅ TOTP Key '{name}' successfully configured.")
                
                # If exported, unpack the payload and write out the QR code
                if args.generate and args.export and res and 'data' in res:
                    data = res['data']
                    url = data.get('url', '')
                    barcode = data.get('barcode', '')
                    
                    if url: print(f"  ├─ Provisioning URL : {url}")
                    
                    if barcode:
                        os.makedirs(args.out_dir, exist_ok=True)
                        qr_path = os.path.join(args.out_dir, f"totp_{name}_qr.png")
                        with open(qr_path, "wb") as f:
                            f.write(base64.b64decode(barcode))
                        print(f"  ├─ QR Code saved to : {qr_path}")
                        print(f"  ℹ️  (Scan this QR code with Google Authenticator or Authy)")

            except Exception as e:
                print(f"❌ Error configuring TOTP key: {e}", file=sys.stderr)
                
        elif action == "read":
            try:
                res = client.read(f"{mount}/keys/{name}")
                if res and 'data' in res:
                    print(json.dumps(res['data'], indent=2))
                else: print(f"❌ Key '{name}' not found.")
            except Exception as e:
                print(f"❌ Error reading key: {e}", file=sys.stderr)
                
        elif action == "info":
            try:
                res = client.read(f"{mount}/keys/{name}")
                if res and 'data' in res:
                    d = res['data']
                    print(f"📱 TOTP Key: {name}")
                    print(f"  ├─ Engine Mount : {mount}/")
                    print(f"  ├─ Issuer       : {d.get('issuer', 'None')}")
                    print(f"  ├─ Account Name : {d.get('account_name', 'None')}")
                    print(f"  ├─ Algorithm    : {d.get('algorithm', 'Unknown')}")
                    print(f"  ├─ Digits       : {d.get('digits', 'Unknown')}")
                    print(f"  ├─ Period       : {d.get('period', 'Unknown')}s")
                else: print(f"❌ Key '{name}' not found in '{mount}/'.")
            except Exception as e:
                print(f"❌ Error fetching key info: {e}", file=sys.stderr)
                
        elif action == "delete":
            try:
                client.delete(f"{mount}/keys/{name}")
                print(f"✅ Deleted TOTP key '{name}' from '{mount}/'.")
            except Exception as e:
                print(f"❌ Error deleting TOTP key: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 3. CODE (Generate TOTP)
    # -------------------------------------------------------------------------
    elif cmd == "code":
        mount = getattr(args, 'mount', 'totp').strip('/')
        name = args.name
        
        try:
            res = client.read(f"{mount}/code/{name}")
            if res and 'data' in res and 'code' in res['data']:
                code = res['data']['code']
                print(f"⏳ Current TOTP Code for '{name}':")
                print(f"\n      [ {code} ]\n")
            else:
                print(f"❌ Could not generate code. Key '{name}' might not exist.", file=sys.stderr)
        except Exception as e:
            print(f"❌ Error generating TOTP code: {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 4. VERIFY (Verify a TOTP Code)
    # -------------------------------------------------------------------------
    elif cmd == "verify":
        mount = getattr(args, 'mount', 'totp').strip('/')
        name = args.name
        code = args.code
        
        try:
            res = client.write(f"{mount}/verify/{name}", code=code)
            if res and 'data' in res:
                is_valid = res['data'].get('valid', False)
                if is_valid:
                    print(f"✅ SUCCESS: TOTP Code '{code}' is VALID for key '{name}'.")
                    sys.exit(0)
                else:
                    print(f"❌ REJECTED: TOTP Code '{code}' is INVALID or EXPIRED for key '{name}'.", file=sys.stderr)
                    sys.exit(1)
            else:
                print(f"⚠️ Unexpected response from Vault.", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"❌ Error verifying TOTP code: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
