# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_totp.py
# Purpose : Dedicated CLI for Vault TOTP Secrets Engine
# -----------------------------------------------------------------------------
import argparse
import sys
import os
import json
import base64
import subprocess
from .core import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault TOTP Secrets Engine Manager")
    parser.add_argument("--timeout", type=int, default=60, help="API HTTP timeout")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. ENGINE
    p_engine = subparsers.add_parser("engine", help="Manage TOTP Secrets Engines")
    p_engine.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_engine.add_argument("path_args", nargs="*", default=["totp"], help="Mount path name (default: totp)")

    # 2. KEY
    p_key = subparsers.add_parser("key", help="Manage TOTP Keys")
    p_key.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_key.add_argument("path_args", nargs="*", default=["totp"], help="<mount>/<key> [<account_name>] [<issuer>] OR <mount> <key> [<account_name>] [<issuer>]")
    p_key.add_argument("--export", action="store_true", help="Save a QR code PNG file (when generating)")
    p_key.add_argument("--show-qr", action="store_true", help="Print the QR code directly to the terminal (requires 'qrcode' pip package)")
    p_key.add_argument("--out-dir", default=".", help="Directory to save the QR code image if exported (default: ./)")
    p_key.add_argument("--key-string", help="Explicit base64 or PEM encoded key (if not auto-generating)")
    p_key.add_argument("--url", help="A standard otpauth:// URL to import an existing key")
    p_key.add_argument("--account-name", help="Fallback flag if not provided positionally")
    p_key.add_argument("--issuer", default="Vault", help="Fallback flag if not provided positionally")
    p_key.add_argument("--period", type=int, default=30, help="Time validity period in seconds (default: 30)")
    p_key.add_argument("--digits", type=int, default=6, choices=[6, 8], help="Number of digits in the code (default: 6)")
    p_key.add_argument("--algorithm", default="SHA1", choices=["SHA1", "SHA256", "SHA512"], help="Hashing algorithm")

    # 3. CODE
    p_code = subparsers.add_parser("code", help="Generate a current TOTP code")
    p_code.add_argument("path_args", nargs="+", help="<mount>/<key> OR <mount> <key>")

    # 4. VERIFY
    p_verify = subparsers.add_parser("verify", help="Verify a TOTP code provided by a user")
    p_verify.add_argument("path_args", nargs="+", help="<mount>/<key> <code> OR <mount> <key> <code>")

    # 5. EXEC
    p_exec = subparsers.add_parser("exec", help="Generate a TOTP code, inject it into ENV, and run a command")
    p_exec.add_argument("path_args", nargs=argparse.REMAINDER, help="<mount>/<key> [--] <cmd> OR <mount> <key> [--] <cmd>")

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
        mount = args.path_args[0].strip('/') if args.path_args else 'totp'
        
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
        raw_args = args.path_args

        # 🌟 SMART PATH PARSING
        if '/' in raw_args[0]:
            mount, name = raw_args[0].split('/', 1)
            remaining = raw_args[1:]
        else:
            if action == "list":
                mount = raw_args[0]
                name = ""
                remaining = raw_args[1:]
            else:
                if len(raw_args) < 2:
                    print("❌ Error: Path must include the mount point (e.g., totp/my-key or totp my-key)")
                    sys.exit(1)
                mount = raw_args[0]
                name = raw_args[1]
                remaining = raw_args[2:]
        
        # Extract optional positionals
        account_name = args.account_name
        issuer = args.issuer
        if len(remaining) > 0:
            account_name = remaining[0]
        if len(remaining) > 1:
            issuer = remaining[1]
        
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

        if action in ["create", "update"]:
            payload = {
                "period": args.period,
                "algorithm": args.algorithm,
                "digits": args.digits
            }
            if issuer: payload["issuer"] = issuer
            if account_name: payload["account_name"] = account_name

            # Implicit Generate Logic
            if args.key_string:
                payload["key"] = args.key_string
            elif args.url:
                payload["url"] = args.url
            else:
                if not account_name:
                    print("❌ Error: 'account_name' is strictly required when generating a new key.")
                    print("Usage: vault-totp key create <mount> <key> <account_name> [issuer]")
                    sys.exit(1)
                    
                payload["generate"] = True
                payload["export"] = True # Need to tell Vault to send us the barcode payload

            print(f"🚀 {action.capitalize()}ing TOTP Key '{name}' in '{mount}/'...")
            try:
                res = client.write(f"{mount}/keys/{name}", **payload)
                print(f"✅ TOTP Key '{name}' successfully configured.")
                
                # Handle QR Code generation if we asked Vault to generate the key
                if payload.get("generate") and res and 'data' in res:
                    data = res['data']
                    url = data.get('url', '')
                    barcode = data.get('barcode', '')
                    
                    if url: print(f"  ├─ Provisioning URL : {url}")
                    
                    if args.export and barcode:
                        os.makedirs(args.out_dir, exist_ok=True)
                        qr_path = os.path.join(args.out_dir, f"totp_{name}_qr.png")
                        with open(qr_path, "wb") as f:
                            f.write(base64.b64decode(barcode))
                        print(f"  ├─ QR Code saved to : {qr_path}")
                        
                    if args.show_qr and url:
                        try:
                            import qrcode
                            print(f"\n  📱 Scan this QR Code with your Authenticator App:\n")
                            qr = qrcode.QRCode()
                            qr.add_data(url)
                            qr.make(fit=True)
                            qr.print_tty()
                            print("\n")
                        except ImportError:
                            print("  ⚠️ Cannot print QR to terminal: 'qrcode' python package is missing.")
                            print("  ℹ️ Run: pip install qrcode")

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
        raw_args = args.path_args
        if '/' in raw_args[0]:
            mount, name = raw_args[0].split('/', 1)
        else:
            if len(raw_args) < 2:
                print("❌ Error: Path must include mount point (e.g., totp/my-key or totp my-key)")
                sys.exit(1)
            mount = raw_args[0]
            name = raw_args[1]
        
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
        raw_args = args.path_args
        if '/' in raw_args[0]:
            mount, name = raw_args[0].split('/', 1)
            remaining = raw_args[1:]
        else:
            if len(raw_args) < 2:
                print("❌ Error: Path must include mount point (e.g., totp/my-key 123456 or totp my-key 123456)")
                sys.exit(1)
            mount = raw_args[0]
            name = raw_args[1]
            remaining = raw_args[2:]
            
        if not remaining:
            print("❌ Error: Missing verification code.")
            print("Usage: vault-totp verify <mount> <key> <code>")
            sys.exit(1)
            
        code = remaining[0]
        
        try:
            res = client.write(f"{mount}/code/{name}", code=code)
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

    # -------------------------------------------------------------------------
    # 5. EXEC (Ephemeral Injection)
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        raw_args = args.path_args
        if not raw_args:
            print("❌ Error: Missing arguments for exec command.")
            sys.exit(1)
            
        if '/' in raw_args[0]:
            mount, name = raw_args[0].split('/', 1)
            remaining = raw_args[1:]
        else:
            if len(raw_args) < 2:
                print("❌ Error: Path must include mount point (e.g., totp/my-key -- ./script.sh)")
                sys.exit(1)
            mount = raw_args[0]
            name = raw_args[1]
            remaining = raw_args[2:]
            
        command_list = remaining
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
            
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        try:
            # 1. Fetch the TOTP code
            res = client.read(f"{mount}/code/{name}")
            if not res or 'data' not in res or 'code' not in res['data']:
                print(f"❌ Could not generate code. Key '{name}' might not exist.", file=sys.stderr)
                sys.exit(1)
                
            code = res['data']['code']
            
            # 2. Inject into environment
            env = os.environ.copy()
            env["VAULT_TOTP_CODE"] = code
            
            print(f"🚀 Injecting TOTP code into environment (VAULT_TOTP_CODE) and running command...\n" + "-"*40, file=sys.stderr)
            
            # 3. Execute
            exit_code = subprocess.run(command_list, env=env).returncode
            sys.exit(exit_code)

        except Exception as e:
            print(f"❌ Error during exec: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()