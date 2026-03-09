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
    p_engine.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_engine.add_argument("path_args", nargs="*", default=["totp"], help="Mount path name (default: totp)")

    # 2. KEY
    p_key = subparsers.add_parser("key", help="Manage TOTP Keys")
    p_key.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"])
    p_key.add_argument("path_args", nargs="*", default=["totp"], help="<mount>/<key> [<account_name>] [<issuer>] OR <mount> <key> [<account_name>] [<issuer>]")
    p_key.add_argument("--export", action="store_true", help="Save a QR code PNG file (when generating)")
    p_key.add_argument("--show-qr", action="store_true", help="Print the QR code directly to the terminal")
    p_key.add_argument("--out-dir", default=".", help="Directory to save the QR code image if exported")
    p_key.add_argument("--key-string", help="Explicit base64 or PEM encoded key (if not auto-generating)")
    p_key.add_argument("--url", help="A standard otpauth:// URL to import an existing key")
    p_key.add_argument("--account-name", help="Fallback flag if not provided positionally")
    p_key.add_argument("--issuer", default="Vault", help="Fallback flag if not provided positionally")
    p_key.add_argument("--period", type=int, default=30, help="Time validity period in seconds (default: 30)")
    p_key.add_argument("--digits", type=int, default=6, choices=[6, 8], help="Number of digits in the code")
    p_key.add_argument("--algorithm", default="SHA1", choices=["SHA1", "SHA256", "SHA512"])

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

    # -------------------------------------------------------------------------
    # 1. ENGINE
    # -------------------------------------------------------------------------
    if cmd == "engine":
        action = args.action
        mount = args.path_args[0].strip('/') if args.path_args else 'totp'
        
        if action == "list":
            engines = vault.list_engines(backend_type="totp")
            if engines:
                print("🌐 Active TOTP Secrets Engines:")
                for e in engines: print(f"  ├─ {e}")
            else: print("ℹ️ No TOTP Engines mounted.")
            sys.exit(0)

        if action == "create":
            print(f"🚀 Enabling TOTP Engine at '{mount}/'...")
            if vault.setup_totp_engine(mount):
                print(f"🎉 TOTP Engine successfully enabled at '{mount}/'")
                
        elif action in ["read", "info"]:
            config = vault.read_totp_engine_config(mount)
            if config:
                if action == "read":
                    print(json.dumps(config, indent=2))
                else:
                    print(f"🏛️ TOTP Engine Mount: {mount}/")
                    print(f"  ├─ Default Lease TTL : {config.get('default_lease_ttl', 'System Default')}")
                    print(f"  ├─ Max Lease TTL     : {config.get('max_lease_ttl', 'System Default')}")
            else:
                print(f"❌ Could not read config for '{mount}/'")

        elif action == "update":
            print("ℹ️ Update action requires sys/mount tuning. Destroy and recreate, or update keys instead.")

        elif action == "delete":
            print(f"🧹 Tearing down TOTP engine at '{mount}/'...")
            if vault.teardown_totp_engine(mount):
                print(f"🎉 TOTP Engine destroyed!")

    # -------------------------------------------------------------------------
    # 2. KEY
    # -------------------------------------------------------------------------
    elif cmd == "key":
        action = args.action
        raw_args = args.path_args

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
                    sys.exit("❌ Error: Path must include the mount point (e.g., totp/my-key or totp my-key)")
                mount = raw_args[0]
                name = raw_args[1]
                remaining = raw_args[2:]
        
        account_name = args.account_name
        issuer = args.issuer
        if len(remaining) > 0: account_name = remaining[0]
        if len(remaining) > 1: issuer = remaining[1]
        
        if action == "list":
            keys = vault.list_totp_keys(mount)
            if keys:
                print(f"🔑 Active TOTP Keys at '{mount}/':")
                for k in keys: print(f"  ├─ {k}")
            else: print(f"ℹ️ No TOTP keys found at '{mount}/'.")
            sys.exit(0)

        if action in ["create", "update"]:
            payload = {"period": args.period, "algorithm": args.algorithm, "digits": args.digits}
            if issuer: payload["issuer"] = issuer
            if account_name: payload["account_name"] = account_name

            if args.key_string:
                payload["key"] = args.key_string
            elif args.url:
                payload["url"] = args.url
            else:
                if not account_name:
                    print("❌ Error: 'account_name' is strictly required when generating a new key.")
                    sys.exit(1)
                payload["generate"] = True
                payload["export"] = True 

            print(f"🚀 {action.capitalize()}ing TOTP Key '{name}' in '{mount}/'...")
            res = vault.create_totp_key(name, mount, **payload)
            
            if res:
                print(f"✅ TOTP Key '{name}' successfully configured.")
                if payload.get("generate") and isinstance(res, dict):
                    url = res.get('url', '')
                    barcode = res.get('barcode', '')
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
                
        elif action == "read":
            data = vault.read_totp_key(name, mount)
            if data: print(json.dumps(data, indent=2))
            else: print(f"❌ Key '{name}' not found.")
                
        elif action == "info":
            d = vault.read_totp_key(name, mount)
            if d:
                print(f"📱 TOTP Key: {name}")
                print(f"  ├─ Engine Mount : {mount}/")
                print(f"  ├─ Issuer       : {d.get('issuer', 'None')}")
                print(f"  ├─ Account Name : {d.get('account_name', 'None')}")
                print(f"  ├─ Algorithm    : {d.get('algorithm', 'Unknown')}")
                print(f"  ├─ Digits       : {d.get('digits', 'Unknown')}")
                print(f"  ├─ Period       : {d.get('period', 'Unknown')}s")
            else: print(f"❌ Key '{name}' not found.")
                
        elif action == "delete":
            if vault.delete_totp_key(name, mount):
                print(f"✅ Deleted TOTP key '{name}' from '{mount}/'.")

    # -------------------------------------------------------------------------
    # 3. CODE
    # -------------------------------------------------------------------------
    elif cmd == "code":
        raw_args = args.path_args
        if '/' in raw_args[0]: mount, name = raw_args[0].split('/', 1)
        else: mount, name = raw_args[0], raw_args[1]
        
        code = vault.generate_totp_code(name, mount)
        if code:
            print(f"⏳ Current TOTP Code for '{name}':")
            print(f"\n      [ {code} ]\n")
        else:
            print(f"❌ Could not generate code. Key '{name}' might not exist.", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 4. VERIFY
    # -------------------------------------------------------------------------
    elif cmd == "verify":
        raw_args = args.path_args
        if '/' in raw_args[0]:
            mount, name = raw_args[0].split('/', 1)
            remaining = raw_args[1:]
        else:
            mount, name = raw_args[0], raw_args[1]
            remaining = raw_args[2:]
            
        if not remaining: sys.exit("❌ Error: Missing verification code.")
        code = remaining[0]
        
        is_valid, err_msg = vault.verify_totp_code(name, code, mount)
        if is_valid:
            print(f"✅ SUCCESS: TOTP Code '{code}' is VALID for key '{name}'.")
            sys.exit(0)
        else:
            print(f"❌ REJECTED: TOTP Code '{code}' is INVALID or EXPIRED for key '{name}'.", file=sys.stderr)
            if err_msg: print(f"  └─ {err_msg}", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 5. EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        raw_args = args.path_args
        if '/' in raw_args[0]:
            mount, name = raw_args[0].split('/', 1)
            remaining = raw_args[1:]
        else:
            mount, name = raw_args[0], raw_args[1]
            remaining = raw_args[2:]
            
        command_list = remaining[1:] if remaining and remaining[0] == "--" else remaining
        if not command_list: sys.exit("❌ Error: No command provided to execute.")

        code = vault.generate_totp_code(name, mount)
        if not code: sys.exit(1)
            
        env = os.environ.copy()
        env["VAULT_TOTP_CODE"] = code
        print(f"🚀 Injecting TOTP code into environment (VAULT_TOTP_CODE) and running command...\n" + "-"*40, file=sys.stderr)
        
        try:
            exit_code = subprocess.run(command_list, env=env).returncode
            sys.exit(exit_code)
        except Exception as e:
            print(f"❌ Error during exec: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
