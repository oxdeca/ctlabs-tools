# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_login.py
# License : MIT
# -----------------------------------------------------------------------------

import os
import sys
import time
import hvac
import secrets
import argparse
import requests
import warnings
import subprocess
from getpass import getpass

# Import the new classes we built in helper.py
from .core import HashiVault, GCPSecretManager

# Suppress self-signed cert warnings
warnings.filterwarnings('ignore')

SECURE_DIR = os.path.expanduser("~/.ctlabs_vault")
os.makedirs(SECURE_DIR, mode=0o700, exist_ok=True)
KEY_FILE = os.path.join(SECURE_DIR, ".vault_key")
ENV_FILE = os.path.join(SECURE_DIR, ".env.gpg")


def get_args():
    parser = argparse.ArgumentParser(description="Vault Interactive Login Wrapper")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 1. INFO Command (Replaces --status and --details)
    subparsers.add_parser("info", help="Show details and expiration status of the currently loaded token")

    # 2. CLEAR Command (Replaces --clear)
    subparsers.add_parser("clear", help="Clear the locally cached token (logout)")

    # 3. USER Command (Human Login)
    p_user = subparsers.add_parser("user", help="Login via LDAP or Userpass")
    p_user.add_argument("username", nargs="?", help="Vault Username")
    p_user.add_argument("-p", "--password", dest="password", help="Vault Password (will prompt if omitted)")
    p_user.add_argument("-a", "--addr", dest="addr", help="Vault Server Address (overrides VAULT_ADDR env var)")

    # 4. APPROLE Command (Machine Login)
    p_approle = subparsers.add_parser("approle", help="Login via AppRole")
    p_approle.add_argument("role_id", nargs="?", help="AppRole Role ID (or GSM path)")
    p_approle.add_argument("-p", "--secret-id", dest="secret_id", help="AppRole Secret ID or GSM path (will prompt if omitted)")
    p_approle.add_argument("-a", "--addr", dest="addr", help="Vault Server Address (overrides VAULT_ADDR env var)")

    return parser.parse_args()


def get_random_passphrase(length=32):
    """Generates and stores a random passphrase for local GPG encryption."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%()-_+{}[]"
    pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
    with open(KEY_FILE, "w") as f:
        f.write(pwd)
    os.chmod(KEY_FILE, 0o600)
    return pwd


def check_vault_health(vault_addr):
    """Pings the Vault health endpoint."""
    print(f"🔍 Checking connection to {vault_addr}...")
    try:
        requests.get(f"{vault_addr}/v1/sys/health", verify=False, timeout=5)
    except Exception:
        print(f"❌ Cannot reach Vault at {vault_addr}.")
        sys.exit(1)


def resolve_gsm_secret(secret_value):
    """Checks if a string is a GSM path and unwraps it if necessary."""
    if secret_value and secret_value.startswith("projects/"):
        print(f"🔄 Detected GSM path. Fetching from Google Cloud...")
        gsm = GCPSecretManager()
        if not gsm.is_available:
            print("❌ Cannot fetch GSM secret: google-cloud-secret-manager not installed.")
            sys.exit(1)
            
        parts = secret_value.split("/")
        project = parts[1]
        secret_id = parts[3]
        version = parts[5] if len(parts) > 5 else "latest"
        
        resolved_value = gsm.get_secret(project, secret_id, version)
        if not resolved_value:
            print(f"❌ Failed to unwrap GSM secret: {secret_value}")
            sys.exit(1)
        return resolved_value
    return secret_value


def login_approle(client, role_id_input, secret_id_input):
    """Handles AppRole login, unwrapping GSM secrets if necessary."""
    role_id = role_id_input or input("Enter AppRole Role ID (or GSM path): ").strip()
    secret_id = secret_id_input or getpass("Enter AppRole Secret ID (or GSM path): ").strip()
    
    role_id = resolve_gsm_secret(role_id)
    secret_id = resolve_gsm_secret(secret_id)

    print("Attempting AppRole login...")
    try:
        res = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        if client.is_authenticated():
            return res, "AppRole"
    except Exception as e:
        print(f"❌ AppRole authentication failed: {e}")
    return None, None


def login_human(client, vault_user, vault_pass):
    """Handles LDAP and Userpass autodiscovery login."""
    user = vault_user or input("Enter Username: ").strip()
    pwd = vault_pass or os.getenv("VAULT_PASS") or getpass("Enter Password: ").strip()
    
    auth_methods = [
        ("LDAP", client.auth.ldap.login),
        ("Userpass", client.auth.userpass.login)
    ]
    
    for method_name, login_func in auth_methods:
        try:
            print(f"Attempting {method_name} login...")
            res = login_func(username=user, password=pwd, mount_point=method_name.lower())
            if client.is_authenticated():
                return res, method_name
        except Exception:
            continue
            
    print("❌ Authentication failed: Invalid credentials or unsupported method.")
    return None, None


def cache_local_token(vault_addr, token, lease_duration):
    """Encrypts and caches the token configuration for local dev tools."""
    expires_at = int(time.time()) + lease_duration
    
    secret_content = (
        f"VAULT_ADDR={vault_addr}\n"
        f"VAULT_TOKEN={token}\n"
        f"VAULT_SKIP_VERIFY=true\n"
        f"CREATED_AT={int(time.time())}\n"
        f"EXPIRES_AT={expires_at}\n"
        f"LEASE_DURATION={lease_duration}\n"
    )

    passphrase = get_random_passphrase()
    process = subprocess.Popen(
        ['gpg', '--symmetric', '--batch', '--yes', '--passphrase', passphrase, '-o', ENV_FILE],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate(input=secret_content.encode())

    if process.returncode == 0:
        print(f"🔒 Credentials securely cached to {ENV_FILE}")
        print(f"✅ Token expires in {lease_duration}s.")
    else:
        print(f"❌ GPG Error: {stderr.decode()}")


def main():
    args = get_args()
    vault = HashiVault()

    # ---------------------------------------------------------
    # 1. INFO COMMAND
    # ---------------------------------------------------------
    if args.command == "info":
        if not vault.load_secrets():
            print("ℹ️ No active Vault session found. Please log in first.")
            sys.exit(1)
            
        is_valid, remaining = vault.check_expiration()
        if remaining <= 0:
            print("❌ The locally cached token has completely expired.")
            sys.exit(1)

        hours, remainder = divmod(remaining, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        info = vault.lookup_token()
        print("\n🔐 Current Vault Token Info:")
        if info:
            display_name = info.get('display_name', 'N/A')
            
            # 🧠 SMART UX: Extract the exact AppRole name from the token metadata!
            meta = info.get('meta', {})
            if meta and 'role_name' in meta:
                if display_name == "approle":
                    display_name = f"approle-{meta['role_name']}"
                else:
                    display_name = f"{display_name}-{meta['role_name']}"

            print(f"  • Display Name : {display_name}")
            print(f"  • Policies     : {', '.join(info.get('policies', []))}")
            print(f"  • Entity ID    : {info.get('entity_id', 'N/A')}")
            print(f"  • TTL          : {info.get('creation_ttl', 'N/A')}s")
            print(f"  • Renewable    : {info.get('renewable', False)}")
        else:
            print("  ⚠️ Could not fetch details from Vault. Token may lack 'auth/token/lookup-self' permission.")
        
        print("\n⏳ Session Status:")
        if is_valid:
            print(f"  ✅ Token is valid and active.")
        else:
            print(f"  ⚠️ Token is alive but within the expiration grace period ({vault.grace_period}s).")
        print(f"  ⏱️  Time remaining: {hours}h {minutes}m {seconds}s")
        sys.exit(0)

    # ---------------------------------------------------------
    # 2. CLEAR COMMAND
    # ---------------------------------------------------------
    if args.command == "clear":
        cleared = False
        if os.path.exists(KEY_FILE):
            os.remove(KEY_FILE)
            cleared = True
        if os.path.exists(ENV_FILE):
            os.remove(ENV_FILE)
            cleared = True
            
        if cleared:
            print("🧹 Local Vault cache cleared successfully. You are now logged out.")
        else:
            print("ℹ️ No active session found to clear.")
        sys.exit(0)

    # ---------------------------------------------------------
    # 3. LOGIN COMMANDS (User, AppRole, or Interactive Fallback)
    # ---------------------------------------------------------
    
    # Smart Address Resolution: CLI Flag -> Environment Variable -> Interactive Prompt
    vault_addr = getattr(args, 'addr', None) or os.environ.get("VAULT_ADDR")
    if not vault_addr:
        vault_addr = input("Enter Vault Address (e.g., https://IP:PORT): ").strip()
        
    check_vault_health(vault_addr)
    client = hvac.Client(url=vault_addr, verify=False)
    
    login_res = None
    used_method = None

    if args.command == "approle":
        login_res, used_method = login_approle(client, args.role_id, args.secret_id)
        
    elif args.command == "user":
        login_res, used_method = login_human(client, args.username, args.password)
        
    else:
        # Fallback to interactive mode if they just type `vault-login`
        print("\nSelect Authentication Method:")
        print("1. Human (LDAP/Userpass)")
        print("2. Machine (AppRole / GSM)")
        choice = input("Choice [1/2]: ").strip()
        
        if choice == "2":
            login_res, used_method = login_approle(client, None, None)
        else:
            login_res, used_method = login_human(client, None, None)

    if not login_res:
        sys.exit(1)

    print(f"\n✅ {used_method} login successful.")

    # Extract token details
    token = login_res['auth']['client_token']
    
    # Vault sometimes returns '0' or missing lease_duration for root/special tokens
    lease_duration = login_res['auth'].get('lease_duration', 28800) 
    if lease_duration == 0: lease_duration = 28800

    # Save to Dev/Test cache so Terraform/Ansible wrappers can pick it up
    cache_local_token(vault_addr, token, lease_duration)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Login aborted by user.")
        sys.exit(1)
