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
from helper import HashiVault, GCPSecretManager

# Suppress self-signed cert warnings
warnings.filterwarnings('ignore')

SECURE_DIR = os.path.expanduser("~/.ctlabs_vault")
os.makedirs(SECURE_DIR, mode=0o700, exist_ok=True)
KEY_FILE = os.path.join(SECURE_DIR, ".vault_key")
ENV_FILE = os.path.join(SECURE_DIR, ".env.gpg")

def get_args():
    parser = argparse.ArgumentParser(description="Vault Interactive Login Wrapper")
    parser.add_argument("-a", "--addr", help="Vault Server Address (e.g., https://IP:PORT)")
    
    # Human Auth
    parser.add_argument("-u", "--user", help="Vault Username (LDAP/Userpass)")
    parser.add_argument("-p", "--password", help="Vault Password")
    
    # Machine Auth
    parser.add_argument("--approle", action="store_true", help="Use AppRole authentication instead of userpass")
    parser.add_argument("--role-id", help="AppRole Role ID (or GCP Secret Manager path)")
    parser.add_argument("--secret-id", help="AppRole Secret ID (or GCP Secret Manager path)")
    
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
            
        # Extract project and secret details from path: projects/PROJECT/secrets/SECRET/versions/VERSION
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
    
    # Resolve through GSM if the user provided GCP paths
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
    vault_addr = args.addr or input("Enter Vault Address (e.g., https://IP:PORT): ").strip()
    
    check_vault_health(vault_addr)
    
    client = hvac.Client(url=vault_addr, verify=False)
    login_res = None
    used_method = None

    # Determine workflow based on flags or interactive prompt
    if args.approle:
        login_res, used_method = login_approle(client, args.role_id, args.secret_id)
    elif args.user or args.password:
        login_res, used_method = login_human(client, args.user, args.password)
    else:
        # Ask interactively if no flags provided
        print("\nSelect Authentication Method:")
        print("1. Human (LDAP/Userpass)")
        print("2. Machine (AppRole / GSM)")
        choice = input("Choice [1/2]: ").strip()
        
        if choice == "2":
            login_res, used_method = login_approle(client, args.role_id, args.secret_id)
        else:
            login_res, used_method = login_human(client, args.user, args.password)

    if not login_res:
        sys.exit(1)

    print(f"\n✅ {used_method} login successful.")

    # Extract token details
    token = login_res['auth']['client_token']
    
    # Vault sometimes returns '0' or missing lease_duration for root/special tokens
    # Defaulting to 8 hours (28800s) if missing
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
