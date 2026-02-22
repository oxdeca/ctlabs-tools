# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_login.py
# License : MIT
# -----------------------------------------------------------------------------

import hvac
import os
import time
import warnings
import secrets
import subprocess
import argparse
import requests
from getpass import getpass

# Suppress self-signed cert warnings
warnings.filterwarnings('ignore')

SECURE_DIR = os.path.expanduser("~/.ctlabs_vault")
os.makedirs(SECURE_DIR, mode=0o700, exist_ok=True)
KEY_FILE = os.path.join(SECURE_DIR, ".vault_key")
ENV_FILE = os.path.join(SECURE_DIR, ".env.gpg")

def get_args():
    parser = argparse.ArgumentParser(description="Vault Login Wrapper")
    parser.add_argument("-a", "--addr", help="Vault Server Address")
    parser.add_argument("-u", "--user", help="Vault Username")
    parser.add_argument("-p", "--password", help="Vault Password")
    return parser.parse_args()

def get_random_passphrase(length=32):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%()-_+{}[]"
    pwd = ''.join(secrets.choice(alphabet) for i in range(length))
    with open(KEY_FILE, "w") as f:
        f.write(pwd)
    os.chmod(KEY_FILE, 0o600)
    return pwd

def main():
    args = get_args()
    vault_addr = args.addr or input("Enter Vault Address (https://IP:PORT): ").strip()
    
    print(f"🔍 Checking connection to {vault_addr}...")
    try:
        requests.get(f"{vault_addr}/v1/sys/health", verify=False, timeout=5)
    except Exception:
        print(f"❌ Cannot reach Vault at {vault_addr}.")
        exit(1)

    vault_user = args.user or input("Enter Username: ")
    vault_pass = args.password or os.getenv("VAULT_PASS") or getpass("Enter Password: ")
    
    client = hvac.Client(url=vault_addr, verify=False)
    
    # --- Autodiscovery Logic ---
    auth_methods = [
        ("LDAP", client.auth.ldap.login),
        ("Userpass", client.auth.userpass.login)
    ]
    
    login_res   = None
    used_method = None

    for method_name, login_func in auth_methods:
        try:
            print(f"Attempting {method_name} login...")
            login_res = login_func(
                username=vault_user, 
                password=vault_pass, 
                mount_point=method_name.lower()
            )
            if client.is_authenticated():
                used_method = method_name
                break
        except Exception:
            continue # Try next method

    if not client.is_authenticated():
        print("❌ Authentication failed: Invalid credentials or unsupported method.")
        return

    # --- Sync Timeout with Vault ---
    token = login_res['auth']['client_token']
    lease_duration = login_res['auth']['lease_duration'] # Duration in seconds
    expires_at = int(time.time()) + lease_duration
    
    print(f"✅ {used_method} login successful. Token expires in {lease_duration}s.")

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
        print(f"🔒 Secrets encrypted to {ENV_FILE}")
    else:
        print(f"❌ GPG Error: {stderr.decode()}")

if __name__ == "__main__":
    main()
