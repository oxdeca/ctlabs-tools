# -----------------------------------------------------------------------------
# File    : ctlabs-tools/pytest/vault_login.py
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

# Suppress self-signed cert warnings for lab use
warnings.filterwarnings('ignore')

# Store secrets in a persistent hidden folder in the root or user home
SECURE_DIR = os.path.expanduser("~/.vault_cache")
os.makedirs(SECURE_DIR, mode=0o700, exist_ok=True)

KEY_FILE = os.path.join(SECURE_DIR, ".vault_key")
ENV_FILE = os.path.join(SECURE_DIR, ".env.gpg")

def get_args():
    parser = argparse.ArgumentParser(description="Vault Login Wrapper")
    # Removed default so it forces input or flag
    parser.add_argument("-a", "--addr", help="Vault Server Address (e.g., https://1.2.3.4:8200)")
    parser.add_argument("-m", "--method", choices=["1", "2"], help="Auth Method: 1 for LDAP, 2 for Userpass")
    parser.add_argument("-u", "--user", help="Vault Username")
    parser.add_argument("-p", "--password", help="Vault Password")
    return parser.parse_args()

def get_random_passphrase(length=32):
    """Generates a secure random string and saves it to a hidden file."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%()-_+{}[]"
    pwd = ''.join(secrets.choice(alphabet) for i in range(length))
    with open(KEY_FILE, "w") as f:
        f.write(pwd)
    os.chmod(KEY_FILE, 0o600)
    return pwd

# --- Logic Start ---

args = get_args()

# 1. Resolve Vault Address
vault_addr = args.addr or input("Enter Vault Address (https://IP:PORT): ").strip()

# Pre-flight check: Verify Vault is reachable
print(f"🔍 Checking connection to {vault_addr}...")
try:
    requests.get(f"{vault_addr}/v1/sys/health", verify=False, timeout=5)
except Exception as e:
    print(f"❌ Cannot reach Vault at {vault_addr}. Check the IP/Port and VPN.")
    exit(1)

# 2. Resolve Credentials
auth_type  = args.method or input("Choose Auth Method (1 for LDAP, 2 for Userpass): ").strip()
vault_user = args.user or input("Enter Username: ")
vault_pass = args.password or os.getenv("VAULT_PASS") or getpass("Enter Password: ")

client = hvac.Client(url=vault_addr, verify=False)

try:
    # 3. Perform Authentication
    if auth_type == "1":
        res = client.auth.ldap.login(username=vault_user, password=vault_pass, mount_point="ldap")
    else:
        res = client.auth.userpass.login(username=vault_user, password=vault_pass, mount_point="userpass")

    if client.is_authenticated():
        token = res['auth']['client_token']
        print(f"✅ Vault authentication successful.")

        # 4. Prepare secrets for encryption
        secret_content = (
            f"VAULT_ADDR={vault_addr}\n"
            f"VAULT_TOKEN={token}\n"
            f"VAULT_SKIP_VERIFY=true\n"
            f"CREATED_AT={int(time.time())}\n"
        )

        # 5. Generate encryption key
        passphrase = get_random_passphrase()

        # 6. Encrypt using GPG
        process = subprocess.Popen(
            ['gpg', '--symmetric', '--batch', '--yes', '--passphrase', passphrase, '-o', ENV_FILE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(input=secret_content.encode())

        if process.returncode == 0:
            print(f"🔒 Secrets encrypted to {ENV_FILE}")
            print(f"🔑 Passphrase saved to {KEY_FILE}")
        else:
            print(f"❌ GPG Error: {stderr.decode()}")

    else:
        print("❌ Authentication failed: Invalid credentials.")

except Exception as e:
    print(f"⚠️ An error occurred during login: {e}")
