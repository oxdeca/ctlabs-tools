# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/base.py
# License : MIT
# -----------------------------------------------------------------------------

import hvac
import jmespath
import json
import os
import pytest
import socket
import subprocess
import sys
import time
import urllib
import urllib.parse
import warnings

class VaultBase:
    def __init__(self, grace_period=300, timeout=90):
        self.grace_period  = grace_period
        self.timeout       = timeout
        self.base_path     = os.path.expanduser("~/.ctlabs_vault")
        self.key_path      = os.path.join(self.base_path, ".vault_key")
        self.gpg_path      = os.path.join(self.base_path, ".env.gpg")
        self._memory_token = None
        self._memory_url   = None

    def _get_client(self):
        if self._memory_token and self._memory_url:
            return hvac.Client(url=self._memory_url, token=self._memory_token, verify=False)
            
        secrets = self._decrypt_secrets()
        if not secrets: return None
            
        is_valid, _ = self.check_expiration()
        if not is_valid: return None

        skip_verify = secrets.get("VAULT_SKIP_VERIFY", "false").lower() == "true"
        return hvac.Client(
            url=secrets.get("VAULT_ADDR"), 
            token=secrets.get("VAULT_TOKEN"), 
            verify=not skip_verify,
            timeout=self.timeout
        )

    #
    # locally cached vault token store
    #
    def _decrypt_secrets(self):
        if not os.path.exists(self.key_path) or not os.path.exists(self.gpg_path):
            return None

        with open(self.key_path, "r") as f:
            passphrase = f.read().strip()

        res = subprocess.run(
            ['gpg', '--decrypt', '--batch', '--passphrase', passphrase, self.gpg_path],
            capture_output=True, text=True
        )

        if res.returncode != 0:
            return None

        secrets = {}
        for line in res.stdout.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                secrets[key] = val.strip()
        return secrets


    def check_expiration(self):
        current_time = int(time.time())
        
        # BUGFIX: Accurately check memory token and clear if expired
        if self._memory_token:
            remaining = getattr(self, '_memory_expiry', current_time + 3600) - current_time
            if remaining > self.grace_period:
                return True, remaining
            else:
                self._memory_token = None
                self._memory_url = None

        secrets = self._decrypt_secrets()
        if not secrets: return False, 0
        
        expiry_timestamp = int(secrets.get("EXPIRES_AT", int(secrets.get("CREATED_AT", 0)) + 28800))
        remaining = expiry_timestamp - current_time
        return remaining > self.grace_period, remaining

    def load_secrets(self):
        if self._memory_token and self._memory_url:
            os.environ["VAULT_ADDR"] = self._memory_url
            os.environ["VAULT_TOKEN"] = self._memory_token
            os.environ["VAULT_SKIP_VERIFY"] = "true"
            return True

        secrets = self._decrypt_secrets()
        if not secrets:
            return False

        is_valid, remaining = self.check_expiration()

        if not is_valid:
            if os.path.exists(self.key_path): os.remove(self.key_path)
            if os.path.exists(self.gpg_path): os.remove(self.gpg_path)
            return False

        os.environ.update(secrets)
        os.environ["VAULT_SKIP_VERIFY"] = "true" 
        return True

    def ensure_valid_token(self, interactive=False):
        while True:
            # 1. Try Local GPG Cache or Memory (Human Dev Workflow)
            if self.load_secrets():
                return True

            # 2. Try Automated AppRole Login (Rundeck / CI/CD Workflow)
            role_id = os.getenv("VAULT_ROLE_ID")
            secret_id = os.getenv("VAULT_SECRET_ID")
            vault_url = os.getenv("VAULT_ADDR")

            if role_id and secret_id and vault_url:
                print("🤖 Automated environment detected. Logging into Vault via AppRole...")
                if self.approle_login(vault_url, role_id, secret_id):
                    return True

            # 3. Fallback to Headless Failure or Interactive Prompt
            if not interactive:
                if "PYTEST_CURRENT_TEST" in os.environ:
                    pytest.fail("Vault auth failed: No valid token or AppRole credentials found in environment.")
                else:
                    print("❌ Vault auth failed: No valid token or AppRole credentials found in environment.")
                    sys.exit(1)
                
            print("\n" + "!"*40 + "\n🔑 VAULT TOKEN EXPIRED OR MISSING\n" + "!"*40)
            print("Please run 'vault-login' in a separate terminal.")
            choice = input("Action: [r]etry, [q]uit: ").strip().lower()
            
            if choice == 'q':
                if "PYTEST_CURRENT_TEST" in os.environ:
                    pytest.exit("User aborted test run due to Vault expiry.")
                else:
                    print("🛑 User aborted.")
                    sys.exit(1)
                    
            print("🔄 Checking for new Vault secrets...")
            # The loop goes back to the top and checks load_secrets() again!


