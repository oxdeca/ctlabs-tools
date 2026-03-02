# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/core.py
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

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HashiVault:
    def __init__(self, grace_period=300, timeout=90):
        self.grace_period = grace_period
        self.timeout      = timeout
        self.base_path    = os.path.expanduser("~/.ctlabs_vault")
        self.key_path     = os.path.join(self.base_path, ".vault_key")
        self.gpg_path     = os.path.join(self.base_path, ".env.gpg")
        
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

    #
    # Secrets
    #
    def read_secret(self, path, mount_point='secret'):
        client = self._get_client()
        if not client: return None

        try:
            if mount_point.lower() == 'cubbyhole':
                response = client.read(f"cubbyhole/{path}")
                if response and 'data' in response:
                    return response['data']
                return None
            else:
                response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)
                return response['data']['data']
        except Exception as e:
            print(f"❌ Error reading {mount_point}/{path}: {e}")
            return None

    def write_secret(self, path, secret_data, mount_point='secret'):
        client = self._get_client()
        if not client: return False

        try:
            if mount_point.lower() == 'cubbyhole':
                client.write(f"cubbyhole/{path}", **secret_data)
            else:
                client.secrets.kv.v2.create_or_update_secret(
                    path=path, 
                    secret=secret_data, 
                    mount_point=mount_point
                )
            print(f"✅ Successfully wrote secret to {mount_point}/{path}")
            return True
        except Exception as e:
            print(f"❌ Error writing secret to Vault: {e}")
            return False

    def list_secrets(self, path, mount_point='secret'):
        client = self._get_client()
        if not client: return None
        try:
            if mount_point in ['secret', 'kv', 'kvv2']:
                res = client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)
            else:
                res = client.list(f"{mount_point}/{path}")

            return res.get('data', {}).get('keys', [])
        except Exception as e:
            # Vault throws an InvalidPath/404 when trying to list a leaf node.
            # We fail silently here so the CLI can smoothly fall back to a "read".
            error_str = str(e)
            if "404" in error_str or "InvalidPath" in type(e).__name__ or "None, on list" in error_str:
                return []
            
            print(f"❌ Error listing secrets at {mount_point}/{path}: {e}")
            return None

    def search_secrets(self, base_path, search_pattern, mount_point='secret'):
        """Safely yields paths and matched keys, evaluating both folder/secret names and payload keys."""
        client = self._get_client()
        if not client: return
        
        import re
        try:
            regex = re.compile(search_pattern, re.IGNORECASE)
        except re.error as e:
            print(f"❌ Invalid regex pattern '{search_pattern}': {e}")
            return

        def _recurse(current, is_folder=True):
            path_matches = bool(regex.search(current))
            
            if is_folder:
                # If the folder path itself matches, yield it immediately
                if path_matches and current != base_path:
                    yield current, [], True, True # path, matched_keys, path_matches, is_folder
                
                try:
                    res = client.secrets.kv.v2.list_secrets(path=current, mount_point=mount_point)
                    keys = res.get('data', {}).get('keys', [])
                    for k in keys:
                        next_path = f"{current}/{k}" if current else k
                        if k.endswith('/'):
                            yield from _recurse(next_path.rstrip('/'), is_folder=True)
                        else:
                            yield from _recurse(next_path, is_folder=False)
                except Exception as e:
                    # If listing fails on the base_path, it might actually be a leaf node
                    if current == base_path:
                        yield from _recurse(current, is_folder=False)
            else:
                # It's a secret (leaf node). Read the payload to check the keys.
                matched_keys = []
                try:
                    secret_res = client.secrets.kv.v2.read_secret_version(path=current, mount_point=mount_point)
                    secret_data = secret_res.get('data', {}).get('data', {})
                    matched_keys = [sk for sk in secret_data.keys() if regex.search(sk)]
                except Exception:
                    pass # Ignore permission errors
                
                # Yield if the secret's path matches OR if any keys inside matched
                if path_matches or matched_keys:
                    yield current, matched_keys, path_matches, False

        yield from _recurse(base_path, is_folder=True)

    def resolve_mapped_config(self, config):
        results = {}
        mount_point = config.get("mount", "kvv2")
        
        for secret_def in config.get("secrets", []):
            name = secret_def["name"]
            path = secret_def["path"]
            
            data = self.read_secret(path=path, mount_point=mount_point)
            if data:
                results[name] = data.get(name, data)
            else:
                results[name] = None
                
        return results

    #
    #  RAW Data
    #
    def read_raw_path(self, path):
        """Reads the raw data from any Vault API path, handling both Vault-wrapped and raw responses."""
        client = self._get_client()
        if not client: return None
        try:
            if path.endswith('/'):
                res = client.list(path)
            else:
                res = client.read(path)

            if not res: 
                return None
            
            if 'data' in res and 'request_id' in res:
                return res['data']
            
            return res
        except Exception as e:
            print(f"❌ Error reading raw path '{path}': {e}")
            return None

    #
    # AppRoles
    #
    def approle_login(self, vault_url, role_id, secret_id):
        client = hvac.Client(url=vault_url, verify=False)
        try:
            res = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            self._memory_token = res['auth']['client_token']
            self._memory_url = vault_url
            lease = res['auth'].get('lease_duration', 3600)
            self._memory_expiry = int(time.time()) + lease
            print("✅ AppRole login successful. Token stored in memory.")
            return True
        except Exception as e:
            print(f"❌ AppRole authentication failed: {e}")
            return False

    def create_or_update_approle(self, role_name, policies, ttl="1h"):
        client = self._get_client()
        if not client: return False
        try:
            client.auth.approle.create_or_update_approle(
                role_name=role_name,
                token_policies=policies,
                token_ttl=ttl,
                bind_secret_id=True
            )
            return True
        except Exception as e:
            print(f"❌ Error setting up AppRole {role_name}: {e}")
            return False

    def read_approle(self, role_name):
        """Fetches detailed properties of a specific AppRole."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.auth.approle.read_role(role_name=role_name)
            return res.get('data', {})
        except Exception as e:
            print(f"❌ Error reading AppRole {role_name}: {e}")
            return None

    def get_approle_credentials(self, role_name):
        client = self._get_client()
        if not client: return None
        try:
            role_id = client.auth.approle.read_role_id(role_name=role_name)['data']['role_id']
            secret_id = client.auth.approle.generate_secret_id(role_name=role_name)['data']['secret_id']
            return {"role_id": role_id, "secret_id": secret_id}
        except Exception as e:
            print(f"❌ Error fetching AppRole creds: {e}")
            return None

    def list_approles(self):
        """Fetches a list of all configured AppRoles."""
        client = self._get_client()
        if not client: return None
        try:
            # hvac returns a dict with 'keys' if successful
            res = client.auth.approle.list_roles()
            return res.get('data', {}).get('keys', [])
        except Exception as e:
            # A 404/InvalidPath usually just means no roles exist yet
            if "404" in str(e): return []
            print(f"❌ Error listing AppRoles: {e}")
            return None

    def delete_approle(self, role_name):
        """Deletes a specific AppRole."""
        client = self._get_client()
        if not client: return False
        try:
            client.auth.approle.delete_role(role_name=role_name)
            return True
        except Exception as e:
            print(f"❌ Error deleting AppRole {role_name}: {e}")
            return False

    def create_manager_policy(self, manager_name, target_role):
        """Creates a policy allowing a manager to issue SecretIDs for a target role."""
        client = self._get_client()
        if not client: return None

        policy_name = f"manager-{manager_name}-for-{target_role}"
        # Policy: Only allow generating SecretIDs for the specific target
        policy_hcl = f"""
        path "auth/approle/role/{target_role}/secret-id" {{
          capabilities = ["update"]
        }}
        """
        
        try:
            client.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)
            return policy_name
        except Exception as e:
            print(f"❌ Failed to create manager policy: {e}")
            return None

    # gcp tokens
    def create_minimal_policy(self, role_name, secret_path, gcp_roleset=None):
        """Creates a standard restricted policy for a specific AppRole (KVv2 Aware)."""
        client = self._get_client()
        if not client: return None

        policy_name = f"policy-{role_name}"
        
        # BUGFIX: Handle KVv2 data/ and metadata/ routing
        # If the user passes 'kv/my-app', we split it to 'kv/data/my-app'
        parts = secret_path.split('/', 1)
        if len(parts) > 1:
            mount = parts[0]
            path = parts[1]
            data_path = f"{mount}/data/{path}"
            meta_path = f"{mount}/metadata/{path}"
        else:
            data_path = secret_path
            meta_path = secret_path

        policy_hcl = f"""
        # Allow reading the actual secret data
        path "{data_path}/*" {{ capabilities = ["read", "list"] }}
        path "{data_path}"   {{ capabilities = ["read", "list"] }}
        
        # Allow reading the secret metadata (required by many tools)
        path "{meta_path}/*" {{ capabilities = ["read", "list"] }}
        path "{meta_path}"   {{ capabilities = ["read", "list"] }}
        """

        if gcp_roleset:
            # 🧠 SMART FIX: Automatically inject the /token/ pathing for the user
            # e.g., "gcp/my-project/devops" -> "gcp/my-project/token/devops"
            parts = gcp_roleset.rsplit('/', 1)
            if len(parts) == 2:
                gcp_path = f"{parts[0]}/token/{parts[1]}"
            else:
                gcp_path = f"gcp/token/{gcp_roleset}" # Fallback for old default mounts

            policy_hcl += f"""
            # Allow generating dynamic GCP OAuth tokens for {gcp_roleset}
            path "{gcp_path}" {{
              capabilities = ["read"]
            }}
            """
        
        try:
            client.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)
            print(f"✅ Created minimal KVv2 policy: {policy_name}")
            return policy_name
        except Exception as e:
            print(f"❌ Failed to create policy: {e}")
            return None

    def setup_automated_approle(self, role_name, secret_path):
        """High-level helper to create policy and role in one shot."""
        # 1. Create the restricted policy
        policy_name = self.create_minimal_policy(role_name, secret_path)
        if not policy_name: return False

        # 2. Create the AppRole linked to that policy
        return self.create_or_update_approle(role_name, [policy_name])

    def delete_policy(self, policy_name):
        """Deletes a specific Vault policy."""
        client = self._get_client()
        if not client: return False
        try:
            client.sys.delete_policy(name=policy_name)
            return True
        except Exception as e:
            # Don't print an error if it just doesn't exist
            if "404" not in str(e):
                print(f"⚠️ Could not delete policy {policy_name}: {e}")
            return False

    def lookup_token(self):
        """Fetches metadata about the currently active token."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.auth.token.lookup_self()
            return res.get('data', {})
        except Exception as e:
            print(f"❌ Error looking up token: {e}")
            return None

    def get_gcp_token(self, roleset_name, mount_point='gcp'):
        """Generates a dynamic, short-lived GCP OAuth token from Vault."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/token/{roleset_name}")
            if not res:
                print(f"❌ Vault Error: Roleset '{roleset_name}' not found at '{mount_point}/'.", file=sys.stderr)
                return None
                
            return res.get('token') or res.get('token_oauth2_secret') or res.get('data', {}).get('token')
        except Exception as e:
            print(f"❌ Error generating GCP token for roleset '{roleset_name}': {e}", file=sys.stderr)
            return None

    def get_gcp_token_info(self, token_string):
        """Introspects ANY existing GCP OAuth token using Google's public endpoint."""
        if not token_string: return {}
        
        import requests  # Import locally to guarantee it's available
        try:
            # Bumped timeout to 10s just in case it's a slow network route
            r = requests.get(f"https://oauth2.googleapis.com/tokeninfo?access_token={token_string}", timeout=10)
            
            if r.status_code == 200:
                return r.json()
            else:
                return {"error": r.json().get("error_description", f"Google API returned HTTP {r.status_code}")}
                
        except Exception as e:
            # NO MORE SILENT FAILURES! Pass the exact error back to the CLI.
            return {"error": f"Network/Python error: {e.__class__.__name__} - {str(e)}"}


    def configure_oidc_issuer(self, issuer_url):
        """Phase 1: Tells Vault to broadcast its identity for WIF."""
        client = self._get_client()
        if not client: return False
        try:
            client.write('identity/oidc/config', issuer=issuer_url)
            print(f"✅ Vault OIDC Issuer set to: {issuer_url}")
            return True
        except Exception as e:
            print(f"❌ Error setting OIDC issuer: {e}")
            return False

    #
    # secret engines
    #
    def setup_gcp_engine(self, creds_json, mount_point='gcp'):
        """Phase 1: Enables GCP engine and configures it with the Master JSON key."""
        client = self._get_client()
        if not client: return False
        try:
            # 1. Safely enable the engine
            try:
                client.sys.enable_secrets_engine(backend_type='gcp', path=mount_point)
                print(f"✅ Enabled GCP secrets engine at '{mount_point}/'")
            except Exception as e:
                if "path is already in use" not in str(e):
                    print(f"❌ Failed to enable engine: {e}")
                    return False
            
            # 2. Write the Master Credentials
            client.write(f'{mount_point}/config', credentials=creds_json)
            print(f"✅ Configured GCP Engine '{mount_point}/' with Master Credentials")
            return True
        except Exception as e:
            # Added exact exception typing so errors are never blank again!
            print(f"❌ Error configuring GCP engine: {type(e).__name__} - {str(e)}")
            return False

    def create_gcp_roleset(self, name, project_id, bindings_hcl, mount_point='gcp'):
        """Phase 2: Creates a roleset to generate temporary GCP OAuth tokens."""
        client = self._get_client()
        if not client: return False
        
        import time
        # BUMPED TO 6 ATTEMPTS
        for attempt in range(1, 7):
            try:
                client.write(
                    f'{mount_point}/roleset/{name}',
                    project=project_id,
                    secret_type="access_token",
                    token_scopes=[
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/userinfo.email"
                    ],
                    bindings=bindings_hcl
                )
                print(f"✅ Created GCP roleset '{name}' in project '{project_id}'")
                return True
            except Exception as e:
                error_msg = str(e)
                # ADDED API ENABLEMENT ERRORS TO THE CATCH LIST
                if attempt < 6 and ("Invalid JWT Signature" in error_msg or "timed out" in error_msg.lower() or "accessNotConfigured" in error_msg or "SERVICE_DISABLED" in error_msg):
                    print(f"  ⏳ GCP IAM sync delay detected. Waiting 30 seconds for Google to catch up... (Attempt {attempt}/6)")
                    time.sleep(30)
                else:
                    print(f"❌ Error creating roleset '{name}': {e}")
                    return False
        return False

    def read_gcp_roleset(self, name, mount_point='gcp'):
        """Reads the configuration of an existing GCP roleset."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f'{mount_point}/roleset/{name}')
            return res.get('data') if res else None
        except Exception as e:
            print(f"❌ Error reading roleset '{name}': {e}")
            return None

    def delete_gcp_roleset(self, name, mount_point='gcp'):
        """Deletes a GCP roleset and cleans up its underlying Service Account in GCP."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f'{mount_point}/roleset/{name}')
            print(f"✅ Deleted roleset '{name}' at '{mount_point}/'. GCP Service Account queued for deletion.")
            return True
        except Exception as e:
            print(f"❌ Error deleting roleset '{name}': {e}")
            return False

    def list_gcp_rolesets(self, mount_point='gcp'):
        """Lists all configured rolesets under a specific GCP engine mount."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f'{mount_point}/roleset')
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            # Vault returns 404 on list if the path is empty
            if "404" in str(e): return []
            print(f"❌ Error listing rolesets at '{mount_point}/': {e}")
            return []

    def teardown_gcp_engine(self, mount_point='gcp'):
        """Phase 3 (Cleanup): Disables the GCP secrets engine to clean up Vault."""
        client = self._get_client()
        if not client: return False
        try:
            # Bypass the buggy hvac.sys module and use the raw read that we know works!
            res = client.read("sys/mounts")
            engines = res.get('data', res) if isinstance(res, dict) else res
            
            if engines and f"{mount_point}/" in engines:
                client.sys.disable_secrets_engine(path=mount_point)
                print(f"✅ Disabled GCP secrets engine at '{mount_point}/'")
            else:
                print(f"ℹ️ Engine '{mount_point}/' was not mounted. Skipping unmount.")
                
            return True
        except Exception as e:
            error_msg = str(e).strip()
            print(f"⚠️ Could not disable GCP engine: {error_msg if error_msg else type(e).__name__}")
            return False

    def list_leases(self, prefix):
        """Lists active leases for ANY Vault secrets engine."""
        client = self._get_client()
        if not client: return []
        try:
            # We pass the exact prefix the user typed
            res = client.list(f"sys/leases/lookup/{prefix}")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" in str(e) or "permission denied" in str(e).lower():
                return []
            print(f"❌ Error listing leases for {prefix}: {e}")
            return []

    def list_engines(self, backend_type=None):
        """Fetches a list of mounted secrets engines, optionally filtered by type."""
        client = self._get_client()
        if not client: return None
        try:
            engines = client.read("sys/mounts")
            
            if not engines:
                return []
                
            data = engines.get('data', engines) if isinstance(engines, dict) else engines
            
            mounts = []
            for path, config in data.items():
                # If backend_type is provided, filter by it. Otherwise, return all!
                if backend_type is None or config.get('type') == backend_type:
                    mounts.append(path)
                    
            return mounts
        except Exception as e:
            error_msg = str(e).strip()
            print(f"❌ Error listing {backend_type or 'all'} mounts: {error_msg if error_msg else e.__class__.__name__}", file=sys.stderr)
            return None

    # -------------------------------------------------------------------------
    # USERPASS / LDAP MANAGEMENT
    # -------------------------------------------------------------------------
    def create_user(self, username, password=None, policies=None, auth_type="userpass"):
        """Creates or updates a human user in Vault."""
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
        if password and auth_type == "userpass":
            payload['password'] = password
            
        try:
            client.write(f"auth/{auth_type}/users/{username}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating {auth_type} user '{username}': {e}")
            return False

    def read_user(self, username, auth_type="userpass"):
        """Reads configuration details for a human user."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/{auth_type}/users/{username}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading {auth_type} user '{username}': {e}")
            return None

    def delete_user(self, username, auth_type="userpass"):
        """Deletes a human user."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/{auth_type}/users/{username}")
            return True
        except Exception as e:
            print(f"❌ Error deleting {auth_type} user '{username}': {e}")
            return False

    def list_users(self, auth_type="userpass"):
        """Lists all users for a specific auth method."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"auth/{auth_type}/users")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing {auth_type} users: {e}")
            return []

    # -------------------------------------------------------------------------
    # POLICY MANAGEMENT
    # -------------------------------------------------------------------------
    def create_policy(self, name, rules):
        """Creates or updates an ACL policy using the modern endpoint."""
        client = self._get_client()
        if not client: return False
        try:
            # Directly hit the modern ACL path
            client.write(f"sys/policies/acl/{name}", policy=rules)
            return True
        except Exception as e:
            print(f"❌ Error creating policy '{name}': {e}")
            return False

    def read_policy(self, name):
        """Reads an existing ACL policy using the modern endpoint."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"sys/policies/acl/{name}")
            return res.get('data', {}).get('policy') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading policy '{name}': {e}")
            return None

    def delete_policy(self, name):
        """Deletes an ACL policy using the modern endpoint."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"sys/policies/acl/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting policy '{name}': {e}")
            return False

    def list_policies(self):
        """Lists all ACL policies using the modern endpoint."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("sys/policies/acl")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            print(f"❌ Error listing policies: {e}")
            return []

    # -------------------------------------------------------------------------
    # AUTH GROUP MANAGEMENT (LDAP/OIDC)
    # -------------------------------------------------------------------------
    def create_group(self, name, policies=None, auth_type="ldap"):
        """Maps an external auth group (like LDAP) to Vault policies."""
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
            
        try:
            client.write(f"auth/{auth_type}/groups/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating {auth_type} group '{name}': {e}")
            return False

    def read_group(self, name, auth_type="ldap"):
        """Reads configuration details for an auth group."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/{auth_type}/groups/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading {auth_type} group '{name}': {e}")
            return None

    def delete_group(self, name, auth_type="ldap"):
        """Deletes an auth group mapping."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/{auth_type}/groups/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting {auth_type} group '{name}': {e}")
            return False

    def list_groups(self, auth_type="ldap"):
        """Lists all mapped groups for a specific auth method."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"auth/{auth_type}/groups")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing {auth_type} groups: {e}")
            return []

    # -------------------------------------------------------------------------
    # IDENTITY ENTITY MANAGEMENT
    # -------------------------------------------------------------------------
    def create_entity(self, name, policies=None):
        """Creates or updates a Vault Identity Entity."""
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
            
        try:
            # Vault standardizes entity creation by name here
            client.write(f"identity/entity/name/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating entity '{name}': {e}")
            return False

    def read_entity(self, name):
        """Reads configuration details for an entity."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"identity/entity/name/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading entity '{name}': {e}")
            return None

    def delete_entity(self, name):
        """Deletes an identity entity."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"identity/entity/name/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting entity '{name}': {e}")
            return False

    def list_entities(self):
        """Lists all identity entities."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("identity/entity/name")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing entities: {e}")
            return []

    def merge_entities(self, from_entity_name, to_entity_name):
        """Merges one entity (and its aliases) into another, deleting the source."""
        client = self._get_client()
        if not client: return False
        
        # 1. Look up the UUIDs for both entities
        from_ent = self.read_entity(from_entity_name)
        to_ent = self.read_entity(to_entity_name)
        
        if not from_ent or 'id' not in from_ent:
            print(f"❌ Error: Source entity '{from_entity_name}' not found.")
            return False
        if not to_ent or 'id' not in to_ent:
            print(f"❌ Error: Target entity '{to_entity_name}' not found.")
            return False
            
        # 2. Fire the merge API call
        try:
            client.write(
                "identity/entity/merge",
                from_entity_ids=[from_ent['id']],
                to_entity_id=to_ent['id']
            )
            return True
        except Exception as e:
            print(f"❌ Error merging entities: {e}")
            return False


    # -------------------------------------------------------------------------
    # IDENTITY ALIAS MANAGEMENT
    # -------------------------------------------------------------------------
    def get_auth_accessor(self, mount_point):
        """Resolves a human-readable auth mount point to its internal Accessor UUID."""
        client = self._get_client()
        if not client: return None
        
        # Vault stores mounts with a trailing slash in sys/auth (e.g., 'ldap/')
        mount_point = mount_point.strip('/') + '/'
        try:
            auth_methods = client.sys.list_auth_methods().get('data', {})
            if mount_point in auth_methods:
                return auth_methods[mount_point].get('accessor')
            return None
        except Exception as e:
            print(f"❌ Error fetching auth accessor for '{mount_point}': {e}")
            return None

    def create_entity_alias(self, entity_name, alias_name, mount_point="userpass"):
        """Smart Alias: Links a login name to an Entity by resolving UUIDs automatically."""
        client = self._get_client()
        if not client: return False

        # 1. Resolve Entity UUID
        entity = self.read_entity(entity_name)
        if not entity or 'id' not in entity:
            print(f"❌ Error: Entity '{entity_name}' not found. Create it first.")
            return False
        
        # 2. Resolve Auth Mount UUID
        accessor = self.get_auth_accessor(mount_point)
        if not accessor:
            print(f"❌ Error: Auth mount '{mount_point}' not found or inaccessible.")
            return False

        # 3. Map them together!
        try:
            client.write(
                "identity/entity-alias",
                name=alias_name,
                canonical_id=entity['id'],
                mount_accessor=accessor
            )
            return True
        except Exception as e:
            print(f"❌ Error creating alias '{alias_name}' for entity '{entity_name}': {e}")
            return False

    def delete_entity_alias(self, entity_name, alias_name, mount_point="userpass"):
        """Smart Alias: Finds and deletes a specific alias from an entity."""
        client = self._get_client()
        if not client: return False
        
        accessor = self.get_auth_accessor(mount_point)
        entity = self.read_entity(entity_name)
        if not entity or 'aliases' not in entity: return False
        
        # Find the specific alias UUID inside the entity's data
        alias_id = None
        for alias in entity['aliases']:
            if alias['name'] == alias_name and alias['mount_accessor'] == accessor:
                alias_id = alias['id']
                break
                
        if not alias_id:
            print(f"⚠️ Alias '{alias_name}' on '{mount_point}' not found for entity '{entity_name}'.")
            return False
            
        try:
            client.delete(f"identity/entity-alias/id/{alias_id}")
            return True
        except Exception as e:
            print(f"❌ Error deleting alias: {e}")
            return False

    # -------------------------------------------------------------------------
    # KUBERNETES AUTH MANAGEMENT
    # -------------------------------------------------------------------------
    def create_kubernetes_role(self, name, sa_names, sa_namespaces, policies=None, ttl="1h"):
        """Creates or updates a Kubernetes Auth Role."""
        client = self._get_client()
        if not client: return False
        
        payload = {
            "bound_service_account_names": [sa.strip() for sa in sa_names.split(",")],
            "bound_service_account_namespaces": [ns.strip() for ns in sa_namespaces.split(",")],
            "token_ttl": ttl
        }
        if policies:
            payload['token_policies'] = [p.strip() for p in policies.split(",")]
            
        try:
            client.write(f"auth/kubernetes/role/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating Kubernetes role '{name}': {e}")
            return False

    def read_kubernetes_role(self, name):
        """Reads configuration details for a Kubernetes Auth Role."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/kubernetes/role/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading Kubernetes role '{name}': {e}")
            return None

    def delete_kubernetes_role(self, name):
        """Deletes a Kubernetes Auth Role."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/kubernetes/role/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting Kubernetes role '{name}': {e}")
            return False

    def list_kubernetes_roles(self):
        """Lists all Kubernetes Auth Roles."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("auth/kubernetes/role")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing Kubernetes roles: {e}")
            return []

    # -------------------------------------------------------------------------
    # KUBERNETES SECRETS ENGINE (JIT Dynamic Accounts)
    # -------------------------------------------------------------------------
    def setup_k8s_secrets_engine(self, mount_point, host, ca_cert, jwt):
        """Mounts and configures a K8s Secrets Engine."""
        client = self._get_client()
        if not client: return False
        try:
            current_mounts = client.sys.list_mounted_secrets_engines()['data']
            if f"{mount_point}/" not in current_mounts:
                client.sys.enable_secrets_engine('kubernetes', path=mount_point)
            
            # Configure engine with the cluster's API endpoint and credentials
            client.write(f"{mount_point}/config", kubernetes_host=host, kubernetes_ca_cert=ca_cert, service_account_jwt=jwt)
            return True
        except Exception as e:
            print(f"❌ Error setting up K8s Secrets engine: {e}")
            return False

    def teardown_k8s_secrets_engine(self, mount_point):
        """Unmounts a K8s Secrets Engine."""
        client = self._get_client()
        if not client: return False
        try:
            client.sys.disable_secrets_engine(mount_point)
            return True
        except Exception as e:
            print(f"❌ Error tearing down K8s Secrets engine: {e}")
            return False

    def create_k8s_secret_role(self, name, mount_point, allowed_namespaces, rules_payload, ttl="1h"):
        """Creates a role defining what K8s privileges can be dynamically generated."""
        client = self._get_client()
        if not client: return False
        
        payload = {
            "allowed_kubernetes_namespaces": [ns.strip() for ns in allowed_namespaces.split(",")],
            "generated_role_rules": rules_payload, # 🧠 Vault natively accepts JSON or YAML here!
            "token_default_ttl": ttl,
            "token_max_ttl": ttl
        }
        try:
            client.write(f"{mount_point}/roles/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating K8s Secret Role '{name}': {e}")
            return False

    def read_k8s_secret_role(self, name, mount_point):
        """Reads a K8s secret role configuration."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/roles/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading K8s role '{name}': {e}")
            return None

    def delete_k8s_secret_role(self, name, mount_point):
        """Deletes a K8s secret role."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"{mount_point}/roles/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting K8s role '{name}': {e}")
            return False

    def list_k8s_secret_roles(self, mount_point):
        """Lists active K8s secret roles."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"{mount_point}/roles")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing K8s roles: {e}")
            return []

    def get_k8s_secret_token(self, role_name, k8s_namespace, mount_point):
        """Requests a dynamic, ephemeral K8s Service Account token."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.write(f"{mount_point}/creds/{role_name}", kubernetes_namespace=k8s_namespace)
            return res.get('data', {}).get('service_account_token')
        except Exception as e:
            print(f"❌ Error generating K8s token for '{role_name}': {e}")
            return None

# ----------------------------------------------------------------------------


class GCPSecretManager:
    def __init__(self):
        try:
            from google.cloud import secretmanager
            self.client = secretmanager.SecretManagerServiceClient()
            self.is_available = True
        except ImportError:
            print("⚠️ google-cloud-secret-manager is not installed. GSM features disabled.")
            self.client = None
            self.is_available = False

    def get_secret(self, project, secret_id, version="latest"):
        if not self.is_available:
            return None
            
        name = f"projects/{project}/secrets/{secret_id}/versions/{version}"
        
        try:
            response = self.client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            print(f"❌ Failed to fetch {secret_id} from GSM: {e}")
            return None