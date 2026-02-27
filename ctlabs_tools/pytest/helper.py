# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/helper.py
# License : MIT
# -----------------------------------------------------------------------------

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

# hvac is only needed if HashiVault is actually used
try:
    import hvac
except ImportError:
    pass


class Terraform:
    def __init__(self, wd=".", interactive=False, auth_callback=None):
        self.wd            = wd
        self.tf_plan       = {}
        self.tf_state      = {}
        self.plan_bin      = "tfplan.bin"
        self.interactive   = interactive
        self.auth_callback = auth_callback  # Dependency Injection for auth checks

    def _run_cmd(self, args, capture=True):
        while True:
            try:
                # Dynamically run the auth check before execution
                if self.auth_callback:
                    self.auth_callback(interactive=self.interactive)
    
                is_json_req = "show" in args and "-json" in args
                current_capture = True if is_json_req else (False if self.interactive else capture)
                
                res = subprocess.run(args, cwd=self.wd, capture_output=current_capture, text=True, env=os.environ)
    
                if res.returncode < 0:
                    raise KeyboardInterrupt
    
                if res.returncode == 0:
                    return res
                
                if not self.interactive:
                    return res 
    
            except KeyboardInterrupt:
                print("\n\n🛑 [STOP] User triggered exit. Killing pytest session...")
                sys.exit(1)
    
            except Exception as e:
                print(f"\n⚠️ Execution Error: {e}")
                if not self.interactive: raise
    
            print("\n" + "!"*40 + f"\n--- TERRAFORM FAILURE: {' '.join(args)} ---\n" + "!"*40)
            choice = input("Action: [r]etry, [q]uit: ").strip().lower()
            if choice != 'r':
                pytest.fail("User aborted.")
            print("🔄 Retrying command...")

    def init(self):
        return self._run_cmd(["terraform", "init", "-upgrade"], capture=False)

    def import_(self, resource, id):
        return self._run_cmd(["terraform", "import", resource, id], capture=False)

    def plan(self, file=None):
        plan_bin = file or self.plan_bin
        res = self._run_cmd(["terraform", "plan", "-out", plan_bin], capture=False)

        if res.returncode == 0:
            self.show_plan() 
        return res

    def apply(self):
        res = self._run_cmd(["terraform", "apply", "-auto-approve"], capture=False)
        if res.returncode == 0:
            self.show_state()
        else:
            if not self.interactive:
                pytest.fail("Terraform Apply failed.")
        return res

    def has_changes(self):
        """
        Evaluates the current Terraform plan using JMESPath.
        Returns True if changes exist, False if the plan is a complete no-op.
        """
        if not self.tf_plan:
            self.show_plan()
            
        actions = self.search_plan("resource_changes[].change.actions[]") or []
        for action in actions:
            if action not in ["no-op", "read"]:
                return True
        return False

    def show_changes(self):
        """
        Prints a colored, human-readable summary of the resources that will be 
        created, updated, replaced, or deleted.
        """
        RESET  = "\033[0m"
        BOLD   = "\033[1m"
        GREEN  = "\033[92m"
        YELLOW = "\033[93m"
        RED    = "\033[91m"
        CYAN   = "\033[96m"

        if not self.has_changes():
            print(f"\n{GREEN}✅ [TERRAFORM] No changes required. Infrastructure is up-to-date.{RESET}")
            return

        print(f"\n{BOLD}🔍 [TERRAFORM] Detected changes in the following resources:{RESET}")
        
        for resource in self.tf_plan.get("resource_changes", []):
            address = resource.get("address")
            actions = resource.get("change", {}).get("actions", [])
            
            if actions == ["no-op"] or actions == ["read"]:
                continue
                
            if "delete" in actions and "create" in actions:
                action_str = "REPLACE"
                color = CYAN
            elif "create" in actions:
                action_str = "CREATE"
                color = GREEN
            elif "delete" in actions:
                action_str = "DELETE"
                color = RED
            elif "update" in actions:
                action_str = "UPDATE"
                color = YELLOW
            else:
                action_str = ", ".join(actions).upper()
                color = RESET 
                
            print(f"  {color}➜ {action_str.ljust(10)} : {address}{RESET}")
        print("-" * 60)

    def show_state(self):
        res = self._run_cmd(["terraform", "show", "-json"], capture=True)
        if res.returncode == 0:
            self.tf_state = json.loads(res.stdout)
        return self.tf_state

    def show_plan(self, file="tfplan.json"):
        show_res = self._run_cmd(["terraform", "show", "-json", self.plan_bin], capture=True)
        
        if show_res.returncode == 0:
            self.tf_plan = json.loads(show_res.stdout)
            with open(os.path.join(self.wd, file), "w") as f:
                json.dump(self.tf_plan, f, indent=2)
        return self.tf_plan

    def search_plan(self, query):
        if not self.tf_plan:
            self.show_plan()
        return jmespath.search(query, self.tf_plan)

    def search_state(self, query):
        if not self.tf_state:
            self.show_state()
        return jmespath.search(query, self.tf_state)

    def _find_in_data(self, data_root, address):
        if not data_root: return None

        outputs = data_root.get("outputs", {})
        if address in outputs:
            return outputs[address].get("value")

        def find_resource(module, target):
            for res in module.get("resources", []):
                if res.get("address") == target or res.get("name") == target:
                    return res.get("values")
            for child in module.get("child_modules", []):
                result = find_resource(child, target)
                if result: return result
            return None

        return find_resource(data_root.get("root_module", {}), address)

    def destroy(self, force=False):
        if self.interactive and not force:
            print("\n" + "!"*40 + "\n🛑 DESTROY CONFIRMATION REQUIRED\n" + "!"*40)
            response = input(">>> Do you want to destroy the Terraform stack? (y/n): ").lower().strip()
            
            if response != 'y':
                print(">>> Skipping destruction.")
                return None

        print(">>> Destroying infrastructure...")
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False)

    def cleanup(self):
        for f in ["tfplan.bin", "tfplan.json"]:
            p = os.path.join(self.wd, f)
            if os.path.exists(p): os.remove(p)


class Ansible:
    def __init__(self, wd="./ctlabs-ansible", inventory="./inventories/sys01.ini", playbook="./playbooks/init.yml", roles="up,setup,base", interactive=False, auth_callback=None):
        self.wd            = wd
        self.inventory     = inventory
        self.playbook      = playbook
        self.roles         = roles
        self.interactive   = interactive
        self.auth_callback = auth_callback

    def run(self, opts=None, inventory=None, playbook=None, roles=None):
        if opts is None:
            opts = ["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"]

        target_inv   = inventory or self.inventory
        target_pb    = playbook  or self.playbook
        target_roles = roles or self.roles
            
        while True:
            try:
                if self.auth_callback:
                    self.auth_callback(interactive=self.interactive)

                cmd = ["ansible-playbook", "-i", target_inv, target_pb, "-t", target_roles] + opts
                res = subprocess.run(cmd, cwd=self.wd, capture_output=False, text=True, env=os.environ)
                
                if res.returncode < 0: 
                    raise KeyboardInterrupt
                    
                if res.returncode == 0:
                    print("✅ Ansible run completed successfully.")
                    return res

                if not self.interactive:
                    pytest.fail("Ansible failed.")

            except KeyboardInterrupt:
                print("\n\n🛑 [STOP] Manual escape triggered. Exiting suite...")
                sys.exit(1)

            except Exception as e:
                print(f"\n⚠️ Execution Error: {e}")
                if not self.interactive: pytest.fail(str(e))

            print("\n" + "!"*40 + "\n--- ANSIBLE FAILURE ---\n" + "!"*40)
            if input("Action: [r]etry, [q]uit: ").strip().lower() != 'r':
                pytest.fail("User aborted after task failure.")
            print("🔄 Retrying command...")


class ConfTest:
    def __init__(self, wd=".", input="tfplan.json", interactive=False, auth_callback=None):
        self.wd            = wd
        self.input         = input
        self.interactive   = interactive
        self.auth_callback = auth_callback

    def run(self, ns="main"):
        while True:
            try:
                if self.auth_callback:
                    self.auth_callback(interactive=self.interactive)

                res = subprocess.run(
                    ['conftest', 'test', self.input, "-n", ns], 
                    cwd=self.wd, env=os.environ, capture_output=False, text=True
                )
                
                if res.returncode == 0:
                    print(f"✅ Policy check '{ns}' passed.")
                    return res
                
                if not self.interactive:
                    pytest.fail(f"Policy check '{ns}' failed.")

            except Exception as e:
                print(f"\n⚠️ Policy/Callback Error: {e}")
                if not self.interactive: raise

            print(f"\n" + "!"*40 + f"\n--- POLICY FAILURE (Namespace: {ns}) ---\n" + "!"*40)
            if input("Action: [r]etry, [q]uit: ").strip().lower() != 'r':
                pytest.fail("User aborted policy test.")
            print("🔄 Retrying command...")


class HashiVault:
    def __init__(self, grace_period=300):
        self.grace_period = grace_period
        self.base_path = os.path.expanduser("~/.ctlabs_vault")
        self.key_path = os.path.join(self.base_path, ".vault_key")
        self.gpg_path = os.path.join(self.base_path, ".env.gpg")
        
        self._memory_token = None
        self._memory_url = None

    def approle_login(self, vault_url, role_id, secret_id):
        client = hvac.Client(url=vault_url, verify=False)
        try:
            res = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            self._memory_token = res['auth']['client_token']
            self._memory_url = vault_url
            print("✅ AppRole login successful. Token stored in memory.")
            return True
        except Exception as e:
            print(f"❌ AppRole authentication failed: {e}")
            return False

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
            verify=not skip_verify
        )

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

    def read_raw_path(self, path):
        """Reads the raw data from any Vault API path, handling both Vault-wrapped and raw responses."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(path)
            if not res: 
                return None
            
            # If it's a standard Vault response, unwrap the 'data' block
            if 'data' in res and 'request_id' in res:
                return res['data']
            
            # If it's a raw standard endpoint (like OIDC JWKS), return the whole thing
            return res
        except Exception as e:
            print(f"❌ Error reading raw path '{path}': {e}")
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

    def approle_login(self, vault_url, role_id, secret_id):
        client = hvac.Client(url=vault_url, verify=False)
        try:
            res = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            self._memory_token = res['auth']['client_token']
            self._memory_url = vault_url
            # BUGFIX: Track actual expiration
            lease = res['auth'].get('lease_duration', 3600)
            self._memory_expiry = int(time.time()) + lease
            print("✅ AppRole login successful. Token stored in memory.")
            return True
        except Exception as e:
            print(f"❌ AppRole authentication failed: {e}")
            return False

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
            policy_hcl += f"""
            # Allow generating dynamic GCP OAuth tokens for {gcp_roleset}
            path "gcp/token/{gcp_roleset}" {{
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

    def list_secrets(self, path, mount_point='secret'):
        """Lists keys available at a specific KVv2 path."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)
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

    def get_gcp_token(self, roleset_name, mount_point='gcp'):
        """Generates a dynamic, short-lived GCP OAuth token from Vault."""
        client = self._get_client()
        if not client: return None
        try:
            # Reads from gcp/token/<roleset_name>
            res = client.read(f"{mount_point}/token/{roleset_name}")
            return res.get('data', {}).get('token_oauth2_secret')
        except Exception as e:
            print(f"❌ Error generating GCP token for roleset '{roleset_name}': {e}")
            return None




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




class RemoteDesktop:
    @staticmethod
    def _wait_for_port(hostname, port=3389, timeout=300):
        """
        Blocks and polls the target port until it accepts a TCP connection.
        Prevents RDP clients from failing instantly if the VM is still booting.
        """
        print(f"\n[RDP] Waiting for {hostname}:{port} to become available (timeout: {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Attempt a quick 2-second TCP connection
                with socket.create_connection((hostname, port), timeout=2):
                    print(f"[RDP] ✅ Host {hostname} is ready to accept RDP connections!")
                    return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                # Port is closed or host is down. Sleep and retry.
                time.sleep(5)
                
        print(f"\n⚠️ [RDP] Timed out waiting for {hostname}:{port} after {timeout} seconds.")
        return False

    @staticmethod
    def launch(hostname, username, password, timeout=300):
        """Detects OS and launches the appropriate RDP client after ensuring the port is open."""
        
        # 1. Wait for the Windows Remote Desktop service to actually start
        if not RemoteDesktop._wait_for_port(hostname, port=3389, timeout=timeout):
            print("[RDP] Aborting client launch due to timeout.")
            return

        # 2. Launch the client
        if sys.platform == "darwin":
            RemoteDesktop._launch_royaltsx(hostname, username, password)
        else:
            RemoteDesktop._launch_freerdp(hostname, username, password)

    @staticmethod
    def _launch_royaltsx(hostname, username, password):
        print(f"[RDP] Launching Royal TSX session to {hostname}...")

        user_enc = urllib.parse.quote(username, safe='')
        pass_enc = urllib.parse.quote(password, safe='')
        host_enc = urllib.parse.quote(hostname, safe='')

        rtsx_uri = (
            f"rtsx://rdp%3a%2f%2f{user_enc}:{pass_enc}@{host_enc}"
            f"?using=adhoc"
            f"&property_AuthenticationLevel=0"
            f"&property_Name={host_enc}"
        )

        subprocess.Popen(
            ["open", rtsx_uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def _launch_freerdp(hostname, username, password):
        print(f"[RDP] Launching FreeRDP session to {hostname}...")
        
        cmd = [
            "xfreerdp",
            f"/v:{hostname}",
            f"/u:{username}",
            f"/p:{password}",
            "/cert:ignore",       
            "+clipboard",         
            "/dynamic-resolution" 
        ]
        
        subprocess.Popen(
            cmd, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
