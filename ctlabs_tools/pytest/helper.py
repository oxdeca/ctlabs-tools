# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/helper.py
# License : MIT
# -----------------------------------------------------------------------------

import jmespath
import json
import hvac
import os
import pytest
import subprocess
import sys
import time
import urllib
import warnings


def load_vault_secrets(grace_period=300):
    """
    Decrypts secrets and enforces a TTL based on Vault's actual expiry.
    :param grace_period: Buffer in seconds (default 5m). 
    """
    base_path = os.path.expanduser("~/.ctlabs_vault")
    key_path = os.path.join(base_path, ".vault_key")
    gpg_path = os.path.join(base_path, ".env.gpg")

    if not os.path.exists(base_path):
        os.makedirs(base_path, mode=0o700, exist_ok=True)

    if not os.path.exists(key_path) or not os.path.exists(gpg_path):
        print("❌ Vault secrets not found locally.")
        return False

    with open(key_path, "r") as f:
        passphrase = f.read().strip()

    res = subprocess.run(
        ['gpg', '--decrypt', '--batch', '--passphrase', passphrase, gpg_path],
        capture_output=True, text=True
    )

    if res.returncode == 0:
        secrets = {}
        for line in res.stdout.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                secrets[key] = val.strip()
        
        current_time = int(time.time())
        if "EXPIRES_AT" in secrets:
            expiry_timestamp = int(secrets["EXPIRES_AT"])
        else:
            expiry_timestamp = int(secrets.get("CREATED_AT", 0)) + 28800

        if (current_time + grace_period) > expiry_timestamp:
            print("❌ Vault secrets not found locally.")
            if os.path.exists(key_path): os.remove(key_path)
            if os.path.exists(gpg_path): os.remove(gpg_path)
            
            remaining = expiry_timestamp - current_time
            msg = "expired" if remaining <= 0 else f"expiring in {remaining}s (buffer is {grace_period}s)"
            return False

        os.environ.update(secrets)
        os.environ["VAULT_SKIP_VERIFY"] = "true" 
        return True
    else:
        print(f"❌ GPG Decryption failed: {res.stderr}")
        return False



class Terraform:
    def __init__(self, wd=".", use_vault=False, interactive=False):
        self.wd          = wd
        self.tf_plan     = {}
        self.tf_state    = {}
        self.plan_bin    = "tfplan.bin"
        self.use_vault   = use_vault
        self.interactive = interactive
        self.vault       = HashiVault()

        if use_vault:
            load_vault_secrets()

    def _run_cmd(self, args, capture=True):
        while True:
            try:
                if self.use_vault:
                    self.vault.ensure_valid_token(interactive=self.interactive)
    
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
            nflue
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
            # Refresh internal dict immediately after a successful plan
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
        Evaluates the current Terraform plan to determine if any infrastructure 
        will be created, updated, replaced, or destroyed.
        Returns True if changes exist, False if the plan is a complete no-op.
        """
        # Ensure the plan is loaded into memory
        if not self.tf_plan:
            self.show_plan()
            
        # If the plan is completely empty, there are no changes
        if not self.tf_plan.get("resource_changes"):
            return False

        # Look for any resource whose action is NOT just "no-op" or "read"
        # "read" actions happen when Terraform updates a data source, which doesn't affect infrastructure
        for resource in self.tf_plan.get("resource_changes", []):
            actions = resource.get("change", {}).get("actions", [])
            
            if actions != ["no-op"] and actions != ["read"]:
                return True
                
        return False


    def show_state(self):
        res = self._run_cmd(["terraform", "show", "-json"], capture=True)
        if res.returncode == 0:
            self.tf_state = json.loads(res.stdout)
        return self.tf_state

    def show_plan(self, file="tfplan.json"):
        """Syncs the binary plan to JSON and loads it into memory."""
        # Convert bin to json for easier parsing
        self._run_cmd(["terraform", "show", "-json", self.plan_bin], capture=True)
        show_res = self._run_cmd(["terraform", "show", "-json", self.plan_bin], capture=True)
        
        if show_res.returncode == 0:
            self.tf_plan = json.loads(show_res.stdout)
            with open(os.path.join(self.wd, file), "w") as f:
                json.dump(self.tf_plan, f, indent=2)
        return self.tf_plan

    def search_plan(self, query):
        """
        Queries the Terraform plan JSON using JMESPath.
        Example: tf.search_plan("resource_changes[?address=='google_compute_instance.vm'].change.after | [0]")
        """
        if not self.tf_plan:
            self.show_plan()
            
        return jmespath.search(query, self.tf_plan)

    def search_state(self, query):
        """
        Queries the live Terraform state JSON.
        Example: tf.search_state("values.root_module.resources[?type=='google_compute_instance']")
        """
        if not self.tf_state:
            self.show_state()
            
        return jmespath.search(query, self.tf_state)

    def _find_in_data(self, data_root, address):
        """Recursive helper to find outputs or resources by address."""
        if not data_root: return None

        # 1. Check Outputs
        outputs = data_root.get("outputs", {})
        if address in outputs:
            return outputs[address].get("value")

        # 2. Recursive Resource Search
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
        """
        Destroys infrastructure. 
        Prompts for confirmation if interactive=True and force=False.
        """
        if self.interactive and not force:
            print("\n" + "!"*40 + "\n🛑 DESTROY CONFIRMATION REQUIRED\n" + "!"*40)
            response = input(">>> Do you want to destroy the Terraform stack? (y/n): ").lower().strip()
            
            if response != 'y':
                print(">>> Skipping destruction. Infrastructure remains active.")
                return None

        print(">>> Destroying infrastructure...")
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False)

    def cleanup(self):
        for f in ["tfplan.bin", "tfplan.json"]:
            p = os.path.join(self.wd, f)
            if os.path.exists(p): os.remove(p)



class Ansible:
    def __init__(self, wd="./ctlabs-ansible", inventory="./inventories/sys01.ini", playbook="./playbooks/init.yml", roles="up,setup,base", use_vault=False, interactive=False):
        self.wd          = wd
        self.inventory   = inventory
        self.playbook    = playbook
        self.roles       = roles
        self.use_vault   = use_vault
        self.interactive = interactive
        self.vault       = HashiVault()

        if use_vault:
            load_vault_secrets()

    def run(self, opts=["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"]):
        while True:
            try:
                if self.use_vault:
                    self.vault.ensure_valid_token(interactive=self.interactive)

                cmd = ["ansible-playbook", "-i", self.inventory, self.playbook, "-t", self.roles] + opts
                res = subprocess.run(cmd, cwd=self.wd, capture_output=False, text=True, env=os.environ)
                
                # 2. Handle Ctrl+C (SIGINT)
                if res.returncode < 0: 
                    raise KeyboardInterrupt
                    
                if res.returncode == 0:
                    print("✅ Ansible run completed successfully.")
                    return res

                if not self.interactive:
                    pytest.fail("Ansible failed.")

            except KeyboardInterrupt:
                print("\n\n🛑 [STOP] Manual escape triggered. Exiting suite...")
                import sys
                sys.exit(1) # Hard exit so pytest doesn't try to run next tests

            except Exception as e:
                print(f"\n⚠️ Execution Error: {e}")
                if not self.interactive: pytest.fail(str(e))

            # 3. Standard Failure Loop
            print("\n" + "!"*40 + "\n--- ANSIBLE FAILURE ---\n" + "!"*40)
            if input("Action: [r]etry, [q]uit: ").strip().lower() != 'r':
                pytest.fail("User aborted after task failure.")
            print("🔄 Retrying command...")



class ConfTest:
    def __init__(self, wd=".", input="tfplan.json", use_vault=False, interactive=False):
        self.wd          = wd
        self.input       = input
        self.use_vault   = use_vault
        self.interactive = interactive

        if use_vault:
            load_vault_secrets()

    def run(self, ns="main"):
        """Runs conftest with the same retry logic as Terraform/Ansible."""
        while True:
            try:
                if self.use_vault:
                    load_vault_secrets()

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
                print(f"\n⚠️ Policy/Vault Error: {e}")
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
        
        # In-memory storage for Production/AppRole flows
        self._memory_token = None
        self._memory_url = None

    def approle_login(self, vault_url, role_id, secret_id):
        """Authenticates via AppRole and stores the token purely in memory (Production flow)."""
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
        """Privately handles reading and decrypting the Dev/Test GPG file."""
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
        """Calculates if the Dev/Test token is valid."""
        # If we are using an in-memory token from AppRole, assume it's fresh for the session
        if self._memory_token:
            return True, 3600 

        secrets = self._decrypt_secrets()
        if not secrets: return False, 0
        
        current_time = int(time.time())
        expiry_timestamp = int(secrets.get("EXPIRES_AT", int(secrets.get("CREATED_AT", 0)) + 28800))
        remaining = expiry_timestamp - current_time
        return remaining > self.grace_period, remaining

    def load_secrets(self):
        """Checks expiry and loads secrets into os.environ for Terraform/Ansible subprocesses."""
        # 1. Handle in-memory (AppRole/Production)
        if self._memory_token and self._memory_url:
            os.environ["VAULT_ADDR"] = self._memory_url
            os.environ["VAULT_TOKEN"] = self._memory_token
            os.environ["VAULT_SKIP_VERIFY"] = "true"
            return True

        # 2. Handle Local File Cache (Dev/Test)
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
        """Initializes hvac Client, favoring AppRole memory over Dev GPG cache."""
        # 1. Production Flow: Check memory first
        if self._memory_token and self._memory_url:
            return hvac.Client(url=self._memory_url, token=self._memory_token, verify=False)
            
        # 2. Dev Flow: Fallback to decrypted cache
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
        """Reads a secret dictionary from Vault."""
        client = self._get_client()
        if not client: return None

        try:
            if mount_point.lower() == 'cubbyhole':
                # Cubbyhole behaves like KV-v1, no /data/ wrapper
                response = client.read(f"cubbyhole/{path}")
                if response and 'data' in response:
                    return response['data']
                return None
            else:
                # Standard KV-v2
                response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)
                return response['data']['data']
        except Exception as e:
            print(f"❌ Error reading {mount_point}/{path}: {e}")
            return None

    def write_secret(self, path, secret_data, mount_point='secret'):
        """Writes a dictionary of key-value pairs to Vault."""
        client = self._get_client()
        if not client: return False

        try:
            if mount_point.lower() == 'cubbyhole':
                # Cubbyhole uses the generic write method, passing the dict as kwargs
                client.write(f"cubbyhole/{path}", **secret_data)
            else:
                # Standard KV-v2
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
        """Iterates over a Terraform-style vault block and returns a mapped dictionary."""
        results = {}
        mount_point = config.get("mount", "kvv2")
        
        for secret_def in config.get("secrets", []):
            name = secret_def["name"]
            path = secret_def["path"]
            
            data = self.read_secret(path=path, mount_point=mount_point)
            if data:
                # If the Vault secret dict has a key matching the 'name', extract it. Otherwise, return the whole dict.
                results[name] = data.get(name, data)
            else:
                results[name] = None
                
        return results

    def ensure_valid_token(self, interactive=False):
        """Blocks until a valid Vault token is available. Prompts user if interactive."""
        while not self.load_secrets():
            if not interactive:
                pytest.fail("Vault token expired or missing in headless mode. Cannot proceed.")
                
            print("\n" + "!"*40 + "\n🔑 VAULT TOKEN EXPIRED OR MISSING\n" + "!"*40)
            print("Please run 'vault-login' in a separate terminal.")
            choice = input("Action: [r]etry, [q]uit: ").strip().lower()
            
            if choice == 'q':
                pytest.exit("User aborted test run due to Vault expiry.")
            print("🔄 Checking for new Vault secrets...")
        return True



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
        """Fetches a payload from Google Secret Manager."""
        if not self.is_available:
            return None
            
        # Format required by the API: projects/*/secrets/*/versions/*
        name = f"projects/{project}/secrets/{secret_id}/versions/{version}"
        
        try:
            response = self.client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            print(f"❌ Failed to fetch {secret_id} from GSM: {e}")
            return None



class RemoteDesktop:
    """Handles launching native RDP clients based on the host operating system."""
    
    @staticmethod
    def launch(hostname, username, password):
        """Detects OS and launches the appropriate RDP client."""
        if sys.platform == "darwin":
            RemoteDesktop._launch_royaltsx(hostname, username, password)
        else:
            RemoteDesktop._launch_freerdp(hostname, username, password)

    @staticmethod
    def _launch_royaltsx(hostname, username, password):
        print(f"\n[RDP] Launching Royal TSX session to {hostname}...")

        # Pre-escape problematic characters for Royal TSX's internal parser
        protected_password = password.replace('#', '\\#').replace('&', '0x46').replace('*', '\\*')

        # Perform standard URL encoding
        user_enc = urllib.parse.quote(username, safe='')
        pass_enc = urllib.parse.quote(protected_password, safe='')
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
        print(f"\n[RDP] Launching FreeRDP session to {hostname}...")
        
        cmd = [
            "xfreerdp",
            f"/v:{hostname}",
            f"/u:{username}",
            f"/p:{password}",
            "/cert:ignore",       # Ignore self-signed cert warnings
            "+clipboard",         # Enable copy/paste
            "/dynamic-resolution" # Allow resizing
        ]
        
        subprocess.Popen(
            cmd, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
