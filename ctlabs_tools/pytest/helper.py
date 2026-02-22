# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/helper.py
# License : MIT
# -----------------------------------------------------------------------------

import os
import subprocess
import json
import time
import pytest


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

        if use_vault:
            load_vault_secrets()

    def _run_cmd(self, args, capture=True):
        while True:
            try:
                # 1. THE VAULT CHECK: Loop here until the user fixes the token
                if self.use_vault:
                    while not load_vault_secrets():
                        print("\n" + "!"*40 + "\n🔑 VAULT TOKEN EXPIRED OR MISSING")
                        print("Please run 'vault_login.py' in a separate terminal.")
                        choice = input("Action: [r]etry loading secrets, [q]uit: ").strip().lower()
                        if choice == 'q':
                            pytest.fail("User aborted due to Vault expiry.")
                        print("🔄 Checking for new Vault secrets...")
    
                is_json_req = "show" in args and "-json" in args
                current_capture = True if is_json_req else (False if self.interactive else capture)
                
                res = subprocess.run(args, cwd=self.wd, capture_output=current_capture, text=True, env=os.environ)
    
                # 2. THE CTRL+C HANDLER: Signal -2 (SIGINT) comes back as a negative return code
                if res.returncode < 0:
                    raise KeyboardInterrupt
    
                if res.returncode == 0:
                    return res
                
                if not self.interactive:
                    return res 
    
            except KeyboardInterrupt:
                print("\n\n🛑 [STOP] User triggered exit. Killing pytest session...")
                sys.exit(1) # This stops pytest from jumping to the next test
    
            except Exception as e:
                print(f"\n⚠️ Execution Error: {e}")
                if not self.interactive: raise
    
            # 3. THE FAILURE LOOP: Standard command failure
            print("\n" + "!" * 40 + f"\n--- TERRAFORM FAILURE: {' '.join(args)} ---")
            choice = input("Action: [r]etry (fix issue first), [q]uit: ").strip().lower()
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
            show_res = self._run_cmd(["terraform", "show", "-json", plan_bin], capture=True)
            if show_res.returncode == 0:
                self.tf_plan = json.loads(show_res.stdout)
                with open(os.path.join(self.wd, "tfplan.json"), "w") as f:
                    json.dump(self.tf_plan, f, indent=2)
        return res

    def get_planned_output(self, name):
        outputs = self.tf_plan.get("planned_values", {}).get("outputs", {})
        return outputs.get(name)

    def apply(self):
        res = self._run_cmd(["terraform", "apply", "-auto-approve"], capture=False)
        if res.returncode == 0:
            self.show_state()
        else:
            if not self.interactive:
                pytest.fail("Terraform Apply failed.")
        return res

    def destroy(self):
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False)

    def destroy(self, force=False):
        """
        Destroys infrastructure. 
        Prompts for confirmation if interactive=True and force=False.
        """
        if self.interactive and not force:
            print("\n" + "!" * 40)
            print("🛑 DESTROY CONFIRMATION REQUIRED")
            print("!" * 40)
            response = input(">>> Do you want to destroy the Terraform stack? (y/n): ").lower().strip()
            
            if response != 'y':
                print(">>> Skipping destruction. Infrastructure remains active.")
                return None # Return early without running the command

        print(">>> Destroying infrastructure...")
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False)


    def show_state(self):
        res = self._run_cmd(["terraform", "show", "-json"], capture=True)
        if res.returncode == 0:
            self.tf_state = json.loads(res.stdout)
        return self.tf_state

    def show_plan(self, file="tfplan.json"):
        path = os.path.join(self.wd, file)
        with open(path, "r") as f:
            self.tf_plan = json.load(f)
        return self.tf_plan

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

        if use_vault:
            load_vault_secrets()

    def run(self, opts=["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"]):
        while True:
            try:
                # 1. Handle Vault check interactively
                if self.use_vault:
                    while not load_vault_secrets():
                        print("\n🔑 Vault Token missing/expired!")
                        choice = input("Action: [l]ogin now and retry, [q]uit: ").lower().strip()
                        if choice != 'l':
                            pytest.fail("User aborted due to Vault expiry.")
                        # After user runs vault_login.py in another terminal, loop continues

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
            print("\n" + "!" * 40 + "\n--- ANSIBLE FAILURE ---\n" + "!" * 40)
            if input("Action: [r]etry, [q]uit: ").lower() != 'r':
                pytest.fail("User aborted after task failure.")

class ConfTest:
    def __init__(self, wd=".", input="tfplan.json", use_vault=False, interactive=False):
        self.wd          = wd
        self.input       = input
        self.use_vault   = use_vault
        self.interactive = interactive

        if use_vault:
            load_vault_secrets()

    def test(self, ns="main"):
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

            print(f"\n" + "!" * 40 + f"\n--- POLICY FAILURE (Namespace: {ns}) ---")
            if input("Action: [r]etry (after fixing .rego), [q]uit: ").lower() != 'r':
                pytest.fail("User aborted policy test.")
