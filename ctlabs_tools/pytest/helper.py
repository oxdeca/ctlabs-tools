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
        raise Exception("Vault secrets not found. Please run vault_login.py first.")

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
            if os.path.exists(key_path): os.remove(key_path)
            if os.path.exists(gpg_path): os.remove(gpg_path)
            
            remaining = expiry_timestamp - current_time
            msg = "expired" if remaining <= 0 else f"expiring in {remaining}s (buffer is {grace_period}s)"
            raise Exception(f"Vault session {msg}. Please run vault_login.py again.")

        os.environ.update(secrets)
        os.environ["VAULT_SKIP_VERIFY"] = "true" 
    else:
        raise Exception(f"Failed to decrypt secrets: {res.stderr}")

class Terraform:
    def __init__(self, wd=".", use_vault=False):
        self.wd        = wd
        self.tf_plan   = {}
        self.tf_state  = {}
        self.plan_bin  = "tfplan.bin"
        self.use_vault = use_vault
        if use_vault:
            load_vault_secrets()

    def _run_cmd(self, args, capture=True, interactive=False):
        """
        Internal engine. 
        If interactive=True, it forces capture=False to show output and enters the retry loop.
        """
        while True:
            try:
                if self.use_vault:
                    load_vault_secrets()
                
                is_json_req = "show" in args and "-json" in args
                current_capture = True if is_json_req else (False if interactive else capture)
                
                res = subprocess.run(args, cwd=self.wd, capture_output=current_capture, text=True, env=os.environ)

                if res.returncode == 0:
                    return res
                
                if res.returncode < 0:
                    raise KeyboardInterrupt

                if not interactive:
                    return res 

            except Exception as e:
                print(f"\n⚠️ Vault/Execution Error: {e}")
                if not interactive:
                    raise

            print("\n" + "!" * 40 + f"\n--- TERRAFORM FAILURE: {' '.join(args)} ---")
            choice = input("Action: [r]etry (fix issue/login first), [q]uit: ").strip().lower()
            if choice != 'r':
                pytest.fail("User aborted.")
            print("🔄 Retrying...")

    def init(self, interactive=False):
        return self._run_cmd(["terraform", "init", "-upgrade"], capture=False, interactive=interactive)

    def import_(self, resource, id, interactive=False):
        return self._run_cmd(["terraform", "import", resource, id], capture=False, interactive=interactive)

    def plan(self, file=None, interactive=False):
        plan_bin = file or self.plan_bin
        res = self._run_cmd(["terraform", "plan", "-out", plan_bin], capture=False, interactive=interactive)

        if res.returncode == 0:
            show_res = self._run_cmd(["terraform", "show", "-json", plan_bin], capture=True, interactive=False)
            if show_res.returncode == 0:
                self.tf_plan = json.loads(show_res.stdout)
                with open(os.path.join(self.wd, "tfplan.json"), "w") as f:
                    json.dump(self.tf_plan, f, indent=2)
        return res

    def get_planned_output(self, name):
        outputs = self.tf_plan.get("planned_values", {}).get("outputs", {})
        return outputs.get(name)

    def apply(self, interactive=False):
        res = self._run_cmd(["terraform", "apply", "-auto-approve"], capture=False, interactive=interactive)
        if res.returncode == 0:
            self.show_state()
        else:
            if not interactive:
                pytest.fail("Terraform Apply failed.")
        return res

    def destroy(self, interactive=False):
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False, interactive=interactive)

    def show_state(self):
        res = self._run_cmd(["terraform", "show", "-json"], capture=True, interactive=False)
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
    def __init__(self, wd="./ctlabs-ansible", inventory="./inventories/sys01.ini", playbook="./playbooks/init.yml", roles="up,setup,base", use_vault=False):
        self.wd        = wd
        self.inventory = inventory
        self.playbook  = playbook
        self.roles     = roles
        self.use_vault = use_vault
        if use_vault:
            load_vault_secrets()

    def run(self, opts=["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"], interactive=False):
        while True:
            try:
                if self.use_vault:
                    load_vault_secrets()

                cmd = ["ansible-playbook", "-i", self.inventory, self.playbook, "-t", self.roles] + opts
                res = subprocess.run(cmd, cwd=self.wd, capture_output=False, text=True, env=os.environ)
                
                if res.returncode < 0:
                    raise KeyboardInterrupt
                    
                if res.returncode == 0:
                    print("✅ Ansible run completed successfully.")
                    return res

                if not interactive:
                    pytest.fail("Ansible failed.")

            except Exception as e:
                print(f"\n⚠️ Vault/Auth Error: {e}")
                if not interactive: pytest.fail(str(e))

            print("\n" + "!" * 40)
            print("--- ANSIBLE FAILURE ---")
            print("!" * 40)
            if input("Action: [r]etry, [q]uit: ").lower() != 'r':
                pytest.fail("User aborted.")
            else:
                print("🔄 Retrying Ansible playbook...")


class ConfTest:
    def __init__(self, wd=".", input="tfplan.json", use_vault=False):
        self.wd        = wd
        self.input     = input
        self.use_vault = use_vault
        if use_vault:
            load_vault_secrets()

    def test(self, ns="main", interactive=False):
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
                
                if not interactive:
                    pytest.fail(f"Policy check '{ns}' failed.")

            except Exception as e:
                print(f"\n⚠️ Policy/Vault Error: {e}")
                if not interactive: raise

            print(f"\n" + "!" * 40 + f"\n--- POLICY FAILURE (Namespace: {ns}) ---")
            if input("Action: [r]etry (after fixing .rego), [q]uit: ").lower() != 'r':
                pytest.fail("User aborted policy test.")
