# -----------------------------------------------------------------------------
# File    : ctlabs-tools/pytest/helper.py
# License : MIT
# -----------------------------------------------------------------------------

import os
import subprocess
import json
import time

def load_vault_secrets(expiry_seconds=28800):
    """
    Decrypts secrets and enforces a Time-To-Live (TTL).
    If the CREATED_AT timestamp is older than expiry_seconds, 
    files are deleted and an error is raised.
    """
    # Use a hidden directory in the user's home folder for cross-tool access
    base_path = os.path.expanduser("~/.vault_cache")
    key_path = os.path.join(base_path, ".vault_key")
    gpg_path = os.path.join(base_path, ".env.gpg")

    # Ensure the directory exists (useful for the first run)
    if not os.path.exists(base_path):
        os.makedirs(base_path, mode=0o700, exist_ok=True)

    if not os.path.exists(key_path) or not os.path.exists(gpg_path):
        raise Exception(f"Vault secrets not found. Please run vault_login.py first.")

    with open(key_path, "r") as f:
        passphrase = f.read().strip()

    # Decrypt to memory
    res = subprocess.run(
        ['gpg', '--decrypt', '--batch', '--passphrase', passphrase, gpg_path],
        capture_output=True,
        text=True
    )

    if res.returncode == 0:
        secrets = {}
        for line in res.stdout.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                secrets[key] = val.strip()
        
        # --- Expiry Enforcement ---
        created_at = int(secrets.get("CREATED_AT", 0))
        current_time = int(time.time())
        
        if (current_time - created_at) > expiry_seconds:
            # Session stale: cleanup files to force new login
            if os.path.exists(key_path): os.remove(key_path)
            if os.path.exists(gpg_path): os.remove(gpg_path)
            raise Exception(f"Vault session expired (Max age: {expiry_seconds}s). Run vault_login.py.")

        # If valid, update environment
        os.environ.update(secrets)
        # Ensure helper internal logic also honors the bypass
        os.environ["VAULT_SKIP_VERIFY"] = "true" 
    else:
        raise Exception(f"Failed to decrypt secrets: {res.stderr}")



class Terraform:
    def __init__(self, wd="."):
        self.wd = wd
        load_vault_secrets()

    def _run_cmd(self, args, capture=True):
        return subprocess.run(
            args, 
            cwd=self.wd, 
            capture_output=capture, 
            text=True, 
            env=os.environ
        )

    def init(self):
        return subprocess.run(["terraform", "init", "-upgrade"], cwd=self.wd, env=os.environ)

    def plan(self, file="./tfplan.bin"):
        res = self._run_cmd(["terraform", "plan", "-out", file])
        if res.returncode != 0:
            err = res.stderr if res.stderr.strip() else res.stdout
            raise Exception(f"Terraform Plan Failed:\n{err}")

        show_res = self._run_cmd(["terraform", "show", "-json", file])
        if show_res.returncode == 0:
            self.tf_plan = json.loads(show_res.stdout)
            with open(os.path.join(self.wd, "tfplan.json"), "w") as f:
                json.dump(self.tf_plan, f)
        return res

    def apply(self):
        res = subprocess.run(["terraform", "apply", "-auto-approve"], cwd=self.wd, env=os.environ)
        state_res = self._run_cmd(["terraform", "show", "-json"])
        if state_res.returncode == 0:
            self.tf_state = json.loads(state_res.stdout)
        return res

    def destroy(self):
        return subprocess.run(["terraform", "destroy", "-auto-approve"], cwd=self.wd, env=os.environ)

    def cleanup(self):
        for f in ["tfplan.bin", "tfplan.json"]:
            p = os.path.join(self.wd, f)
            if os.path.exists(p): os.remove(p)


class Ansible:
    def __init__(self, wd="./ctlabs-ansible", inventory="./inventories/sys01.ini", 
                 playbook="./playbooks/init.yml", roles="up,setup,base"):
        self.wd = wd
        self.inventory = inventory
        self.playbook = playbook
        self.roles = roles
        load_vault_secrets()

    def run(self):
        return subprocess.run([
            "ansible-playbook", "-i", self.inventory, self.playbook, 
            "-t", self.roles, "-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"
        ], cwd=self.wd, env=os.environ)


class ConfTest:
    def __init__(self, wd=".", input="tfplan.json"):
        self.wd = wd
        self.input = input
        load_vault_secrets()

    def test(self, ns="main"):
        return subprocess.run([
            'conftest', 'test', self.input, "-n", ns
        ], cwd=self.wd, env=os.environ)
