# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/helper.py
# License : MIT
# -----------------------------------------------------------------------------

import os
import subprocess
import json
import time

def load_vault_secrets(expiry_seconds=28800):
    """Decrypts secrets and enforces a TTL."""
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
        
        created_at = int(secrets.get("CREATED_AT", 0))
        if (int(time.time()) - created_at) > expiry_seconds:
            if os.path.exists(key_path): os.remove(key_path)
            if os.path.exists(gpg_path): os.remove(gpg_path)
            raise Exception(f"Vault session expired. Run vault_login.py.")

        os.environ.update(secrets)
        os.environ["VAULT_SKIP_VERIFY"] = "true" 
    else:
        raise Exception(f"Failed to decrypt secrets: {res.stderr}")

class Terraform:
    def __init__(self, wd=".", skip_vault=True):
        self.wd       = wd
        self.tf_plan  = {}
        self.tf_state = {}
        self.plan_bin = "tfplan.bin"
        if not skip_vault:
            load_vault_secrets()

    def _run_cmd(self, args, capture=True):
        return subprocess.run(args, cwd=self.wd, capture_output=capture, text=True, env=os.environ)

    def init(self):
        return self._run_cmd(["terraform", "init", "-upgrade"], capture=False)

    def import_(self, resource, id):
        return self._run_cmd(["terraform", "import", resource, id])

    def plan(self, file=None):
        plan_bin = file or self.plan_bin
        res = self._run_cmd(["terraform", "plan", "-out", plan_bin])
        if res.returncode != 0:
            err = res.stderr if res.stderr.strip() else res.stdout
            raise Exception(f"Terraform Plan Failed:\n{err}")

        show_res = self._run_cmd(["terraform", "show", "-json", plan_bin])
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
        self.tf_state = self.show_state()
        return res

    def destroy(self):
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False)

    def show_state(self):
        res = self._run_cmd(["terraform", "show", "-json"])
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
    def __init__(self, wd="./ctlabs-ansible", inventory="./inventories/sys01.ini", playbook="./playbooks/init.yml", roles="up,setup,base", skip_vault=True):
        self.wd        = wd
        self.inventory = inventory
        self.playbook  = playbook
        self.roles     = roles
        if not skip_vault:
            load_vault_secrets()

    def run(self, opts=["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"]):
        return subprocess.run(["ansible-playbook", "-i", self.inventory, self.playbook, "-t", self.roles] + opts, cwd=self.wd, env=os.environ)

class ConfTest:
    def __init__(self, wd=".", input="tfplan.json", skip_vault=True):
        self.wd    = wd
        self.input = input
        if not skip_vault:
            load_vault_secrets()

    def test(self, ns="main"):
        return subprocess.run(['conftest', 'test', self.input, "-n", ns], cwd=self.wd, env=os.environ)
