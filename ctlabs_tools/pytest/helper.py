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
                         If the token expires in less than this, it's treated as expired.
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
        # 1. Check for the new EXPIRES_AT (Absolute timestamp from Vault)
        # 2. Fallback to CREATED_AT + 8h if EXPIRES_AT isn't found (Legacy support)
        if "EXPIRES_AT" in secrets:
            expiry_timestamp = int(secrets["EXPIRES_AT"])
        else:
            expiry_timestamp = int(secrets.get("CREATED_AT", 0)) + 28800

        # Enforce the Grace Period
        # If (current time + 5 minutes) is past the expiry, we stop now.
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

    def _run_cmd(self, args, capture=True):
        """Internal wrapper to run TF commands with automatic Vault sync."""
        if self.use_vault:
            # Refresh/Verify token before every single command
            load_vault_secrets()
            
        return subprocess.run(args, cwd=self.wd, capture_output=capture, text=True, env=os.environ )

    def run_interactive(self, command="apply"):
        """
        Runs a Terraform command (default: apply) interactively.
        Retries on failure, allowing manual fixes in between.
        """
        valid_cmds = {
            "apply": ["terraform", "apply", "-auto-approve"],
            "plan": ["terraform", "plan", "-out", self.plan_bin],
            "init": ["terraform", "init", "-upgrade"]
        }
        
        tf_args = valid_cmds.get(command, ["terraform", command])

        try:
            while True:
                # We use capture=False here so the user sees the live TF output
                res = subprocess.run(tf_args, cwd=self.wd, capture_output=False, text=True, env=os.environ)

                if res.returncode < 0:
                    raise KeyboardInterrupt

                if res.returncode == 0:
                    print(f"✅ Terraform {command} successful.")
                    return res

                print("\n" + "!" * 40)
                print(f"--- TERRAFORM {command.upper()} FAILURE ---")
                print("!" * 40)
                
                choice = input("Action: [r]etry, [q]uit: ").strip().lower()
                
                if choice == 'q':
                    pytest.fail(f"User quit after Terraform {command} failed.")
                elif choice == 'r':
                    print(f"🔄 Re-running terraform {command}...")
                    # We call load_vault_secrets specifically here just in case 
                    # the failure was a timeout and we want to catch it before the next run
                    if self.use_vault:
                        load_vault_secrets()
                    continue

        except KeyboardInterrupt:
            print("\n[BAILING OUT] Manual escape triggered.")
            pytest.exit("User aborted test.")


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
    def __init__(self, wd="./ctlabs-ansible", inventory="./inventories/sys01.ini", playbook="./playbooks/init.yml", roles="up,setup,base", use_vault=False):
        self.wd        = wd
        self.inventory = inventory
        self.playbook  = playbook
        self.roles     = roles
        self.use_vault = use_vault
        if use_vault:
            load_vault_secrets()

    def run(self, opts=["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"]):
        # Always ensure environment is fresh before execution
        if self.use_vault:
            load_vault_secrets()
            
        return subprocess.run(["ansible-playbook", "-i", self.inventory, self.playbook, "-t", self.roles] + opts, cwd=self.wd, env=os.environ)

    def run_interactive(self, opts=["-b", "-e", "CTLABS_DOMAIN=ctlabs.internal"]):
        """Runs Ansible in a loop, allowing the user to retry on failure."""
        try:
            while True:
                res = self.run(opts=opts)

                # Return code < 0 usually means a signal (like SIGINT) hit the subprocess
                if res.returncode < 0:
                    raise KeyboardInterrupt

                if res.returncode == 0:
                    print("✅ Ansible run completed successfully.")
                    return res

                # If we get here, the playbook failed
                print("\n" + "!" * 40)
                print("--- ANSIBLE FAILURE ---")
                print("!" * 40)
                
                choice = input("Action: [r]etry current task, [q]uit and fail test: ").strip().lower()
                
                if choice == 'q':
                    pytest.fail("User opted to quit after Ansible failure.")
                elif choice == 'r':
                    print("🔄 Retrying Ansible playbook...")
                    continue 
                else:
                    print("Invalid choice. Please enter 'r' or 'q'.")

        except KeyboardInterrupt:
            print("\n\n[BAILING OUT] Manual escape triggered.")
            pytest.exit("User aborted test suite via KeyboardInterrupt.")

class ConfTest:
    def __init__(self, wd=".", input="tfplan.json", use_vault=False):
        self.wd    = wd
        self.input = input
        if use_vault:
            load_vault_secrets()

    def test(self, ns="main"):
        return subprocess.run(['conftest', 'test', self.input, "-n", ns], cwd=self.wd, env=os.environ)
