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
    
                # Success!
                if res.returncode == 0:
                    return res
                
                # 🧠 SMART UX: Intercept GCP Auth Errors from Terraform
                # (Only works if we are capturing output; otherwise the user sees it directly anyway)
                if current_capture:
                    error_output = (res.stderr or "") + (res.stdout or "")
                    auth_errors = [
                        "invalid authentication credentials", 
                        "oauth2: cannot fetch token", 
                        "could not find default credentials",
                        "invalid_grant",
                        "googleapi: error 401",
                        "reauthentication failed",
                        "refresh token",
                        "application default credentials",
                        "unauthenticated"
                    ]
                    
                    if any(err in error_output.lower() for err in auth_errors):
                        print("\n" + "!"*60)
                        print("🛑 TERRAFORM GCP AUTHENTICATION FAILED")
                        print("!"*60)
                        print("Terraform was denied access to Google Cloud.")
                        print("Your Vault-generated token has likely expired (Tokens only last 60 minutes).")
                        print("To fix this, generate a fresh token in your terminal:\n")
                        print("  vault-secret get-token gcp/<project-id>")
                        print("  export GOOGLE_OAUTH_ACCESS_TOKEN=\"...\"\n")
                        
                        if not self.interactive:
                            pytest.fail("Terraform aborted due to expired GCP credentials.")
                        sys.exit(1)

                if not self.interactive:
                    return res 
    
            except KeyboardInterrupt:
                print("\n\n🛑 [STOP] User triggered exit. Killing pytest session...")
                sys.exit(1)
    
            except Exception as e:
                print(f"\n⚠️ Execution Error: {e}")
                if not self.interactive: raise
    
                
            print("\n" + "!"*40 + f"\n--- TERRAFORM FAILURE: {' '.join(args)} ---\n" + "!"*40)
            if current_capture and hasattr(res, 'stderr') and res.stderr:
                print(res.stderr.strip())

            choice = input("Action: [r]etry, [q]uit current test, [A]bort entire suite: ").strip().lower()
            if choice == 'a':
                pytest.exit("🛑 User triggered master abort. Stopping all remaining tests.")
            elif choice != 'r':
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

        print("\n>>> Destroying infrastructure...")
        return self._run_cmd(["terraform", "destroy", "-auto-approve"], capture=False)

    def cleanup(self):
        for f in ["tfplan.bin", "tfplan.json"]:
            p = os.path.join(self.wd, f)
            if os.path.exists(p): os.remove(p)

# ----------------------------------------------------------------------------


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
            choice = input("Action: [r]etry, [q]uit current test, [A]bort entire suite: ").strip().lower()
            
            if choice == 'a':
                pytest.exit("🛑 User triggered master abort. Stopping all remaining tests.")
            elif choice != 'r':
                pytest.fail("User aborted after task failure.")
                
            print("🔄 Retrying command...")

# ----------------------------------------------------------------------------


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
            choice = input("Action: [r]etry, [q]uit current test, [A]bort entire suite: ").strip().lower()
            
            if choice == 'a':
                pytest.exit("🛑 User triggered master abort. Stopping all remaining tests.")
            elif choice != 'r':
                pytest.fail("User aborted policy test.")
                
            print("🔄 Retrying command...")

# ----------------------------------------------------------------------------


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
