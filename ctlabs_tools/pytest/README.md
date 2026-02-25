# CTLabs Tools

A collection of helpers for infrastructure testing with Terraform, Ansible, and Vault.

## Installation

Install directly from GitHub:

```bash
# Install latest from main
pip install git+https://github.com/oxdeca/ctlabs-tools.git

# or from dev branch
pip install git+https://github.com/oxdeca/ctlabs-tools.git@dev
```

# Install directly from GitHub

```bash
pip install git+https://github.com/oxdeca/ctlabs-tools.git
#
# or from branch dev
#
pip install git+https://github.com/oxdeca/ctlabs-tools.git@dev
```

## Importing in your Tests
Once installed via pip, your imports become clean and location-independent. In your VM's test files, you simply write:

```python
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest
from ctlabs_tools.pytest.vault_login import get_args # etc.
```

## Vault Authentication
To login into vault run:

```bash
vault_login -a https://<VAULT_IP>:8081 -u <USER>
```

## Usage Examples

### Test requiring Vault
```python
tf = Terraform(wd="./infra/vault-stuff", use_vault=True)
```

### Test that works offline/without Vault
```python
tf_offline = Terraform(wd="./infra/local-test", use_vault=False)
```

---

## Pytest Integration (Recommended)
To enable the --interactive flag and shared fixtures across your entire test suite, create a conftest.py in your tests root directory.

1. Configure conftest.py
This setup registers the global flag and creates reusable fixtures.

```python
import pytest
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest

def pytest_addoption(parser):
    """Register the --interactive flag for the entire test suite."""
    parser.addoption(
        "--interactive", 
        action="store_true", 
        default=False, 
        help="Enable interactive retry loops on Terraform, Ansible, and Policy failures"
    )

@pytest.fixture(scope="session")
def is_interactive(request):
    """Returns True if --interactive was passed in the command line."""
    return request.config.getoption("--interactive")

@pytest.fixture(scope="session")
def tf(is_interactive):
    """Shared Terraform fixture."""
    return Terraform(wd="./terraform", use_vault=True)
```

2. Use in Test Files
Your test files now stay clean. Passing --interactive on the command line will automatically trigger retry loops on failures.

```python
def test_infrastructure(tf, is_interactive):
    # If a command fails and --interactive is set, the test pauses for manual fix/retry
    tf.init(interactive=is_interactive)
    tf.plan(interactive=is_interactive)
    tf.apply(interactive=is_interactive)
    
    assert tf.search_plan("instance_ip") is not None
```

## Manual Usage
If you prefer not to use conftest.py, you can import and instantiate the helpers directly.


### Terraform

```py
from ctlabs_tools.pytest.helper import Terraform

# With Vault (Verify/Refresh token on every command)
tf = Terraform(wd="./infra/vault-stuff", use_vault=True)
```

```py
from ctlabs_tools.pytest.helper import Terraform

# Offline/Local (No Vault interaction)
tf = Terraform(wd="./infra/local-test", use_vault=False)

tf.init()
tf.plan()
```


__pytest example__

```py
import pytest
from your_terraform_module import Terraform

@pytest.fixture(scope="module")
def tf():
    """Setup the Terraform instance """
    tf = Terraform(wd="./infra", use_vault=True)
    tf.init()
    yield terraform
    tf.cleanup()

def test_plan_integrity(tf):
    """Verify the plan doesn't violate core requirements."""
    tf.plan()

    # 1. Search for a specific output
    # Ensures the architect didn't change the naming convention
    api_endpoint = tf.search_plan("api_gateway_url")
    assert api_endpoint is not None
    assert "execute-api" in api_endpoint

    # 2. Search for a resource attribute deep in the plan
    # Even if this resource is nested in a module, search_plan finds it
    bucket_vals = tf.search_plan("aws_s3_bucket.data_lake")
    
    assert bucket_vals["force_destroy"] is False, "Safety check: Data lake must not be destroyable"
    assert bucket_vals["versioning"][0]["enabled"] is True

def test_apply_and_verify(tf):
    """Verify live state after infrastructure is stood up."""
    tf.apply()

    # 3. Compare Planned vs Actual (Search State)
    # Useful for verifying computed values like AWS IDs or IPs
    instance_id = tf.search_state("aws_instance.web_server")["id"]
    
    assert instance_id.startswith("i-"), f"Invalid Instance ID: {instance_id}"

def test_teardown(tf):
    """Clean up resources after testing."""
    # Since it's in a container, you might skip this if the container dies anyway,
    # but it's good practice for persistence.
    tf.destroy(force=True)
```


__search_plan()__

Before Apply (search_plan): Did Terraform say it was going to do the right thing?

```py
# Check the diff to ensure it plans to create the resource
diff = tf_stack.search_plan('google_compute_instance.vm["linux-vm01"]')
assert "create" in diff["change"]["actions"]
```

```py
# Checking what action is happening:
# Looks in resource_changes by default
vm_diff = tf_stack.search_plan('module.vm_linux.google_compute_instance.vm["linux-vm01"]')

if vm_diff and "create" in vm_diff.get("change", {}).get("actions", []):
    print("This plan will create the Linux VM!")
```

```py
# Checking the final predicted machine type:
# Looks in planned_values for the final state
vm_future = tf_stack.search_plan('module.vm_linux.google_compute_instance.vm["linux-vm01"]', section="planned_values")

assert vm_future["machine_type"] == "e2-medium", "Incorrect machine size configured!"
```

__search_state()__

After Apply (search_state): Did Terraform actually do it?
```py
# Check the live state to get the actual assigned IP address
live_vm = tf_stack.search_state('google_compute_instance.vm["linux-vm01"]')

# You can now safely grab runtime attributes that didn't exist in the plan!
actual_ip = live_vm["network_interface"][0]["network_ip"]
print(f"The VM successfully deployed with IP: {actual_ip}")
```

### Ansible

```py
from ctlabs_tools.pytest.helper import Ansible

ansible = Ansible(
    wd="./ansible", 
    inventory="./inventories/prod.ini", 
    use_vault=True
)

ansible.run(interactive=True)
```

### ConfTest (Policy Checks)

```py
from ctlabs_tools.pytest.helper import ConfTest

ct = ConfTest(wd=".", input="tfplan.json")
ct.test(ns="security_policies", interactive=True)
```


## Interactive Mode Features

When running with pytest --interactive:
* **Live Logs:** Standard output is shown in real-time.
* **Auto-Retry:** On failure, the process pauses for manual fix/retry: Action: [r]etry, [q]uit.
* **Vault Resilience:** Retries trigger a session refresh, allowing you to re-login in another terminal without killing the test.