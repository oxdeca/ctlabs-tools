# CTLabs Tools

A collection of Python helpers for infrastructure testing with Terraform, Ansible, Policy Checks (ConfTest), and Vault.

## Installation

Install directly from GitHub using pip:

```bash
# Install latest from main
pip install git+[https://github.com/oxdeca/ctlabs-tools.git](https://github.com/oxdeca/ctlabs-tools.git)

# or from the dev branch
pip install git+[https://github.com/oxdeca/ctlabs-tools.git@dev](https://github.com/oxdeca/ctlabs-tools.git@dev)
```

## Importing in your Tests
Once installed, your imports become clean and location-independent:

```python
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest
from ctlabs_tools.pytest.helper import HashiVault, GCPSecretManager, RemoteDesktop
```

---

## Pytest Integration (Recommended Workflow)
To enable the `--interactive` flag, share fixtures across your entire test suite, and cleanly handle Vault authentication, create a `conftest.py` in your tests root directory.

### 1. Configure `conftest.py`
This setup registers the global interactive flag and uses **dependency injection** to pass Vault authentication checks directly into your tools without tightly coupling them.

```python
import pytest
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest, HashiVault

def pytest_addoption(parser):
    """Register the --interactive flag for the entire test suite."""
    parser.addoption(
        "--interactive", 
        action="store_true", 
        default=False, 
        help="Enable interactive retry loops on failures"
    )

@pytest.fixture(scope="session")
def is_interactive(request):
    """Returns True if --interactive was passed in the command line."""
    return request.config.getoption("--interactive")

@pytest.fixture(scope="session")
def vault_auth():
    """Provides a single Vault instance for the test session."""
    return HashiVault()

@pytest.fixture(scope="session")
def tf(is_interactive, vault_auth):
    """Shared Terraform fixture with Vault auth injected."""
    t = Terraform(
        wd="./terraform", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token # Injects the auth check!
    )
    yield t
    t.cleanup()
```

### 2. Use in Test Files
Your test files now stay incredibly clean. Passing `--interactive` on the command line will automatically trigger retry loops and Vault token refreshes on failures.

```python
def test_infrastructure(tf):
    # Vault auth is automatically verified before these commands run
    tf.init()
    tf.plan()
    
    # Print colored summary of changes
    tf.show_changes() 
    
    tf.apply()
    
    assert tf.search_state("values.root_module.resources[0].type") is not None
```

---

## Manual Usage (Without Pytest Fixtures)
If you prefer not to use `conftest.py`, you can import and instantiate the helpers directly.

```python
from ctlabs_tools.pytest.helper import Terraform, HashiVault

# 1. Initialize Vault
vault = HashiVault()
vault.ensure_valid_token(interactive=True)

# 2. Pass the callback to Terraform
tf = Terraform(
    wd="./infra/my-stack", 
    interactive=True, 
    auth_callback=vault.ensure_valid_token
)

tf.init()
tf.plan()
```

---

## Terraform Testing Examples

### 1. Plan Integrity Testing
Verify the plan doesn't violate core requirements before applying.

```python
def test_plan_integrity(tf):
    tf.plan()
    
    # 1. Check if the plan actually has changes
    if not tf.has_changes():
        pytest.skip("No infrastructure changes detected.")

    # 2. Search for a specific resource using JMESPath
    bucket_diff = tf.search_plan("resource_changes[?address=='aws_s3_bucket.data_lake'] | [0]")
    
    # Ensure it's not being deleted!
    assert "delete" not in bucket_diff["change"]["actions"]
    
    # Check a specific planned value
    bucket_future = tf.search_plan("planned_values.root_module.resources[?address=='aws_s3_bucket.data_lake'] | [0]")
    assert bucket_future["values"]["force_destroy"] is False
```

### 2. Conftest / Policy Evaluation
Evaluate your plan against OPA/Rego policies.

```python
def test_policies(tf, is_interactive, vault_auth):
    tf.plan()
    
    if tf.has_changes():
        print("\n[CONFTEST] Evaluating Terraform plan against Rego policies...")
        
        policy_checker = ConfTest(
            wd=".", 
            input="tfplan.json", 
            interactive=is_interactive,
            auth_callback=vault_auth.ensure_valid_token
        )
        
        # Will pause interactively or abort pytest if a policy fails
        policy_checker.run(ns="main")
```

### 3. Post-Apply Verification
Verify live state after infrastructure is stood up.

```python
def test_apply_and_verify(tf):
    tf.apply()

    # Compare Planned vs Actual by searching the live state JSON
    live_vm = tf.search_state("values.root_module.resources[?address=='aws_instance.web_server'] | [0]")
    
    actual_ip = live_vm["values"]["public_ip"]
    print(f"The VM successfully deployed with IP: {actual_ip}")
```

---

## Ansible Examples

```python
from ctlabs_tools.pytest.helper import Ansible, HashiVault

vault = HashiVault()

ansible = Ansible(
    wd="./ansible", 
    inventory="./inventories/prod.ini", 
    interactive=True,
    auth_callback=vault.ensure_valid_token
)

# Runs standard playbook
ansible.run() 

# Run with custom extra vars
ansible.run(opts=["-b", "-e", "CTLABS_DOMAIN=custom.local"])
```

---

## Remote Desktop Helper

Easily launch native RDP sessions (RoyalTSX on macOS, FreeRDP on Linux) dynamically from your test suite based on deployed credentials.

```python
from ctlabs_tools.pytest.helper import RemoteDesktop

def test_rdp_access():
    # ... your password retrieval logic ...
    
    # Launches the correct native RDP client based on the OS
    RemoteDesktop.launch(
        hostname="win-srv-01.ctlabs.internal", 
        username="admin", 
        password="SuperSecretPassword123!"
    )
```

---

## Interactive Mode Features

When running tests with `pytest --interactive`:
* **Live Logs:** Standard output for Terraform and Ansible is shown in real-time.
* **Auto-Retry:** On failure, the process catches the error and pauses for a manual fix: `Action: [r]etry, [q]uit`.
* **Vault Resilience:** Because the auth callback is dynamically injected into the retry loops, hitting `[r]etry` will automatically trigger a Vault session check, allowing you to re-login in another terminal without killing your entire test suite!
