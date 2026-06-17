# 🧪 CTLabs Infrastructure Testing

A collection of Python helpers for testing Infrastructure-as-Code (Terraform, Ansible, ConfTest) via Pytest. 

*Note: Vault authentication has been decoupled into the `ctlabs_tools.vault` module, but remains fully backward-compatible in your test fixtures via a facade pattern.*

---

## 🧩 Pytest Fixtures & Setup
Create a `conftest.py` to seamlessly wrap your Terraform execution with dynamic Vault identities.

```python
import pytest
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest
from ctlabs_tools.vault.core    import HashiVault

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
        wd=".",
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token # Injects the auth check!
    )
    yield t
    t.cleanup()

@pytest.fixture(scope="session")
def tf_stack(tf, is_interactive, vault_auth):
    tf.init()
    tf.plan()
    has_changes = tf.has_changes()

    if has_changes:
        print("\n[CONFTEST] Evaluating Terraform plan against Rego policies...")
        policy_checker = ConfTest(wd=".", input="tfplan.json", interactive=is_interactive, auth_callback=vault_auth.ensure_valid_token)
        policy_checker.run(ns="main")

    tf.show_changes()
    tf.apply()
    tf.has_changes = has_changes
    yield tf
    tf.cleanup()
    print("")
    tf.destroy()
```

---

## 🏗️ Terraform Testing

### Plan Integrity & Ephemeral Values
Verify the plan doesn't violate core requirements before applying.
```python
def test_plan_secrets_and_changes(tf):
    tf.plan()
    if not tf.has_changes():
        pytest.skip("No changes detected.")
        
    # Search the plan JSON using JMESPath
    bucket_diff = tf.search_plan("resource_changes[?address=='aws_s3_bucket.data'] | [0]")
    assert "delete" not in bucket_diff["change"]["actions"]
```

### Post-Apply Verification
Verify live state after infrastructure is stood up.
```python
def test_apply_and_verify(tf):
    tf.apply()
    live_vm = tf.search_state("values.root_module.resources[?address=='aws_instance.web'] | [0]")
    assert live_vm["values"]["instance_state"] == "running"
```

---

## 🛡️ ConfTest / Policy Evaluation
Evaluate your Terraform plans against OPA/Rego policies.

```python
from ctlabs_tools.pytest.helper import ConfTest

def test_policies(tf, is_interactive, vault_auth):
    tf.plan()
    if tf.has_changes():
        policy_checker = ConfTest(
            wd=".", 
            input="tfplan.json", 
            interactive=is_interactive,
            auth_callback=vault_auth.ensure_valid_token
        )
        policy_checker.run(ns="main")
```

---

## 🐧 Ansible & Remote Desktop
Run configuration management and launch native RDP sessions dynamically based on deployment results.

```python
from ctlabs_tools.pytest.helper import Ansible, RemoteDesktop

def test_config_management(vault_auth, is_interactive):
    ansible = Ansible(
        wd="./ansible", 
        inventory="./inventories/prod.ini", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token
    )
    ansible.run(roles="setup", opts=["-b", "-e", "CTLABS_ENV=prod"]) 

def test_rdp_access(tf):
    ip = tf.search_state("values.outputs.vm_ip.value")
    RemoteDesktop.launch(hostname=ip, username="admin", password="Password123!")
```
