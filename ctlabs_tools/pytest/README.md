# 🧪 CTLabs Infrastructure Testing

A collection of Python helpers for testing Infrastructure-as-Code (Terraform, Ansible, ConfTest) via Pytest. 

*Note: Vault authentication has been decoupled into the `ctlabs_tools.vault` module, but remains fully backward-compatible in your test fixtures via a facade pattern.*

---

## 🧩 Pytest Fixtures & Setup
Create a `conftest.py` to seamlessly wrap your Terraform execution with dynamic Vault identities.

```python
import os
import pytest
from ctlabs_tools.pytest.helper import Terraform, HashiVault

def pytest_addoption(parser):
    parser.addoption("--interactive", action="store_true", default=False)

@pytest.fixture(scope="session")
def is_interactive(request):
    return request.config.getoption("--interactive")

@pytest.fixture(scope="session")
def vault_auth():
    # HashiVault is imported from the helper facade!
    v = HashiVault()
    v.ensure_valid_token(interactive=True) 
    return v

@pytest.fixture(scope="session")
def tf(is_interactive, vault_auth):
    # 1. Ask Vault for a JIT GCP token
    gcp_token = vault_auth.get_gcp_token(
        roleset_name="terraform-runner", 
        mount_point="gcp/ctlabs-prj-2025101601"
    )
    
    # 2. Inject it securely into the local environment
    if gcp_token:
        os.environ["GOOGLE_OAUTH_ACCESS_TOKEN"] = gcp_token
        os.environ["CLOUDSDK_AUTH_ACCESS_TOKEN"] = gcp_token

    # 3. Start Terraform
    t = Terraform(
        wd="./terraform", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token 
    )
    yield t
    t.cleanup()
    
    # 4. Clean up the environment variables
    os.environ.pop("GOOGLE_OAUTH_ACCESS_TOKEN", None)
    os.environ.pop("CLOUDSDK_AUTH_ACCESS_TOKEN", None)
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
