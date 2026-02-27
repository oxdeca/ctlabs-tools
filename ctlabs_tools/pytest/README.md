# CTLabs Tools

A comprehensive collection of Python helpers for infrastructure testing with Terraform, Ansible, Policy Checks (ConfTest), and HashiCorp Vault.

## Installation

Install directly from GitHub using pip:

```bash
# Install latest from main
pip install git+[https://github.com/oxdeca/ctlabs-tools.git](https://github.com/oxdeca/ctlabs-tools.git)

# or from the dev branch
pip install git+[https://github.com/oxdeca/ctlabs-tools.git@dev](https://github.com/oxdeca/ctlabs-tools.git@dev)
```

## Importing in your Tests
Once installed, your imports are clean and location-independent:

```python
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest
from ctlabs_tools.pytest.helper import HashiVault, GCPSecretManager, RemoteDesktop
```

---

## Vault Authentication & AppRole Management
The `HashiVault` class supports both interactive human login and automated machine authentication (AppRole).

### 1. Interactive Human Login
Use the included utility to authenticate manually via LDAP/Userpass. This caches a secure GPG-encrypted token for your local session.

```bash
python -m ctlabs_tools.pytest.vault_login --addr [https://vault.example.com](https://vault.example.com)
```

### 2. Automated AppRole Setup (Admin)
Use `vault-approle` to manage machine identities for CI/CD or Orchestrators (like Rundeck).

```bash
# Set up a new AppRole with a generated minimal policy for a specific path
python -m ctlabs_tools.pytest.vault_approle setup my-service --path "kv/apps/my-service"

# Set up a "Manager" role (e.g., for Rundeck) to issue SecretIDs for another role
python -m ctlabs_tools.pytest.vault_approle setup rundeck-mgr --type manager --target pytest-role

# Retrieve RoleID and generate a new SecretID (JSON output)
python -m ctlabs_tools.pytest.vault_approle get-creds my-service
```

---

## Pytest Integration (Recommended Workflow)
To handle the `--interactive` flag and cleanly manage Vault authentication across your suite, create a `conftest.py`.

### Configure `conftest.py`
```python
import pytest
from ctlabs_tools.pytest.helper import Terraform, ConfTest, HashiVault

def pytest_addoption(parser):
    parser.addoption("--interactive", action="store_true", default=False)

@pytest.fixture(scope="session")
def is_interactive(request):
    return request.config.getoption("--interactive")

@pytest.fixture(scope="session")
def vault_auth():
    v = HashiVault()
    v.ensure_valid_token(interactive=True) 
    return v

@pytest.fixture(scope="session")
def tf(is_interactive, vault_auth):
    t = Terraform(
        wd="./terraform", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token 
    )
    yield t
    t.cleanup()
```

---

## Terraform Testing Examples

### 1. Plan Integrity & Ephemeral Values
Verify the plan doesn't violate core requirements before applying. Ephemeral values (Terraform 1.10+) don't exist in the state file, so use `search_plan` to verify them during the planning phase.

```python
def test_plan_secrets_and_changes(tf):
    tf.plan()
    
    if not tf.has_changes():
        pytest.skip("No changes detected.")
        
    # Verify ephemeral secrets are correctly retrieved by the module
    secret_val = tf.search_plan("planned_values.outputs.secrets.value.api_key")
    assert secret_val is not None
    
    # Ensure critical resources aren't being deleted
    bucket_diff = tf.search_plan("resource_changes[?address=='aws_s3_bucket.data'] | [0]")
    assert "delete" not in bucket_diff["change"]["actions"]
```

### 2. Post-Apply Verification
Verify live state after infrastructure is stood up.

```python
def test_apply_and_verify(tf):
    tf.apply()
    
    # Search the live state JSON using JMESPath
    live_vm = tf.search_state("values.root_module.resources[?address=='aws_instance.web'] | [0]")
    assert live_vm["values"]["instance_state"] == "running"
```

---

## ConfTest / Policy Evaluation
Evaluate your Terraform plans against OPA/Rego policies before applying them.

```python
def test_policies(tf, is_interactive, vault_auth):
    tf.plan()
    
    if tf.has_changes():
        policy_checker = ConfTest(
            wd=".", 
            input="tfplan.json", 
            interactive=is_interactive,
            auth_callback=vault_auth.ensure_valid_token
        )
        
        # Will pause interactively or abort pytest if a policy fails
        policy_checker.run(ns="main")
```

---

## Ansible Examples
Run configuration management against your newly provisioned infrastructure.

```python
from ctlabs_tools.pytest.helper import Ansible

def test_config_management(vault_auth, is_interactive):
    ansible = Ansible(
        wd="./ansible", 
        inventory="./inventories/prod.ini", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token
    )

    # Runs standard playbook with Extra Vars
    ansible.run(roles="setup,config", opts=["-b", "-e", "CTLABS_ENV=prod"]) 
```

---

## Google Cloud Secret Manager (GSM) Integration
If you are bootstrapping identities via Google Cloud, you can fetch them securely.

```python
from ctlabs_tools.pytest.helper import GCPSecretManager

def test_fetch_gsm_bootstrap():
    gsm = GCPSecretManager()
    if gsm.is_available:
        # Fetches projects/my-project/secrets/my-secret/versions/latest
        secret_payload = gsm.get_secret("my-project", "my-secret")
        assert secret_payload is not None
```

---

## Remote Desktop Helper
Launch native RDP sessions dynamically based on deployment results (RoyalTSX on macOS, FreeRDP on Linux).

```python
from ctlabs_tools.pytest.helper import RemoteDesktop

def test_rdp_access(tf):
    # Retrieve dynamic IP from state
    ip = tf.search_state("values.outputs.vm_ip.value")
    
    RemoteDesktop.launch(
        hostname=ip, 
        username="admin", 
        password="SuperSecretPassword123!"
    )
```

