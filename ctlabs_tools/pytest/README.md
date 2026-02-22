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
vault_login -a https://<VAULT_IP>:8081 -u <USER> -m 2
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

### Using the flag in tests
```python
def test_deploy(tf, is_interactive):
    # Commands will loop on failure if --interactive is passed to pytest
    tf.init(interactive=is_interactive)
    tf.plan(interactive=is_interactive)
    tf.apply(interactive=is_interactive)
```

---

## Interactive Mode Features
When running with pytest --interactive:
* **Live Logs:** Standard output is shown in real-time.
* **Auto-Retry:** On failure, the process pauses for manual fix/retry: Action: [r]etry, [q]uit.
* **Vault Resilience:** Retries trigger a session refresh, allowing you to re-login in another terminal without killing the test.