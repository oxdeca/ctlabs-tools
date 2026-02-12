# Install directly from GitHub

```py
pip install git+https://github.com/oxdeca/ctlabs-tools.git
```

Importing in your Tests
Once installed via pip, your imports become clean and location-independent. In your VM's test files, you simply write:

```py
from pytest.helper import Terraform, Ansible
from pytest.vault_login import get_args # etc.
```