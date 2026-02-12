# Install directly from GitHub
# If the repo is public:

```py
pip install git+https://github.com/your-username/ctlabs-tools.git
```

# If the repo is private (using a Personal Access Token):
# pip install git+https://<TOKEN>@github.com/your-username/ctlabs-tools.git

Importing in your Tests
Once installed via pip, your imports become clean and location-independent. In your VM's test files, you simply write:

```py
from pytest.helper import Terraform, Ansible
from pytest.vault_login import get_args # etc.
```