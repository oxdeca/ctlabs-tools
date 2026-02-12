# Install directly from GitHub

```py
pip install git+https://github.com/oxdeca/ctlabs-tools.git
#
# or from branch dev
#
pip install git+https://github.com/oxdeca/ctlabs-tools.git@dev
```

Importing in your Tests
Once installed via pip, your imports become clean and location-independent. In your VM's test files, you simply write:

```py
from ctlabs_tools.pytest.helper import Terraform, Ansible
from ctlabs_tools.pytest.vault_login import get_args # etc.
```

___vault_login___

To login into vault run:

```bash
vault_login -a https://<VAULT_IP>:8081 -u <USER> -m 2
```


# Test requiring Vault

```py
tf = Terraform(wd="./infra/vault-stuff")
```

# Test that works offline/without Vault

```py
tf_offline = Terraform(wd="./infra/local-test", skip_vault=True)
```
