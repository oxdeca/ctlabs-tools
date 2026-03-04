# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/core.py
# License : MIT
# -----------------------------------------------------------------------------

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import the base and all mixins
from .base            import VaultBase
from .mixins.system   import VaultSystemMixin
from .mixins.kv       import VaultKVMixin
from .mixins.gcp      import VaultGCPMixin
from .mixins.k8s      import VaultK8sMixin
from .mixins.oidc     import VaultOIDCMixin
from .mixins.approle  import VaultAppRoleMixin
from .mixins.identity import VaultIdentityMixin

class HashiVault(
    VaultBase,
    VaultSystemMixin,
    VaultKVMixin,
    VaultGCPMixin,
    VaultK8sMixin,
    VaultOIDCMixin,
    VaultAppRoleMixin,
    VaultIdentityMixin
):
    """
    Unified Vault Client.
    Inherits all capabilities from domain-specific Mixins.
    """
    pass
