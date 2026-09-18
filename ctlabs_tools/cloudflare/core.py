# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/cloudflare/core.py
# License : MIT
# -----------------------------------------------------------------------------

from .base          import CloudflareBase, CloudflareError
from .mixins.tokens import CloudflareTokensMixin, ACCOUNT_SCOPE, ZONE_SCOPE
from .mixins.cubbyhole import CloudflareCubbyholeMixin


class Cloudflare(
    CloudflareBase,
    CloudflareTokensMixin,
    CloudflareCubbyholeMixin,
):
    """
    Unified Cloudflare client.

    Credentials can be passed explicitly, read from the CLOUDFLARE_* env vars,
    or (for the cubbyhole helpers) supplied a HashiVault instance.

        from ctlabs_tools.cloudflare import Cloudflare

        cf = Cloudflare(token=..., account_id=..., zone_id=...)
        tok = cf.create_scoped_token("dns-ci", ["DNS Write", "Zone Read"])
    """
    pass
