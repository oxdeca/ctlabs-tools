# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/cloudflare/mixins/cubbyhole.py
# License : MIT
# -----------------------------------------------------------------------------

CUBBYHOLE_MOUNT = "cubbyhole"


class CloudflareCubbyholeMixin:
    """
    Tiny helpers to stash the *current* token in Vault's cubbyhole.

    The cubbyhole is scoped to the Vault token that writes it, so whatever
    process reads it back (Terraform via ephemeral vault_generic_secret) must
    use the same Vault token.
    """

    def store_cubbyhole(self, path="cloudflare", data=None):
        """Write account_id / zone_id / account_token to cubbyhole/<path>."""
        vault   = self._get_vault()
        payload = dict(data or {})
        if self.account_id:
            payload.setdefault("account_id", self.account_id)
        if self.zone_id:
            payload.setdefault("zone_id", self.zone_id)
        if self.token:
            payload.setdefault("account_token", self.token)
        return vault.write_secret(path=path, secret_data=payload, mount_point=CUBBYHOLE_MOUNT)

    def read_cubbyhole(self, path="cloudflare"):
        """Read back the cubbyhole payload (or None)."""
        return self._get_vault().read_secret(path=path, mount_point=CUBBYHOLE_MOUNT)

    def clear_cubbyhole(self, path="cloudflare"):
        """Delete the cubbyhole payload."""
        vault  = self._get_vault()
        client = vault._get_client()
        if not client:
            return False
        try:
            client.delete(f"{CUBBYHOLE_MOUNT}/{path.strip('/')}")
            return True
        except Exception as e:
            print(f"❌ Error clearing cubbyhole/{path}: {e}")
            return False
