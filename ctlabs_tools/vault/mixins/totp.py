# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/totp.py
# License : MIT
# -----------------------------------------------------------------------------
import sys

class VaultTOTPMixin:
    # -------------------------------------------------------------------------
    # ENGINE CONFIGURATION
    # -------------------------------------------------------------------------
    def setup_totp_engine(self, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            current_mounts = client.sys.list_mounted_secrets_engines()['data']
            if f"{mount_point}/" not in current_mounts:
                client.sys.enable_secrets_engine('totp', path=mount_point)
            return True
        except Exception as e:
            print(f"❌ Error setting up TOTP engine: {e}", file=sys.stderr)
            return False

    def teardown_totp_engine(self, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.sys.disable_secrets_engine(path=mount_point)
            return True
        except Exception as e:
            print(f"❌ Error tearing down TOTP engine: {e}", file=sys.stderr)
            return False

    def read_totp_engine_config(self, mount_point):
        client = self._get_client()
        if not client: return None
        try:
            res = client.sys.read_mount_configuration(path=mount_point)
            return res.get('data') if res else None
        except Exception as e:
            print(f"❌ Error reading TOTP engine config: {e}", file=sys.stderr)
            return None

    # -------------------------------------------------------------------------
    # KEY MANAGEMENT
    # -------------------------------------------------------------------------
    def create_totp_key(self, name, mount_point, **kwargs):
        client = self._get_client()
        if not client: return None
        try:
            res = client.write(f"{mount_point}/keys/{name}", **kwargs)
            # If generating a key, Vault returns the barcode and url in 'data'
            if res and 'data' in res:
                return res['data']
            return True
        except Exception as e:
            print(f"❌ Error configuring TOTP key: {e}", file=sys.stderr)
            return None

    def read_totp_key(self, name, mount_point):
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/keys/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading TOTP key '{name}': {e}", file=sys.stderr)
            return None

    def delete_totp_key(self, name, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"{mount_point}/keys/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting TOTP key '{name}': {e}", file=sys.stderr)
            return False

    def list_totp_keys(self, mount_point):
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"{mount_point}/keys")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing TOTP keys at '{mount_point}/': {e}", file=sys.stderr)
            return []

    # -------------------------------------------------------------------------
    # CODE GENERATION & VERIFICATION
    # -------------------------------------------------------------------------
    def generate_totp_code(self, name, mount_point):
        """Generates a current TOTP code for a key."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/code/{name}")
            return res.get('data', {}).get('code') if res else None
        except Exception as e:
            print(f"❌ Error generating TOTP code: {e}", file=sys.stderr)
            return None

    def verify_totp_code(self, name, code, mount_point):
        """Verifies a user-provided TOTP code."""
        client = self._get_client()
        if not client: return False, "Vault client unavailable"
        try:
            res = client.write(f"{mount_point}/code/{name}", code=code)
            if res and 'data' in res:
                is_valid = res['data'].get('valid', False)
                return is_valid, ""
            return False, "Unexpected response from Vault"
        except Exception as e:
            return False, str(e)

