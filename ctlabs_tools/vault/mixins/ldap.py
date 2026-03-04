# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/ldap.py
# License : MIT
# -----------------------------------------------------------------------------
import sys

class VaultLDAPMixin:
    
    # -------------------------------------------------------------------------
    # ENGINE CONFIGURATION
    # -------------------------------------------------------------------------
    def setup_ldap_engine(self, mount_point, url, bind_dn, bind_pass, user_dn):
        client = self._get_client()
        if not client: return False
        try:
            current_mounts = client.sys.list_mounted_secrets_engines()['data']
            if f"{mount_point}/" not in current_mounts:
                client.sys.enable_secrets_engine('ldap', path=mount_point)
            
            client.write(
                f"{mount_point}/config", 
                url=url, 
                binddn=bind_dn, 
                bindpass=bind_pass, 
                userdn=user_dn
            )
            return True
        except Exception as e:
            print(f"❌ Error setting up LDAP Secrets engine: {e}")
            return False

    def teardown_ldap_engine(self, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.sys.disable_secrets_engine(mount_point)
            return True
        except Exception as e:
            print(f"❌ Error tearing down LDAP Secrets engine: {e}")
            return False

    def read_ldap_engine_config(self, mount_point):
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/config")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading config at '{mount_point}/': {e}")
            return None

    def update_ldap_engine_config(self, mount_point, **kwargs):
        client = self._get_client()
        if not client: return False
        try:
            current = self.read_ldap_engine_config(mount_point) or {}
            payload = {
                "url": kwargs.get("url") or current.get("url", ""),
                "binddn": kwargs.get("bind_dn") or current.get("binddn", ""),
                "bindpass": kwargs.get("bind_pass") or current.get("bindpass", ""),
                "userdn": kwargs.get("user_dn") or current.get("userdn", "")
            }
            client.write(f"{mount_point}/config", **payload)
            return True
        except Exception as e:
            print(f"❌ Error updating config at '{mount_point}/': {e}")
            return False

    # -------------------------------------------------------------------------
    # ROLE MANAGEMENT
    # -------------------------------------------------------------------------
    def create_ldap_role(self, name, mount_point, creation_ldif, deletion_ldif, default_ttl="1h", max_ttl="24h"):
        client = self._get_client()
        if not client: return False
        try:
            client.write(
                f"{mount_point}/role/{name}",
                creation_ldif=creation_ldif,
                deletion_ldif=deletion_ldif,
                default_ttl=default_ttl,
                max_ttl=max_ttl
            )
            return True
        except Exception as e:
            print(f"❌ Error creating LDAP Role '{name}': {e}")
            return False

    def read_ldap_role(self, name, mount_point):
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/role/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading LDAP role '{name}': {e}")
            return None

    def delete_ldap_role(self, name, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"{mount_point}/role/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting LDAP role '{name}': {e}")
            return False

    def list_ldap_roles(self, mount_point):
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"{mount_point}/role")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing LDAP roles: {e}")
            return []

    # -------------------------------------------------------------------------
    # CREDENTIAL GENERATION
    # -------------------------------------------------------------------------
    def get_ldap_credentials(self, role_name, mount_point):
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/creds/{role_name}")
            return res.get('data') if res else None
        except Exception as e:
            print(f"❌ Error generating LDAP credentials for '{role_name}': {e}")
            return None
