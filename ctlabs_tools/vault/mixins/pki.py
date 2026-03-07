# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/pki.py
# License : MIT
# -----------------------------------------------------------------------------
import sys

class VaultPKIMixin:
    # -------------------------------------------------------------------------
    # ENGINE CONFIGURATION
    # -------------------------------------------------------------------------
    def setup_pki_engine(self, mount_point, common_name, max_ttl="87600h"):
        client = self._get_client()
        if not client: return False
        try:
            current_mounts = client.sys.list_mounted_secrets_engines()['data']
            if f"{mount_point}/" not in current_mounts:
                client.sys.enable_secrets_engine('pki', path=mount_point, config={'max_lease_ttl': max_ttl})
            
            # Generate Root CA
            client.write(f"{mount_point}/root/generate/internal", common_name=common_name, ttl=max_ttl)
            
            # Configure URLs
            client.write(f"{mount_point}/config/urls", 
                         issuing_certificates=f"http://127.0.0.1:8200/v1/{mount_point}/ca",
                         crl_distribution_points=f"http://127.0.0.1:8200/v1/{mount_point}/crl")
            return True
        except Exception as e:
            print(f"❌ Error setting up PKI engine: {e}")
            return False

    def teardown_pki_engine(self, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.sys.disable_secrets_engine(mount_point)
            return True
        except Exception as e:
            print(f"❌ Error tearing down PKI engine: {e}")
            return False

    # -------------------------------------------------------------------------
    # ROLE MANAGEMENT
    # -------------------------------------------------------------------------
    def create_pki_role(self, name, mount_point, allowed_domains, allow_subdomains=True, max_ttl="72h"):
        client = self._get_client()
        if not client: return False
        try:
            domains = [d.strip() for d in allowed_domains.split(",")]
            client.write(
                f"{mount_point}/roles/{name}",
                allowed_domains=domains,
                allow_subdomains=allow_subdomains,
                max_ttl=max_ttl,
                key_type="rsa",
                key_bits=2048
            )
            return True
        except Exception as e:
            print(f"❌ Error creating PKI role: {e}")
            return False

    def read_pki_role(self, name, mount_point):
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/roles/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading PKI role '{name}': {e}")
            return None

    def delete_pki_role(self, name, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"{mount_point}/roles/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting PKI role '{name}': {e}")
            return False

    # -------------------------------------------------------------------------
    # CERTIFICATE ISSUANCE
    # -------------------------------------------------------------------------
    def issue_certificate(self, role_name, mount_point, common_name, ttl="24h"):
        client = self._get_client()
        if not client: return None
        try:
            res = client.write(f"{mount_point}/issue/{role_name}", common_name=common_name, ttl=ttl)
            return res.get('data') if res else None
        except Exception as e:
            print(f"❌ Error issuing certificate: {e}")
            return None

