# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/system.py
# License : MIT
# -----------------------------------------------------------------------------

import sys

class VaultSystemMixin:
    def lookup_token(self):
        """Fetches metadata about the currently active token."""
        client = self._get_client()
        if not client:
            return None
        try:
            res = client.auth.token.lookup_self()
            return res.get('data', {})
        except Exception as e:
            print(f"❌ Error looking up token: {e}")
            return None

    def list_engines(self, backend_type=None):
        """Fetches a list of mounted secrets engines, optionally filtered by type."""
        client = self._get_client()
        if not client: return None
        try:
            engines = client.read("sys/mounts")
            
            if not engines:
                return []
                
            data = engines.get('data', engines) if isinstance(engines, dict) else engines
            
            mounts = []
            for path, config in data.items():
                # If backend_type is provided, filter by it. Otherwise, return all!
                if backend_type is None or config.get('type') == backend_type:
                    mounts.append(path)
                    
            return mounts
        except Exception as e:
            error_msg = str(e).strip()
            print(f"❌ Error listing {backend_type or 'all'} mounts: {error_msg if error_msg else e.__class__.__name__}", file=sys.stderr)
            return None

    def list_leases(self, prefix):
        """Lists active leases for ANY Vault secrets engine."""
        client = self._get_client()
        if not client: return []
        try:
            # We pass the exact prefix the user typed
            res = client.list(f"sys/leases/lookup/{prefix}")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" in str(e) or "permission denied" in str(e).lower():
                return []
            print(f"❌ Error listing leases for {prefix}: {e}")
            return []

    
    def revoke_lease(self, lease_id):
        """Revokes a specific individual lease ID."""
        client = self._get_client()
        if not client: return False
        try:
            client.write(f"sys/leases/revoke/{lease_id}")
            return True
        except Exception as e:
            print(f"❌ Error revoking lease '{lease_id}': {e}")
            return False

    def force_revoke_prefix(self, prefix):
        """Forcefully wipes all leases under a prefix (fixes Ghost Clusters)."""
        client = self._get_client()
        if not client: return False
        try:
            clean_prefix = prefix.strip('/')
            client.write(f"sys/leases/revoke-force/{clean_prefix}")
            return True
        except Exception as e:
            print(f"❌ Error force-revoking prefix '{prefix}': {e}")
            return False

    #
    #  RAW Data
    #
    def read_raw_path(self, path):
        """Reads the raw data from any Vault API path, handling both Vault-wrapped and raw responses."""
        client = self._get_client()
        if not client: return None
        try:
            if path.endswith('/'):
                res = client.list(path)
            else:
                res = client.read(path)

            if not res: 
                return None
            
            if 'data' in res and 'request_id' in res:
                return res['data']
            
            return res
        except Exception as e:
            print(f"❌ Error reading raw path '{path}': {e}")
            return None

