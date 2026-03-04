# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/gcp.py
# License : MIT
# -----------------------------------------------------------------------------

class VaultGCPMixin:
    def get_gcp_token(self, roleset_name, mount_point='gcp'):
        """Generates a dynamic, short-lived GCP OAuth token from Vault."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/token/{roleset_name}")
            if not res:
                print(f"❌ Vault Error: Roleset '{roleset_name}' not found at '{mount_point}/'.", file=sys.stderr)
                return None
                
            return res.get('token') or res.get('token_oauth2_secret') or res.get('data', {}).get('token')
        except Exception as e:
            print(f"❌ Error generating GCP token for roleset '{roleset_name}': {e}", file=sys.stderr)
            return None

    def get_gcp_token_info(self, token_string):
        """Introspects ANY existing GCP OAuth token using Google's public endpoint."""
        if not token_string: return {}
        
        import requests  # Import locally to guarantee it's available
        try:
            # Bumped timeout to 10s just in case it's a slow network route
            r = requests.get(f"https://oauth2.googleapis.com/tokeninfo?access_token={token_string}", timeout=10)
            
            if r.status_code == 200:
                return r.json()
            else:
                return {"error": r.json().get("error_description", f"Google API returned HTTP {r.status_code}")}
                
        except Exception as e:
            # NO MORE SILENT FAILURES! Pass the exact error back to the CLI.
            return {"error": f"Network/Python error: {e.__class__.__name__} - {str(e)}"}

    def read_gcp_engine_config(self, mount_point):
        """Reads the configuration of a GCP secrets engine."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/config")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading config at '{mount_point}/': {e}")
            return None

    def update_gcp_engine_config(self, mount_point, ttl=None, max_ttl=None):
        """Updates the TTL settings of a GCP secrets engine."""
        client = self._get_client()
        if not client: return False
        try:
            payload = {}
            if ttl: payload['ttl'] = ttl
            if max_ttl: payload['max_ttl'] = max_ttl
            
            if not payload:
                print("ℹ️ No update parameters provided.")
                return True
                
            client.write(f"{mount_point}/config", **payload)
            return True
        except Exception as e:
            print(f"❌ Error updating config at '{mount_point}/': {e}")
            return False

    #
    # secret engines
    #
    def setup_gcp_engine(self, creds_json, mount_point='gcp'):
        """Phase 1: Enables GCP engine and configures it with the Master JSON key."""
        client = self._get_client()
        if not client: return False
        try:
            # 1. Safely enable the engine
            try:
                client.sys.enable_secrets_engine(backend_type='gcp', path=mount_point)
                print(f"✅ Enabled GCP secrets engine at '{mount_point}/'")
            except Exception as e:
                if "path is already in use" not in str(e):
                    print(f"❌ Failed to enable engine: {e}")
                    return False
            
            # 2. Write the Master Credentials
            client.write(f'{mount_point}/config', credentials=creds_json)
            print(f"✅ Configured GCP Engine '{mount_point}/' with Master Credentials")
            return True
        except Exception as e:
            # Added exact exception typing so errors are never blank again!
            print(f"❌ Error configuring GCP engine: {type(e).__name__} - {str(e)}")
            return False

    def create_gcp_roleset(self, name, project_id, bindings_hcl, mount_point='gcp'):
        """Phase 2: Creates a roleset to generate temporary GCP OAuth tokens."""
        client = self._get_client()
        if not client: return False
        
        import time
        # BUMPED TO 6 ATTEMPTS
        for attempt in range(1, 7):
            try:
                client.write(
                    f'{mount_point}/roleset/{name}',
                    project=project_id,
                    secret_type="access_token",
                    token_scopes=[
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/userinfo.email"
                    ],
                    bindings=bindings_hcl
                )
                print(f"✅ Created GCP roleset '{name}' in project '{project_id}'")
                return True
            except Exception as e:
                error_msg = str(e)
                # ADDED API ENABLEMENT ERRORS TO THE CATCH LIST
                if attempt < 6 and ("Invalid JWT Signature" in error_msg or "timed out" in error_msg.lower() or "accessNotConfigured" in error_msg or "SERVICE_DISABLED" in error_msg):
                    print(f"  ⏳ GCP IAM sync delay detected. Waiting 30 seconds for Google to catch up... (Attempt {attempt}/6)")
                    time.sleep(30)
                else:
                    print(f"❌ Error creating roleset '{name}': {e}")
                    return False
        return False

    def read_gcp_roleset(self, name, mount_point='gcp'):
        """Reads the configuration of an existing GCP roleset."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f'{mount_point}/roleset/{name}')
            return res.get('data') if res else None
        except Exception as e:
            print(f"❌ Error reading roleset '{name}': {e}")
            return None


    def delete_gcp_roleset(self, name, mount_point='gcp'):
        """Deletes a GCP roleset and cleans up its underlying Service Account in GCP."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f'{mount_point}/roleset/{name}')
            print(f"✅ Deleted roleset '{name}' at '{mount_point}/'. GCP Service Account queued for deletion.")
            return True
        except Exception as e:
            print(f"❌ Error deleting roleset '{name}': {e}")
            return False

    def list_gcp_rolesets(self, mount_point='gcp'):
        """Lists all configured rolesets under a specific GCP engine mount."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f'{mount_point}/roleset')
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            # Vault returns 404 on list if the path is empty
            if "404" in str(e): return []
            print(f"❌ Error listing rolesets at '{mount_point}/': {e}")
            return []

    def teardown_gcp_engine(self, mount_point='gcp'):
        """Phase 3 (Cleanup): Disables the GCP secrets engine to clean up Vault."""
        client = self._get_client()
        if not client: return False
        try:
            # Bypass the buggy hvac.sys module and use the raw read that we know works!
            res = client.read("sys/mounts")
            engines = res.get('data', res) if isinstance(res, dict) else res
            
            if engines and f"{mount_point}/" in engines:
                client.sys.disable_secrets_engine(path=mount_point)
                print(f"✅ Disabled GCP secrets engine at '{mount_point}/'")
            else:
                print(f"ℹ️ Engine '{mount_point}/' was not mounted. Skipping unmount.")
                
            return True
        except Exception as e:
            error_msg = str(e).strip()
            print(f"⚠️ Could not disable GCP engine: {error_msg if error_msg else type(e).__name__}")
            return False
