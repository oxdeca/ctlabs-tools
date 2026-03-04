# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/gsm.py
# License : MIT
# -----------------------------------------------------------------------------

class GCPSecretManager:
    def __init__(self):
        try:
            from google.cloud import secretmanager
            self.client = secretmanager.SecretManagerServiceClient()
            self.is_available = True
        except ImportError:
            print("⚠️ google-cloud-secret-manager is not installed. GSM features disabled.")
            self.client = None
            self.is_available = False

    def get_secret(self, project, secret_id, version="latest"):
        if not self.is_available:
            return None
            
        name = f"projects/{project}/secrets/{secret_id}/versions/{version}"
        
        try:
            response = self.client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            print(f"❌ Failed to fetch {secret_id} from GSM: {e}")
            return None