# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/oidc.py
# License : MIT
# -----------------------------------------------------------------------------

class VaultOIDCMixin:
    # -------------------------------------------------------------------------
    # OIDC / SSO MANAGEMENT
    # -------------------------------------------------------------------------
    
    def configure_oidc_issuer(self, issuer_url):
        """Phase 1: Tells Vault to broadcast its identity for WIF."""
        client = self._get_client()
        if not client: return False
        try:
            client.write('identity/oidc/config', issuer=issuer_url)
            print(f"✅ Vault OIDC Issuer set to: {issuer_url}")
            return True
        except Exception as e:
            print(f"❌ Error setting OIDC issuer: {e}")
            return False


    def configure_oidc(self, client_id, client_secret, default_role="default", discovery_url="https://accounts.google.com"):
        """Configures the OIDC auth engine to talk to an Identity Provider (e.g., Google)."""
        client = self._get_client()
        if not client: return False
        try:
            # 1. Safely enable the OIDC auth method
            try:
                client.sys.enable_auth_method(method_type='oidc', path='oidc')
                print("✅ Enabled OIDC auth method at 'oidc/'")
            except Exception as e:
                if "path is already in use" not in str(e):
                    print(f"❌ Failed to enable OIDC auth method: {e}")
                    return False

            # 2. Apply the configuration
            client.write(
                "auth/oidc/config",
                oidc_discovery_url=discovery_url,
                oidc_client_id=client_id,
                oidc_client_secret=client_secret,
                default_role=default_role
            )
            return True
        except Exception as e:
            print(f"❌ Error configuring OIDC engine: {e}")
            return False

    def get_oidc_client_id(self):
        """Helper to safely fetch the current Client ID from the OIDC config."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read("auth/oidc/config")
            return res.get('data', {}).get('oidc_client_id') if res else None
        except Exception as e:
            print(f"❌ Error reading OIDC config: {e}")
            return None

    def create_oidc_role(self, name, bound_claims, policies=None, ttl="1h", client_id=None):
        """Creates or updates an OIDC role mapping groups/emails to Vault policies."""
        client = self._get_client()
        if not client: return False
        
        # Auto-fetch client_id if not explicitly provided
        if not client_id:
            client_id = self.get_oidc_client_id()
            if not client_id:
                print("❌ Cannot create OIDC role: Missing Client ID. Run 'config' first.")
                return False

        payload = {
            "bound_audiences": client_id,
            "allowed_redirect_uris": [
                "http://localhost:8250/oidc/callback",
                # TODO: Replace with your actual Vault UI domain
                "https://vault.yourdomain.com:8200/ui/vault/auth/oidc/oidc/callback" 
            ],
            "user_claim": "email",
            "bound_claims": bound_claims,
            "token_ttl": ttl,
            "oidc_scopes": ["openid", "email", "profile"] # 🌟 FIX: Force Google to return the email!
        }
        
        if policies:
            payload['token_policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
            
        try:
            client.write(f"auth/oidc/role/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating OIDC role '{name}': {e}")
            return False

    def read_oidc_role(self, name):
        """Reads an OIDC role configuration."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/oidc/role/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading OIDC role '{name}': {e}")
            return None

    def delete_oidc_role(self, name):
        """Deletes an OIDC role."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/oidc/role/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting OIDC role '{name}': {e}")
            return False

    def list_oidc_roles(self):
        """Lists all OIDC roles."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("auth/oidc/role")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing OIDC roles: {e}")
            return []

    def oidc_login(self, role="default", port=8250, no_browser=False):
        """Executes the OIDC browser login flow, supporting both local and headless environments."""
        import os
        import urllib.parse
        import webbrowser
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import hvac

        vault_url = os.environ.get("VAULT_ADDR")
        if not vault_url:
            print("❌ Error: VAULT_ADDR environment variable is not set.")
            return None

        client = hvac.Client(url=vault_url, verify=False)
        redirect_uri = f"http://localhost:{port}/oidc/callback"

        # 1. Ask Vault to generate the Auth URL and the cryptographic Nonce
        try:
            res = client.write("auth/oidc/oidc/auth_url", role=role, redirect_uri=redirect_uri)
            auth_url = res['data']['auth_url']
            client_nonce = res['data'].get('client_nonce', '')  # 🌟 FIX 1: Capture the nonce!
        except Exception as e:
            print(f"❌ Error initiating OIDC login (does role '{role}' exist?): {e}")
            return None

        state = None
        code = None

        # ---------------------------------------------------------------------
        # ROUTE A: Headless Copy/Paste Flow (--no-browser)
        # ---------------------------------------------------------------------
        if no_browser:
            print("\n" + "="*60)
            print("🌐 HEADLESS OIDC LOGIN")
            print("="*60)
            print("1️⃣  Open this URL in your local web browser:\n")
            print(f"{auth_url}\n")
            print("2️⃣  Log in with your account.")
            print("3️⃣  Your browser will redirect to a 'localhost' page and show an error.")
            print("4️⃣  Copy the ENTIRE URL from your browser's address bar and paste it below.")
            print("="*60 + "\n")

            callback_url = input("📋 Paste the full localhost URL here: ").strip()
            
            try:
                parsed = urllib.parse.urlparse(callback_url)
                query = urllib.parse.parse_qs(parsed.query)
                state = query.get('state', [''])[0]
                code = query.get('code', [''])[0]
            except Exception:
                print("❌ Error parsing the URL. Did you paste the entire thing?")
                return None

        # ---------------------------------------------------------------------
        # ROUTE B: Local Listener Flow (Default)
        # ---------------------------------------------------------------------
        else:
            callback_data = {}

            class OIDCHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    parsed = urllib.parse.urlparse(self.path)
                    if parsed.path == "/oidc/callback":
                        query = urllib.parse.parse_qs(parsed.query)
                        callback_data['state'] = query.get('state', [''])[0]
                        callback_data['code'] = query.get('code', [''])[0]
                        
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        success_html = """
                        <html><body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
                            <h1 style="color: #4CAF50;">Authentication Successful!</h1>
                            <p>Vault has received your credentials. You can safely close this tab and return to your terminal.</p>
                        </body></html>
                        """
                        self.wfile.write(success_html.encode('utf-8'))
                    else:
                        self.send_response(404)
                        self.end_headers()

                def log_message(self, format, *args):
                    pass # Keep the CLI clean

            print(f"🌐 Opening your browser to authenticate via SSO...")
            print(f"🔗 If a browser doesn't open automatically, restart with --no-browser or click:\n{auth_url}\n")
            
            server = HTTPServer(('localhost', port), OIDCHandler)
            try:
                webbrowser.open(auth_url)
            except Exception:
                pass

            # 🌟 FIX: Catch Ctrl+C and guarantee the socket closes!
            try:
                server.handle_request()
            except KeyboardInterrupt:
                print("\n🛑 Local listener aborted by user.")
            finally:
                server.server_close()

            state = callback_data.get('state')
            code = callback_data.get('code')

        # ---------------------------------------------------------------------
        # Final Step: Exchange the code & nonce for a Vault Token
        # ---------------------------------------------------------------------
        if not state or not code:
            print("❌ Error: Missing 'state' or 'code' parameters.")
            return None

        try:
            # 🌟 FIX 2: Pass the path, code, nonce, and state to hvac!
            res = client.auth.oidc.oidc_callback(
                code=code, 
                path='oidc', 
                nonce=client_nonce, 
                state=state
            )
            
            auth_data = res.get('auth', {})
            
            # 🌟 FIX: Smartly extract the display name from metadata if the top-level is empty
            meta = auth_data.get('metadata', {})
            display_name = meta.get('email') or auth_data.get('display_name') or 'Unknown'

            return {
                "token": auth_data.get('client_token'),
                "ttl": auth_data.get('lease_duration', 3600),
                "policies": auth_data.get('policies', []),
                "display_name": auth_data.get('display_name', 'Unknown')
            }
        except Exception as e:
            print(f"❌ Error finalizing OIDC authentication: {e}")
            return None


