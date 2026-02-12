# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/auth0/app/pages/1_Single_Page_App.py
# License : MIT
# -----------------------------------------------------------------------------

"""
🌐 Single Page Application - PKCE Flow (No client_secret)
✅ Uses PKCE (Proof Key for Code Exchange)
✅ Authorization Code + PKCE flow
✅ Best for: React, Vue, Angular SPAs
Security Level: ⭐⭐⭐⭐ (PKCE required)
"""
import streamlit as st
import requests
from jose import jwt
from urllib.parse import urlencode, quote
from datetime import datetime
import secrets
import base64
import hashlib

APP_VERSION = "2.1.0"
APP_BUILD_DATE = "2026-02-09"

st.set_page_config(
    page_title="🌐 SPA Authentication (PKCE)",
    page_icon="🌐",
    layout="wide"
)

# ==================== MODEL ====================
class SPAuth:
    """PKCE flow for public clients (no client_secret)"""
    
    def __init__(self, domain, client_id):
        self.domain = domain
        self.client_id = client_id
        self.jwks_url = f"https://{domain}/.well-known/jwks.json"
    
    def generate_pkce_pair(self):
        """Generate code_verifier and code_challenge per RFC 7636"""
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")
        return verifier, challenge
    
    def get_login_url(self, redirect_uri, state, code_challenge):
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": "openid profile email",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        return f"https://{self.domain}/authorize?{urlencode(params)}"
    
    def exchange_code(self, code, redirect_uri, code_verifier):
        """PKCE token exchange (no client_secret)"""
        resp = requests.post(
            f"https://{self.domain}/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier
            },
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json(), None
        try:
            err = resp.json()
            msg = f"{err.get('error', 'unknown')}: {err.get('error_description', resp.text)}"
        except:
            msg = f"HTTP {resp.status_code}"
        return None, msg
    
    def verify_token(self, token):
        try:
            jwks = requests.get(self.jwks_url, timeout=5).json()
            header = jwt.get_unverified_header(token)
            key = [k for k in jwks["keys"] if k["kid"] == header["kid"]][0]
            return jwt.decode(
                token, key, algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://{self.domain}/"
            )
        except Exception as e:
            return None
    
    def get_user_info(self, access_token):
        resp = requests.get(
            f"https://{self.domain}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5
        )
        return resp.json() if resp.status_code == 200 else None


# ==================== CONTROLLER ====================
class SPAController:
    def __init__(self, auth: SPAuth):
        self.auth = auth
    
    def get_redirect_uri(self):
        return st.secrets.auth0_spa.redirect_uri
    
    def generate_state(self):
        return secrets.token_urlsafe(16)
    
    def handle_login(self):
        # Generate PKCE pair
        verifier, challenge = self.auth.generate_pkce_pair()
        state = self.generate_state()
        
        # Store in session (like browser localStorage)
        st.session_state.pkce_verifier = verifier
        st.session_state.oauth_state = state
        
        login_url = self.auth.get_login_url(self.get_redirect_uri(), state, challenge)
        st.markdown(f'<meta http-equiv="refresh" content="0; url={login_url}">', 
                   unsafe_allow_html=True)
    
    def handle_callback(self):
        query_params = st.query_params.to_dict()
        received_state = query_params.get("state", [None])[0] if isinstance(
            query_params.get("state"), list) else query_params.get("state")
        
        if received_state != st.session_state.get("oauth_state"):
            return "❌ CSRF validation failed (state mismatch)"
        
        code = query_params.get("code", [None])[0] if isinstance(
            query_params.get("code"), list) else query_params.get("code")
        
        # Retrieve PKCE verifier from session
        verifier = st.session_state.get("pkce_verifier")
        if not verifier:
            return "❌ PKCE verifier missing. Session expired - please login again."
        
        tokens, error = self.auth.exchange_code(code, self.get_redirect_uri(), verifier)
        if error:
            if "invalid_grant" in error and "PKCE" in error:
                return f"""❌ **PKCE Validation Failed**
                
                `{error}`
                
                **Cause:** Code verifier doesn't match code challenge.
                **Fix:** Always generate fresh PKCE pair per login attempt.
                """
            if "unauthorized_client" in error:
                return f"""❌ **Auth0 Configuration Error**
                
                `{error}`
                
                **Fix:** In Auth0 Dashboard → Applications → [Your SPA App] → Settings:
                1. Application Type must be **"Single Page Application"**
                2. Grant Types → ✅ Check "Authorization Code"
                3. ⚠️ **CLICK "SAVE CHANGES"**
                """
            return f"Token exchange failed: `{error}`"
        
        if not (claims := self.auth.verify_token(tokens["id_token"])):
            return "❌ JWT signature validation failed"
        
        if not (user_info := self.auth.get_user_info(tokens["access_token"])):
            return "❌ Failed to fetch user profile"
        
        st.session_state.update({
            "authenticated": True,
            "user": user_info,
            "tokens": tokens,
            "login_time": datetime.now(),
            "auth_type": "Single Page Application (PKCE)",
            "app_page": "spa"
        })
        
        # Clean up PKCE material
        st.session_state.pop("pkce_verifier", None)
        st.session_state.pop("oauth_state", None)
        st.query_params.clear()
        return None


# ==================== VIEW ====================
def main():
    # Initialize auth
    try:
        cfg = st.secrets.auth0_spa
        auth = SPAuth(cfg.domain, cfg.client_id)
        controller = SPAController(auth)
    except Exception as e:
        st.error(f"❌ Configuration error: {e}\n\nCheck `.streamlit/secrets.toml` has [auth0_spa] section")
        st.stop()
    
    # Handle callback
    if "code" in st.query_params:
        error = controller.handle_callback()
        if error:
            st.error(error)
            st.query_params.clear()
            st.stop()
        st.rerun()
    
    # Header
    st.title("🌐 Single Page Application (PKCE Flow)")
    st.caption("Public Client Authentication • No client_secret • Security Level: ⭐⭐⭐⭐")
    st.divider()
    
    # Educational content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### 🔒 Why PKCE? (Critical for Public Clients)
        
        SPAs run in the browser where **client_secret cannot be protected**. PKCE solves this:
        
        1. **Before redirect**: Generate random `code_verifier` → hash to `code_challenge`
        2. **Send challenge** to Auth0 with authorization request
        3. **After login**: Exchange code + original `code_verifier` for tokens
        4. **Auth0 validates**: Hash(verifier) == challenge → prevents code interception attacks
        
        ```mermaid
        sequenceDiagram
            Browser->>+Auth0: Auth request + code_challenge
            Auth0->>+Browser: Authorization code
            Attacker->>Browser: Steals code (via malware/network)
            Attacker->>+Auth0: Tries to exchange stolen code
            Auth0->>Attacker: ❌ Fails (no code_verifier)
            Browser->>+Auth0: Exchanges code + code_verifier
            Auth0->>+Browser: ✅ Validates hash(verifier) == challenge → returns tokens
        ```
        
        ### ✅ Security Requirements
        - **PKCE is MANDATORY** for all public clients (SPAs, Native apps)
        - **Never use client_secret** in browser code (it's not secret!)
        - **Always use code_challenge_method=S256** (SHA256 hashing)
        - **Short code lifetime** (Auth0 default: 10 minutes)
        - **State parameter** for CSRF protection (separate from PKCE)
        """)
    
    with col2:
        st.info("### 🛡️ PKCE Security Checklist")
        checks = [
            ("Application Type", "✅ Single Page Application"),
            ("PKCE Required", "✅ Mandatory (RFC 7636)"),
            ("client_secret", "❌ Never used (public client)"),
            ("code_challenge_method", "✅ S256 (SHA256)"),
            ("State Parameter", "✅ CSRF protection"),
            ("Token Validation", "✅ JWKS signature check")
        ]
        for label, status in checks:
            st.markdown(f"**{label}**: {status}")
        
        st.divider()
        st.warning("""
        ### ⚠️ Critical Vulnerabilities Without PKCE
        
        - **Authorization Code Interception**: Attacker steals code → exchanges for tokens
        - **Mobile App Reverse Engineering**: Extract hardcoded secrets
        - **Browser Extension Malware**: Reads localStorage secrets
        
        > 💡 PKCE makes stolen codes useless without the original verifier!
        """)
    
    st.divider()
    
    # Authentication UI
    if st.session_state.get("authenticated") and st.session_state.get("app_page") == "spa":
        user = st.session_state.user
        st.success(f"✅ Authenticated as **{user.get('email', 'User')}** (PKCE Flow)")
        
        with st.expander("👤 User Profile", expanded=True):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.write(f"**Name:** {user.get('name', '-')}")
                st.write(f"**Email:** {user.get('email', '-')}")
                st.write(f"**Verified:** {'✅ Yes' if user.get('email_verified') else '❌ No'}")
                st.write(f"**Auth Method:** PKCE (no client_secret)")
            with col2:
                if pic := user.get("picture"):
                    st.image(pic, width=120)
                st.write(f"**User ID:** `{user.get('sub', '-')[:15]}...`")
        
        with st.expander("🔐 PKCE Flow Details (Educational)", expanded=False):
            st.markdown("""
            **PKCE Parameters Used:**
            - `code_challenge_method`: S256 (SHA256 hashing)
            - `code_challenge`: Base64URL(SHA256(verifier))
            - `code_verifier`: 64+ character random string (stored in session)
            
            **Why this is secure:**
            - Verifier never leaves the browser session
            - Challenge is one-way hash (cannot reverse to get verifier)
            - Each login uses fresh PKCE pair (no replay attacks)
            - Short code lifetime (10 min default) limits attack window
            
            > 💡 **Production Note**: In real SPAs, PKCE material is stored in 
            > memory (not localStorage) to prevent XSS theft.
            """)
        
        st.divider()
        if st.button("🚪 Logout", type="primary", use_container_width=True):
            for key in ["authenticated", "user", "tokens", "login_time", "app_page"]:
                st.session_state.pop(key, None)
            st.rerun()
    
    else:
        st.info("""
        ### 👤 Test PKCE Authentication Flow
        
        1. Click **"Login with Auth0 (PKCE)"** below
        2. Enter test user credentials
        3. After login, inspect the "PKCE Flow Details" section
        
        > 💡 **Key Learning**: Notice there's NO client_secret used anywhere!
        > PKCE replaces the security that client_secret provides for confidential clients.
        """)
        
        if st.button("🚀 Login with Auth0 (PKCE)", type="primary", use_container_width=True):
            controller.handle_login()
    
    # Footer
    st.divider()
    st.caption(f"🌐 SPA PKCE Demo • Version {APP_VERSION} • Built {APP_BUILD_DATE}")
    st.caption("Educational purpose only • PKCE is mandatory for all public clients per OAuth 2.0 Security Best Current Practice")

if __name__ == "__main__":
    main()
