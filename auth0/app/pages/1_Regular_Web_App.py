"""
🔐 Regular Web Application - Server-Side Authentication
✅ Uses client_secret (safe on server)
✅ Authorization Code flow
✅ Best for: Streamlit, Flask, Django, server-rendered apps
Security Level: ⭐⭐⭐⭐⭐ (Highest)
"""
import streamlit as st
import requests
from jose import jwt
from urllib.parse import urlencode
from datetime import datetime
import secrets

APP_VERSION = "2.1.0"
APP_BUILD_DATE = "2026-02-09"

st.set_page_config(
    page_title="🔐 Regular Web App Auth",
    page_icon="🔐",
    layout="wide"
)

# ==================== MODEL ====================
class RegularWebAuth:
    def __init__(self, domain, client_id, client_secret):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.jwks_url = f"https://{domain}/.well-known/jwks.json"
    
    def get_login_url(self, redirect_uri, state):
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": "openid profile email",
            "audience": f"https://{self.domain}/api/v2/"
        }
        return f"https://{self.domain}/authorize?{urlencode(params)}"
    
    def exchange_code(self, code, redirect_uri):
        resp = requests.post(
            f"https://{self.domain}/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": redirect_uri
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
    
    def logout_url(self, return_to):
        params = urlencode({"client_id": self.client_id, "returnTo": return_to})
        return f"https://{self.domain}/v2/logout?{params}"


# ==================== CONTROLLER ====================
class RegularWebController:
    def __init__(self, auth: RegularWebAuth):
        self.auth = auth
    
    def get_redirect_uri(self):
        return st.secrets.auth0_regular.redirect_uri
    
    def generate_state(self):
        return secrets.token_urlsafe(16)
    
    def validate_state(self, state):
        return state == st.session_state.get("oauth_state")
    
    def handle_login(self):
        state = self.generate_state()
        st.session_state.oauth_state = state
        login_url = self.auth.get_login_url(self.get_redirect_uri(), state)
        st.markdown(f'<meta http-equiv="refresh" content="0; url={login_url}">', 
                   unsafe_allow_html=True)
    
    def handle_callback(self):
        query_params = st.query_params.to_dict()
        received_state = query_params.get("state", [None])[0] if isinstance(
            query_params.get("state"), list) else query_params.get("state")
        
        if not self.validate_state(received_state):
            return "❌ CSRF validation failed (state mismatch). Please try login again."
        
        code = query_params.get("code", [None])[0] if isinstance(
            query_params.get("code"), list) else query_params.get("code")
        
        tokens, error = self.auth.exchange_code(code, self.get_redirect_uri())
        if error:
            if "unauthorized_client" in error and "authorization_code" in error:
                return f"""❌ **Auth0 Configuration Error**
                
                `{error}`
                
                **Fix:** In Auth0 Dashboard → Applications → [Your App] → Settings:
                1. Application Type must be **"Regular Web Application"** (NOT SPA!)
                2. Grant Types → ✅ Check "Authorization Code"
                3. ⚠️ **CLICK "SAVE CHANGES"** at bottom of page
                """
            return f"Token exchange failed: `{error}`"
        
        if not (claims := self.auth.verify_token(tokens["id_token"])):
            return "❌ JWT signature validation failed. Possible token tampering."
        
        if not (user_info := self.auth.get_user_info(tokens["access_token"])):
            return "❌ Failed to fetch user profile from Auth0."
        
        st.session_state.update({
            "authenticated": True,
            "user": user_info,
            "tokens": tokens,
            "login_time": datetime.now(),
            "auth_type": "Regular Web Application",
            "app_page": "regular_web"
        })
        st.query_params.clear()
        return None
    
    def logout(self):
        for key in ["authenticated", "user", "tokens", "login_time", "oauth_state", "app_page"]:
            st.session_state.pop(key, None)
        logout_url = self.auth.logout_url("http://localhost:8501")
        st.markdown(f'<meta http-equiv="refresh" content="0; url={logout_url}">', 
                   unsafe_allow_html=True)


# ==================== VIEW ====================
def main():
    # Initialize auth
    try:
        cfg = st.secrets.auth0_regular
        auth = RegularWebAuth(cfg.domain, cfg.client_id, cfg.client_secret)
        controller = RegularWebController(auth)
    except Exception as e:
        st.error(f"❌ Configuration error: {e}\n\nCheck `.streamlit/secrets.toml` has [auth0_regular] section")
        st.stop()
    
    # Handle OAuth callback
    if "code" in st.query_params:
        error = controller.handle_callback()
        if error:
            st.error(error)
            st.query_params.clear()
            st.stop()
        st.rerun()
    
    # Header
    st.title("🔐 Regular Web Application")
    st.caption("Server-Side Authentication with client_secret • Security Level: ⭐⭐⭐⭐⭐")
    st.divider()
    
    # Educational content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### 🔒 How This Flow Works (Server-Side)
        
        ```mermaid
        sequenceDiagram
            User->>+Browser: Clicks "Login"
            Browser->>+Auth0: Redirect to login page
            Auth0->>+User: Shows login form
            User->>+Auth0: Enters credentials
            Auth0->>+Browser: Redirect with code
            Browser->>+Your Server: Sends code to /callback
            Your Server->>+Auth0: Exchanges code + client_secret for tokens
            Auth0->>+Your Server: Returns tokens
            Your Server->>+Browser: Creates session cookie
            Browser->>+Your Server: Accesses protected routes with cookie
        ```
        
        ### ✅ Security Advantages
        - **client_secret never leaves server** (unlike SPAs/native apps)
        - **No PKCE required** (client_secret provides equivalent protection)
        - **Full control over token validation** (server-side JWKS checks)
        - **Secure session management** using HTTP-only cookies (Streamlit sessions)
        - **Protection against token leakage** (tokens never in browser JS)
        
        ### ⚠️ Critical Requirements
        1. Application Type = **"Regular Web Application"** in Auth0
        2. Grant Type = **"Authorization Code"** enabled
        3. **Never expose client_secret** in frontend code
        4. Always validate **state parameter** (CSRF protection)
        5. Always validate **JWT signatures** with JWKS
        """)
    
    with col2:
        st.info("### 🛡️ Security Checklist")
        checks = [
            ("Application Type", "✅ Regular Web Application"),
            ("Grant Type", "✅ Authorization Code"),
            ("client_secret", "✅ Server-side only"),
            ("PKCE Required", "❌ No (client_secret sufficient)"),
            ("CSRF Protection", "✅ State parameter"),
            ("Token Validation", "✅ JWKS signature check")
        ]
        for label, status in checks:
            st.markdown(f"**{label}**: {status}")
        
        st.divider()
        st.warning("""
        ### 🚫 Common Vulnerabilities
        
        - Using SPA type for server apps → ❌ Secret leakage risk
        - Skipping state validation → ❌ CSRF attacks
        - Skipping JWT validation → ❌ Token forgery
        - Exposing tokens in URLs → ❌ Leakage via referrers
        """)
    
    st.divider()
    
    # Authentication UI
    if st.session_state.get("authenticated") and st.session_state.get("app_page") == "regular_web":
        user = st.session_state.user
        tokens = st.session_state.tokens
        
        # User profile
        st.success(f"✅ Authenticated as **{user.get('email', 'User')}**")
        
        with st.expander("👤 User Profile", expanded=True):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.write(f"**Name:** {user.get('name', '-')}")
                st.write(f"**Email:** {user.get('email', '-')}")
                st.write(f"**Verified:** {'✅ Yes' if user.get('email_verified') else '❌ No'}")
                st.write(f"**Auth Time:** {st.session_state.login_time.strftime('%Y-%m-%d %H:%M:%S')}")
            with col2:
                if pic := user.get("picture"):
                    st.image(pic, width=120)
                st.write(f"**User ID:** `{user.get('sub', '-')[:15]}...`")
        
        # Token info (educational)
        with st.expander("🔐 Token Information (Educational)", expanded=False):
            st.markdown(f"""
            **ID Token** (JWT):
            - Subject: `{tokens['id_token'].split('.')[1][:20]}...`
            - Expires: `{datetime.fromtimestamp(tokens['expires_in'] + st.session_state.login_time.timestamp()).strftime('%H:%M:%S')}`
            
            **Access Token** (Opaque/Bearer):
            - Type: `{tokens.get('token_type', 'Bearer')}`
            - Scope: `{tokens.get('scope', '-')}`
            
            > 💡 **Security Note**: Access tokens are validated server-side. 
            > Never expose raw tokens to browser JavaScript in production apps.
            """)
        
        # Logout
        st.divider()
        if st.button("🚪 Logout (Clear Session + Auth0)", type="primary", use_container_width=True):
            controller.logout()
    
    else:
        st.info("""
        ### 👤 Ready to Test Authentication?
        
        1. Click **"Login with Auth0"** below
        2. Enter credentials for a test user (create in Auth0 Dashboard → User Management → Users)
        3. After successful login, you'll see your profile here
        
        > 💡 **No test user?** Create one in Auth0 Dashboard:
        > - User Management → Users → "+ Create User"
        > - Email: `test@example.com`
        > - Password: `TestPass123!`
        > - Connection: `Username-Password-Authentication`
        """)
        
        if st.button("🚀 Login with Auth0", type="primary", use_container_width=True):
            controller.handle_login()
    
    # Footer
    st.divider()
    st.caption(f"🔐 Regular Web App Demo • Version {APP_VERSION} • Built {APP_BUILD_DATE}")
    st.caption("Educational purpose only • Follow Auth0 security best practices in production")

if __name__ == "__main__":
    main()
