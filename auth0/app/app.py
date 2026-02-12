# -----------------------------------------------------------------------------
# File    : ctlabs-tools/auth0/app/app.py
# License : MIT
# -----------------------------------------------------------------------------

"""
Auth0 Integration Education Suite - Main Dashboard
Demonstrates secure patterns for all 4 Auth0 application types
Version: 2.1.0 • Built: 2026-02-09
"""
import streamlit as st
from datetime import datetime

APP_VERSION = "2.1.0"
APP_BUILD_DATE = "2026-02-09"

def main():
    st.set_page_config(
        page_title=f"🔐 Auth0 Education Suite v{APP_VERSION}",
        page_icon="🔐",
        layout="wide",
        menu_items={
            "Get Help": "https://auth0.com/docs",
            "Report a bug": "https://github.com/auth0",
            "About": f"Auth0 Integration Education • v{APP_VERSION} • {APP_BUILD_DATE}"
        }
    )
    
    # Header with version
    col_logo, col_title = st.columns([1, 5])
    with col_logo:
        st.image("https://cdn.auth0.com/website/brandkit/logo/logo_symbol_blue_200.svg", width=60)
    with col_title:
        st.title("🔐 Auth0 Integration Education Suite")
        st.caption(f"Version {APP_VERSION} • Built {APP_BUILD_DATE}")
    
    st.divider()
    
    # Hero section
    st.markdown("""
    ## 🎓 Learn Secure Auth0 Integration Patterns
    
    This educational app demonstrates **production-ready authentication flows** for different application architectures.
    Each implementation follows Auth0 security best practices with clear explanations.
    """)
    
    # Application types grid
    st.subheader("🔍 Application Type Comparison")
    
    types = [
        {
            "emoji": "🔐",
            "name": "Regular Web App",
            "desc": "Server-rendered apps (Streamlit, Flask, Django)",
            "flow": "Authorization Code + client_secret",
            "secret_safe": "✅ Yes (server-side only)",
            "page": "1_Regular_Web_App"
        },
        {
            "emoji": "🌐",
            "name": "Single Page App",
            "desc": "React, Vue, Angular SPAs",
            "flow": "Authorization Code + PKCE",
            "secret_safe": "❌ No secrets (PKCE only)",
            "page": "2_Single_Page_App"
        },
        {
            "emoji": "📱",
            "name": "Native/Mobile",
            "desc": "iOS, Android, Desktop apps",
            "flow": "PKCE + Refresh Tokens",
            "secret_safe": "❌ No secrets (PKCE only)",
            "page": "3_Native_Mobile"
        },
        {
            "emoji": "🤖",
            "name": "Machine-to-Machine",
            "desc": "Backend services, CLI tools",
            "flow": "Client Credentials",
            "secret_safe": "✅ Yes (service-to-service)",
            "page": "4_Machine_to_Machine"
        }
    ]
    
    cols = st.columns(4)
    for idx, app_type in enumerate(types):
        with cols[idx]:
            st.page_link(f"pages/{app_type['page']}.py", 
                        label=f"{app_type['emoji']} {app_type['name']}",
                        icon=app_type['emoji'],
                        use_container_width=True)
            st.caption(app_type['desc'])
            st.caption(f"`{app_type['flow']}`")
            st.caption(f"Secrets: {app_type['secret_safe']}")
    
    st.divider()
    
    # Security principles
    st.subheader("🛡️ Universal Security Principles")
    
    principles = [
        "✅ **Never expose client_secret** in browser/mobile code",
        "✅ **Always validate redirect_uri** against allowlist",
        "✅ **Use PKCE** for all public clients (SPAs, Native)",
        "✅ **Validate JWT signatures** using JWKS endpoint",
        "✅ **Use short-lived tokens** + refresh tokens where appropriate",
        "✅ **Implement proper logout** (clear session + IdP logout)"
    ]
    
    for principle in principles:
        st.markdown(principle)
    
    st.divider()
    
    # Setup guide
    with st.expander("⚙️ Required Auth0 Setup (Do This First!)"):
        st.markdown("""
        ### Create 4 Separate Applications in Auth0 Dashboard:
        
        | Type | Auth0 Application Type | Critical Settings |
        |------|------------------------|-------------------|
        | **Regular Web** | `Regular Web Application` | ✅ Authorization Code grant<br>✅ Callback: `http://localhost:8501/pages/1_Regular_Web_App` |
        | **SPA** | `Single Page Application` | ✅ Authorization Code + PKCE<br>✅ Callback: `http://localhost:8501/pages/2_Single_Page_App` |
        | **Native** | `Native` | ✅ Authorization Code + PKCE + Refresh Token<br>✅ Callback: `http://localhost:8501/pages/3_Native_Mobile` |
        | **M2M** | `Machine to Machine` | ✅ Client Credentials grant<br>✅ API: Auth0 Management API (`read:users`) |
        
        ### After Creating Each App:
        1. Copy **Domain**, **Client ID**, and **Client Secret** (where applicable)
        2. Paste into `.streamlit/secrets.toml` (template provided above)
        3. ⚠️ **CLICK "SAVE CHANGES"** after enabling grant types!
        4. Create test users: **User Management → Users → + Create User**
        """)
    
    # Footer
    st.divider()
    st.markdown("""
    ### 📚 Learning Resources
    - [Auth0 Docs: Application Types](https://auth0.com/docs/get-started/applications)
    - [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
    - [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
    - [JWT Validation Best Practices](https://auth0.com/docs/secure/tokens/token-validation)
    
    > 💡 **Remember**: Choose the application type that matches your deployment environment. 
    > Using the wrong type (e.g., SPA type for server apps) creates critical security vulnerabilities.
    """)

if __name__ == "__main__":
    main()
