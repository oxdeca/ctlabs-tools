# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/jwt.py
# License : MIT
# -----------------------------------------------------------------------------

import json
import os
import time
import urllib.parse
import urllib.request

import hvac


class VaultJWTMixin:
    # -------------------------------------------------------------------------
    # JWT / OIDC CI/CD LOGIN (no static secret)
    #
    # A CI job presents a short-lived JWT issued by its platform (GitHub Actions,
    # GitLab, CircleCI, ...). Vault validates the signature against the provider's
    # OIDC discovery document and, if the bound claims match, issues a Vault token.
    # Nothing long-lived is stored on the runner.
    #
    # Env vars:
    #   VAULT_JWT           - the JWT itself (verbatim)
    #   VAULT_JWT_FILE      - path to a file containing the JWT
    #   VAULT_JWT_ROLE      - Vault role name                (default: default)
    #   VAULT_JWT_MOUNT     - JWT auth mount path            (default: jwt)
    #   VAULT_JWT_AUDIENCE  - audience for auto-fetch        (default: vault)
    #
    # Auto-detected platform variables: GitHub Actions
    #   (ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN) and GitLab CI (CI_JOB_JWT_V2/CI_JOB_JWT).
    # -------------------------------------------------------------------------

    def _load_jwt(self):
        """Return a CI JWT from the environment, a file, or the platform's OIDC endpoint."""
        jwt = os.getenv("VAULT_JWT")
        if jwt:
            return jwt.strip()

        path = os.getenv("VAULT_JWT_FILE")
        if path and os.path.exists(path):
            with open(path, "r") as f:
                return f.read().strip()

        # GitLab CI exposes the job JWT directly (legacy variable names).
        jwt = os.getenv("CI_JOB_JWT_V2") or os.getenv("CI_JOB_JWT")
        if jwt:
            return jwt.strip()

        return self._github_oidc_token()

    def _github_oidc_token(self):
        """Fetch a JWT from GitHub Actions' OIDC endpoint, when running in a workflow."""
        request_url   = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
        request_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not (request_url and request_token):
            return None

        audience = os.getenv("VAULT_JWT_AUDIENCE", "vault")
        sep = "&" if "?" in request_url else "?"
        url = f"{request_url}{sep}audience={urllib.parse.quote(audience)}"

        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode()).get("value")
        except Exception as e:
            print(f"❌ Failed to fetch a GitHub OIDC token: {e}")
            return None

    def jwt_login(self, vault_url, jwt=None, role=None, mount=None, verify=False):
        """Exchange a CI JWT for a Vault token and cache it in memory."""
        jwt   = jwt or self._load_jwt()
        role  = role  or os.getenv("VAULT_JWT_ROLE", "default")
        mount = mount or os.getenv("VAULT_JWT_MOUNT", "jwt")

        if not jwt:
            print("❌ JWT/OIDC login failed: no JWT found (set VAULT_JWT or VAULT_JWT_FILE).")
            return False

        client = hvac.Client(url=vault_url, verify=verify, timeout=self.timeout)
        try:
            res = client.auth.jwt.jwt_login(role=role, jwt=jwt, path=mount)
            auth = res["auth"]
            self._memory_token  = auth["client_token"]
            self._memory_url    = vault_url
            self._memory_expiry = int(time.time()) + auth.get("lease_duration", 3600)
            print(f"✅ JWT/OIDC login successful (role '{role}'). Token stored in memory.")
            return True
        except Exception as e:
            print(f"❌ JWT/OIDC authentication failed: {e}")
            return False
