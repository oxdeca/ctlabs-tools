# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/cloudflare/base.py
# License : MIT
# -----------------------------------------------------------------------------

import os

import requests


class CloudflareError(Exception):
    """Raised when the Cloudflare API returns an unsuccessful response."""


class CloudflareBase:
    API_BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, token=None, account_id=None, zone_id=None, timeout=30, vault=None):
        self.token      = token      or os.environ.get("CLOUDFLARE_API_TOKEN")
        self.account_id = account_id or os.environ.get("CLOUDFLARE_ACCOUNT_ID")
        self.zone_id    = zone_id    or os.environ.get("CLOUDFLARE_ZONE_ID")
        self.timeout    = timeout
        self.vault      = vault
        self.session    = requests.Session()

    #
    # Vault is only needed for the cubbyhole helpers. Imported lazily to keep
    # the Cloudflare client usable on its own.
    #
    def _get_vault(self):
        if self.vault is None:
            from ctlabs_tools.vault.core import HashiVault
            self.vault = HashiVault()
            self.vault.ensure_valid_token(interactive=False)
        return self.vault

    def _account_id(self):
        if not self.account_id:
            raise CloudflareError("No account_id configured. Pass account_id= or set $CLOUDFLARE_ACCOUNT_ID.")
        return self.account_id

    def _url(self, path):
        if path.startswith("http"):
            return path
        return f"{self.API_BASE}/{path.lstrip('/')}"

    def _request(self, method, path, body=None, params=None, token=None, raw=False):
        """Fire a Cloudflare API call and return `result`, raising CloudflareError on failure."""
        headers = {"Content-Type": "application/json"}
        auth_token = token or self.token
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        res = self.session.request(
            method,
            self._url(path),
            headers=headers,
            json=body,
            params=params,
            timeout=self.timeout,
        )

        try:
            data = res.json()
        except ValueError:
            raise CloudflareError(f"{method} {path} returned a non-JSON response (HTTP {res.status_code}): {res.text[:400]}")

        if raw:
            return data

        if not data.get("success", False):
            errors = data.get("errors") or [{"code": res.status_code, "message": "unknown error"}]
            detail = "; ".join(f"[{e.get('code')}] {e.get('message')}".strip() for e in errors)
            raise CloudflareError(f"{method} {path} failed (HTTP {res.status_code}): {detail}")

        return data.get("result")
