# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/cloudflare/mixins/tokens.py
# License : MIT
# -----------------------------------------------------------------------------

from ..base import CloudflareError

ACCOUNT_SCOPE = "com.cloudflare.api.account"
ZONE_SCOPE    = "com.cloudflare.api.account.zone"


class CloudflareTokensMixin:
    #
    # Permission groups
    #
    def list_permission_groups(self, scope=None):
        """List permission groups, optionally filtered by scope (e.g. ZONE_SCOPE)."""
        params = {"scope": scope} if scope else None
        return self._request("GET", f"accounts/{self._account_id()}/tokens/permission_groups", params=params) or []

    def resolve_permission_groups(self, names, scope=None):
        """Resolve permission group names (e.g. 'DNS Write') to the [{'id': ...}] payload CF expects."""
        index = {}
        for group in self.list_permission_groups(scope=scope):
            index.setdefault(group["name"], group)

        missing = [n for n in names if n not in index]
        if missing:
            raise CloudflareError(
                f"Unknown permission group(s) for scope {scope or 'any'!r}: {', '.join(missing)}"
            )

        return [{"id": index[n]["id"]} for n in names]

    #
    # Tokens
    #
    def list_tokens(self):
        return self._request("GET", f"accounts/{self._account_id()}/tokens") or []

    def get_token(self, token_id):
        """Fetch token metadata (never the secret value)."""
        return self._request("GET", f"accounts/{self._account_id()}/tokens/{token_id}")

    def create_token(self, name, policies, expires_on=None):
        """Create an account-owned API token. Returns the result including the secret `value`."""
        body = {"name": name, "policies": policies}
        if expires_on:
            body["expires_on"] = expires_on
        return self._request("POST", f"accounts/{self._account_id()}/tokens", body=body)

    def create_scoped_token(self, name, permissions, scope="zone", zone_id=None, expires_on=None, permission_scope=None):
        """
        Create an account token scoped either to the whole account or a single zone.

        permissions: list of permission group names, e.g. ['DNS Write', 'Zone Read']
        scope:       'zone'   -> resources {com.cloudflare.api.account.zone.<zone_id>: *}
                     'account'-> resources {com.cloudflare.api.account.<account_id>: *}

        permission_scope: scope used to *resolve* the permission group names. Defaults
        to the scope matching the resource. Pass ZONE_SCOPE explicitly when building an
        account-resource token out of zone permissions (e.g. to create zones).
        """
        if scope == "zone":
            target_zone = zone_id or self.zone_id
            if not target_zone:
                raise CloudflareError("zone scope requested but no zone_id configured.")
            resource    = f"{ZONE_SCOPE}.{target_zone}"
            default_ps  = ZONE_SCOPE
        elif scope == "account":
            resource    = f"{ACCOUNT_SCOPE}.{self._account_id()}"
            default_ps  = ACCOUNT_SCOPE
        else:
            raise CloudflareError(f"Unsupported token scope: {scope!r} (expected 'zone' or 'account').")

        policies = [{
            "effect":            "allow",
            "resources":         {resource: "*"},
            "permission_groups": self.resolve_permission_groups(permissions, scope=permission_scope or default_ps),
        }]

        return self.create_token(name, policies, expires_on=expires_on)

    def revoke_token(self, token_id):
        """Revoke (delete) an account token by id."""
        return self._request("DELETE", f"accounts/{self._account_id()}/tokens/{token_id}")

    def verify_token(self, token=None):
        """
        Verify a *user* token via /user/tokens/verify.

        Note: account-owned tokens (the ones this package mints) cannot be
        introspected here. Use get_token(token_id) / list_tokens() instead.
        """
        return self._request("GET", "user/tokens/verify", token=token)
