# ☁️ CTLabs Cloudflare Token Suite

A dedicated CLI and Python API for managing Cloudflare API tokens with Zero Standing Privileges.
Long-lived credentials live in HashiCorp Vault; short-lived, scoped tokens are minted on demand
and revoked when they are no longer needed.

Two console scripts expose the tooling, split by concern:

| Command | Purpose |
|---------|---------|
| **`cf-token`** | Mint & manage Cloudflare API tokens (and inspect permission groups) |
| **`cf-vault`** | Inspect the Vault-backed Cloudflare context and the cubbyhole stash |

---

## 📦 Architecture & Philosophy

1. **Creator credential in Vault**: `kvv2/cloudflare` holds `account_id`, `zone_id` and `account_token`
   (the *creator* token, which only needs the `Account API Tokens Write` permission group).
2. **Mint on demand**: `create_scoped_token()` turns named permission groups (e.g. `DNS Write`) into a
   token scoped either to the whole account or to a single zone, with an optional expiry.
3. **Ephemeral by default**: `get-token` / `exec` mint short-lived tokens; `exec` runs your
   command with the token injected into the environment and **revokes it in a `finally` block**.
4. **Cubbyhole handoff**: `--store` stashes the minted token in Vault's *cubbyhole*, which is scoped to
   the calling Vault token. This lets a co-located consumer (e.g. Terraform's
   `ephemeral "vault_generic_secret"`) read the token without it ever touching state.

---

## 💻 `cf-token` — Mint & Manage Tokens

**Global flags** (apply to every command):

| Flag | Default | Description |
|------|---------|-------------|
| `--mount` | `kvv2` | Vault KV mount holding the Cloudflare secrets |
| `--secret-path` | `cloudflare` | Vault secret path (`account_id`/`zone_id`/`account_token`) |
| `--account-id` | from Vault/env | Override the Cloudflare account id |
| `--zone-id` | from Vault/env | Override the Cloudflare zone id |
| `--token` | from Vault/env | Override the creator token (skips the Vault lookup) |
| `--timeout` | `30` | API HTTP timeout, seconds |

### Mint & Print a Token (`get-token`)

Prints the raw token value on **stdout** (metadata goes to stderr, so it is safe to capture).

```bash
cf-token get-token -p "DNS Read" -p "Zone Read" --scope zone --ttl 30m
TOKEN=$(cf-token get-token -p "DNS Write" -p "DNS Read" --scope zone --ttl 1h)
```

### Just-In-Time Execution (`exec`)

Runs a command with a freshly minted token, then revokes it automatically.

```bash
cf-token exec -p "DNS Write" -p "DNS Read" --scope zone --ttl 15m -- terraform plan
cf-token exec -p "Zone Read" --scope account -- bash   # drops into an authenticated subshell
```

### Token Inventory (`list` / `info` / `revoke` / `verify`)

`list` groups account-owned tokens with a status icon and the token's kind
(`🏛️ account` vs `🧭 zone`, derived from its policies):

```bash
cf-token list
```

```
🎫 Account tokens (2):
  ├─ 🟢 active   🧭 zone     d866dc67bcd35a80e5cc6f0292119be4  expires=2026-09-17T22:59:45Z  cf-list-demo
  └─ 🟢 active   🏛️ account  3e78815a3fa383fb4cc31896050c3f1a  expires=2026-09-24T23:59:59Z  tf-token-creator
```

```bash
cf-token info <token_id>         # metadata + policies for one token
cf-token revoke <token_id>
cf-token verify [token]          # only works for *user* tokens, not account-owned ones
```

> **Note:** account-owned tokens can only list other **account-owned** tokens; user-owned tokens
> (`/user/tokens`) are not visible to an account token.

### Permission Groups (`permission-groups list`)

```bash
cf-token permission-groups list --scope zone
cf-token permission-groups list --scope account --filter dns
```

Add `--store [--cubbyhole-path <path>]` to `get-token` or `exec` to also stash the minted token at
`cubbyhole/<path>` (default `cloudflare`).

### Minting flags

| Flag | Description |
|------|-------------|
| `-p`, `--permission-group` | Permission group name, **repeatable** (e.g. `"DNS Write"`) |
| `--scope` | Policy resource scope: `zone` (default) or `account` |
| `--permission-scope` | Scope used to *resolve* permission names (defaults to `--scope`) |
| `--ttl` | Ephemeral TTL: `90s` / `30m` / `1h` / `7d` (sets `expires_on`) |
| `--expires-on` | Explicit ISO-8601 expiry (overrides `--ttl`) |
| `--store` | Also stash the token in Vault's cubbyhole |
| `--cubbyhole-path` | Cubbyhole path for `--store` (default `cloudflare`) |

---

## 🏛️ `cf-vault` — Vault Context & Cubbyhole

```bash
cf-vault info                 # account/zone context, creator token id, token inventory
cf-vault cubbyhole read       # read the stash at cubbyhole/cloudflare
cf-vault cubbyhole read mypath
cf-vault cubbyhole clear      # delete the stash
```

It accepts the same global flags as `cf-token`.

---

## 🤖 CI/CD Authentication

`vault-login` is for **humans**: it caches a token sealed with GPG under `~/.ctlabs_vault/`. A CI runner
has no such cache, so authentication is driven entirely by environment variables. `ensure_valid_token()`
resolves credentials in this order:

1. the local GPG/memory cache (dev workflow), then
2. **JWT / OIDC** when a CI token is present (see below), then
3. **AppRole** when `VAULT_ROLE_ID`, `VAULT_SECRET_ID` and `VAULT_ADDR` are present, then
4. fail (or prompt) if none are available.

### Preferred: JWT / OIDC (no static secret)

The runner presents a short-lived JWT issued by its platform; Vault validates it against the provider's
OIDC discovery document and issues a Vault token directly. Nothing long-lived is stored. Just set
`VAULT_ADDR` plus a JWT source:

| Variable | Description |
|----------|-------------|
| `VAULT_JWT` | The JWT itself (verbatim) |
| `VAULT_JWT_FILE` | Path to a file containing the JWT |
| `VAULT_JWT_ROLE` | Vault role name (default: `default`) |
| `VAULT_JWT_MOUNT` | JWT auth mount path (default: `jwt`) |
| `VAULT_JWT_AUDIENCE` | Audience used for GitHub auto-fetch (default: `vault`) |

Platforms are auto-detected: **GitHub Actions** (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`, fetched with
`id-token: write`) and **GitLab CI** (`CI_JOB_JWT_V2` / `CI_JOB_JWT`). GitHub example:

```yaml
jobs:
  deploy:
    permissions:
      id-token: write          # required to request the OIDC token
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: cf-token exec -p "DNS Write" -p "DNS Read" --scope zone --ttl 15m -- terraform apply -auto-approve
        env:
          VAULT_ADDR: "https://vault.example.com:8200"
          VAULT_JWT_ROLE: "cloudflare-ci"
          VAULT_JWT_AUDIENCE: "vault"
```

```bash
# One-time: point Vault at the provider and bind a role to the job's claims
vault write auth/jwt/config oidc_discovery_url="https://token.actions.githubusercontent.com"
vault write auth/jwt/role/cloudflare-ci \
  role_type="jwt" user_claim="sub" bound_audiences="vault" \
  bound_claims_type="glob" bound_claims='{"repository":"acme/*"}' \
  token_policies="cloudflare-ci" token_ttl="30m"
```

### Fallback: AppRole

Simplest to bootstrap, but the SecretID is a long-lived secret: rotate/mask it and scope the role to a
least-privilege policy. Prefer a **response-wrapped SecretID** — fetch a single-use, short-TTL
(`wrap_ttl`) SecretID at job start and unwrap it into `VAULT_SECRET_ID`.

```yaml
# e.g. GitLab CI
deploy:
  script:
    - cf-token exec -p "DNS Write" -p "DNS Read" --scope zone --ttl 15m -- terraform apply -auto-approve
  variables:
    VAULT_ADDR: "https://vault.example.com:8200"
    VAULT_ROLE_ID: "$VAULT_ROLE_ID"        # from CI secret store / masked variable
    VAULT_SECRET_ID: "$VAULT_SECRET_ID"    # ideally response-wrapped, see below
```

```bash
# Bootstrap the role + policy (vault-auth), then mint credentials for the runner
vault-auth approle create cloudflare-ci --policies cloudflare-ci --ttl 30m
vault-auth approle info cloudflare-ci
```

Whichever path you choose, scope the policy to exactly what the job needs (`kvv2/data/cloudflare` +
`cubbyhole/*` for `--store`) and keep token TTLs short so credentials expire on their own.

---

## 🔑 Permission Model

- **Zone scope** (`--scope zone`) grants a token access to a single zone. Permission names are resolved
  against the zone-scope groups (`ZONE_SCOPE` = `com.cloudflare.api.account.zone`).
- **Account scope** (`--scope account`) grants access to the whole account
  (`ACCOUNT_SCOPE` = `com.cloudflare.api.account`).
- Cloudflare accepts **zone-scoped permission groups on an account-resource policy**. This is how you
  mint a token capable of *creating new zones*: `--scope account --permission-scope zone`.

```bash
# Account-wide token built from zone permission groups (e.g. to create zones)
cf-token get-token --scope account --permission-scope zone \
  -p "Zone Write" -p "Zone Read" -p "DNS Write" --ttl 1h
```

---

## 🐍 Python API

```python
from ctlabs_tools.cloudflare import Cloudflare
from ctlabs_tools.cloudflare.mixins.tokens import ZONE_SCOPE, ACCOUNT_SCOPE

# Credentials may come from Vault (vault=...) or from $CLOUDFLARE_API_TOKEN/ACCOUNT_ID/ZONE_ID
cf = Cloudflare(account_id="...", zone_id="...", vault=vault)

# Mint a zone-scoped token from named permission groups
token = cf.create_scoped_token(
    name="ci-deploy",
    permissions=["DNS Write", "Zone Read"],
    scope="zone",
    expires_on="2026-09-24T23:59:59Z",
)["value"]

cf.list_tokens()
cf.get_token("<token_id>")
cf.revoke_token("<token_id>")

# Cubbyhole helpers (need a HashiVault instance)
cf.store_cubbyhole(path="cloudflare")
cf.read_cubbyhole(path="cloudflare")
cf.clear_cubbyhole(path="cloudflare")
```

---

## ⚠️ Notes & Gotchas

- **Account-owned tokens are not user-introspectable.** `GET /user/tokens/verify` returns `401` for
  them; use `cf-token list` / `cf-token info <id>` instead.
- **Subdomain zones require Enterprise.** Free/Pro accounts cannot create a zone for a subdomain
  (API error `1116`); partial setup is also rejected (`1104`).
- **Private IPs cannot be proxied.** Cloudflare rejects proxied records whose target is RFC1918
  (error `9003`); set `proxied: false` for lab records.
- **Cubbyhole is scoped to the Vault token that wrote it.** A consumer must use the *same* Vault token
  to read it. In particular, the Terraform Vault provider mints an ephemeral child token for its reads
  by default, which cannot see your cubbyhole — set `skip_child_token = true` on the `vault` provider.
