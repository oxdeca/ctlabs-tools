# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/cloudflare/cli.py
# Purpose : Cloudflare CLI, split by concern:
#             cf-token  -> mint & manage Cloudflare API tokens
#             cf-vault  -> Vault-backed context & cubbyhole stash
# -----------------------------------------------------------------------------

import argparse
import contextlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from ..vault.core import HashiVault
from .core import Cloudflare
from .base import CloudflareError
from .mixins.tokens import ACCOUNT_SCOPE, ZONE_SCOPE


def parse_ttl(value):
    """Parse a human TTL ('90s', '30m', '1h', '7d') into an ISO-8601 UTC expires_on string."""
    if not value:
        return None
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    unit = value[-1].lower()
    if unit not in units:
        raise ValueError(f"Invalid TTL {value!r}: use a suffix of s/m/h/d (e.g. 1h, 7d).")
    seconds = int(value[:-1]) * units[unit]
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scope_id(scope):
    return ZONE_SCOPE if scope == "zone" else ACCOUNT_SCOPE


def _connect(args):
    """Return (Cloudflare client, HashiVault client)."""
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    token      = args.token
    account_id = args.account_id
    zone_id    = args.zone_id

    if not token:
        secret = vault.read_secret(path=args.secret_path, mount_point=args.mount)
        if not secret:
            print(f"❌ No Cloudflare credentials found at {args.mount}/{args.secret_path}", file=sys.stderr)
            sys.exit(1)
        token      = secret.get("account_token", "")
        account_id = account_id or secret.get("account_id", "")
        zone_id    = zone_id    or secret.get("zone_id", "")

    return Cloudflare(token=token, account_id=account_id, zone_id=zone_id, timeout=args.timeout, vault=vault), vault


def _mint(cf, args, default_name):
    """Mint a token from the shared CLI flags. Returns the create result."""
    expires_on = args.expires_on or parse_ttl(args.ttl)
    return cf.create_scoped_token(
        name=args.name or default_name,
        permissions=args.permission_group,
        scope=args.scope,
        zone_id=args.zone_id or None,
        expires_on=expires_on,
        permission_scope=_scope_id(args.permission_scope) if args.permission_scope else None,
    )


def _store(vault, cf, path, token):
    # Keep stdout clean (the raw token) by routing the KV helper's prints to stderr.
    with contextlib.redirect_stdout(sys.stderr):
        return vault.write_secret(path=path, mount_point="cubbyhole",
                                  secret_data={"account_id": cf.account_id, "zone_id": cf.zone_id, "account_token": token})


#
# Argument parsing
#
def _add_global_flags(parser):
    parser.add_argument("--timeout", type=int, default=30, help="API HTTP timeout in seconds")
    parser.add_argument("--mount", default="kvv2", help="Vault KV mount holding the Cloudflare secrets (default: kvv2)")
    parser.add_argument("--secret-path", default="cloudflare", help="Vault secret path holding account_id/zone_id/account_token")
    parser.add_argument("--account-id", default="", help="Override the Cloudflare account id")
    parser.add_argument("--zone-id", default="", help="Override the Cloudflare zone id")
    parser.add_argument("--token", default="", help="Override the creator token (skips the Vault lookup)")


def _add_mint_flags(p, expire=True):
    p.add_argument("--name", default="", help="Token name (default: vault-cf-<command>)")
    p.add_argument("--permission-group", "-p", action="append", default=[], required=True, help="Permission group name (repeatable)")
    p.add_argument("--scope", choices=["account", "zone"], default="zone", help="Policy resource scope (default: zone)")
    p.add_argument("--permission-scope", choices=["account", "zone"], default=None,
                   help="Scope used to resolve permission names (default: matches --scope)")
    if expire:
        p.add_argument("--ttl", default="", help="Ephemeral TTL, e.g. 30m / 1h / 7d (sets expires_on)")
    p.add_argument("--expires-on", default="", help="Explicit ISO-8601 expiry (overrides --ttl)")


def _add_store_flags(p):
    p.add_argument("--store", action="store_true", help="Also stash the token in Vault's cubbyhole")
    p.add_argument("--cubbyhole-path", default="cloudflare", help="Cubbyhole path for --store (default: cloudflare)")


def build_token_parser():
    parser = argparse.ArgumentParser(prog="cf-token", description="Mint & manage Vault-backed Cloudflare API tokens")
    _add_global_flags(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # GET-TOKEN -----------------------------------------------------------
    p_get = subparsers.add_parser("get-token", help="Mint a token and print it (raw value on stdout)")
    _add_mint_flags(p_get)
    _add_store_flags(p_get)

    # EXEC ----------------------------------------------------------------
    p_exec = subparsers.add_parser("exec", help="Run a command with a freshly minted, then revoked, token in the env")
    _add_mint_flags(p_exec)
    _add_store_flags(p_exec)
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, help="The command to execute (prefix with '--')")

    # LIST ----------------------------------------------------------------
    subparsers.add_parser("list", help="List account tokens")

    # INFO ----------------------------------------------------------------
    p_info = subparsers.add_parser("info", help="Show token metadata by id")
    p_info.add_argument("token_id")

    # REVOKE --------------------------------------------------------------
    p_revoke = subparsers.add_parser("revoke", help="Revoke a token by id")
    p_revoke.add_argument("token_id")

    # VERIFY --------------------------------------------------------------
    p_verify = subparsers.add_parser("verify", help="Verify a *user* token (account tokens are not introspectable)")
    p_verify.add_argument("token", nargs="?", default="", help="Token value (defaults to the configured token)")

    # PERMISSION GROUPS ---------------------------------------------------
    p_perms = subparsers.add_parser("permission-groups", help="Inspect Cloudflare permission groups")
    perms_subs = p_perms.add_subparsers(dest="action", required=True)
    p_perms_list = perms_subs.add_parser("list", help="List permission groups")
    p_perms_list.add_argument("--scope", choices=["account", "zone"], default="", help="Filter by scope")
    p_perms_list.add_argument("--filter", default="", help="Substring filter on the group name")

    return parser


def build_vault_parser():
    parser = argparse.ArgumentParser(prog="cf-vault", description="Inspect the Vault-backed Cloudflare context")
    _add_global_flags(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # INFO ----------------------------------------------------------------
    subparsers.add_parser("info", help="Show the Cloudflare context and the creator token inventory")

    # CUBBYHOLE -----------------------------------------------------------
    p_cubby = subparsers.add_parser("cubbyhole", help="Inspect the local cubbyhole stash")
    cubby_subs = p_cubby.add_subparsers(dest="action", required=True)
    p_cubby_read = cubby_subs.add_parser("read", help="Read the cubbyhole stash")
    p_cubby_read.add_argument("path", nargs="?", default="cloudflare")
    p_cubby_clear = cubby_subs.add_parser("clear", help="Delete the cubbyhole stash")
    p_cubby_clear.add_argument("path", nargs="?", default="cloudflare")

    return parser


#
# Command handlers
#
_STATUS_ICONS = {"active": "🟢", "disabled": "🟡", "expired": "🔴"}
_KIND_ICONS   = {"account": "🏛️", "zone": "🧭", "account+zone": "🌐", "unknown": "❔"}


def _token_kinds(token):
    """Classify an account token as account-scoped and/or zone-scoped from its policies."""
    kinds = set()
    for policy in token.get("policies") or []:
        for resource in (policy.get("resources") or {}):
            if resource.startswith(f"{ZONE_SCOPE}."):
                kinds.add("zone")
            elif resource.startswith(f"{ACCOUNT_SCOPE}."):
                kinds.add("account")
    return kinds or {"unknown"}


def _print_account_tokens(tokens):
    print(f"🎫 Account tokens ({len(tokens)}):")
    last = len(tokens) - 1
    for i, token in enumerate(tokens):
        branch = "└─" if i == last else "├─"
        status = token.get("status", "?")
        kinds  = "+".join(sorted(_token_kinds(token)))
        print(f"  {branch} {_STATUS_ICONS.get(status, '⚪')} {status:8} "
              f"{_KIND_ICONS.get(kinds, '❔')} {kinds:12} {token.get('id')}  "
              f"expires={token.get('expires_on')}  {token.get('name')}")


def _run_token(args, cf, vault):
    cmd = args.command

    # GET-TOKEN -----------------------------------------------------------
    if cmd == "get-token":
        result = _mint(cf, args, "vault-cf-get-token")
        print(json.dumps({k: v for k, v in result.items() if k != "value"}, indent=2), file=sys.stderr)

        if args.store and _store(vault, cf, args.cubbyhole_path, result["value"]):
            print(f"✅ Stashed token at cubbyhole/{args.cubbyhole_path}", file=sys.stderr)

        print(result["value"])

    # EXEC ----------------------------------------------------------------
    elif cmd == "exec":
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]
        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        result = _mint(cf, args, "vault-cf-exec")
        token  = result["value"]
        if args.store and _store(vault, cf, args.cubbyhole_path, token):
            print(f"✅ Stashed token at cubbyhole/{args.cubbyhole_path}", file=sys.stderr)

        env = os.environ.copy()
        env["CLOUDFLARE_API_TOKEN"] = token
        if cf.account_id:
            env["CLOUDFLARE_ACCOUNT_ID"] = cf.account_id
        if cf.zone_id:
            env["CLOUDFLARE_ZONE_ID"] = cf.zone_id

        print(f"🚀 Executing: {' '.join(command_list)}\n" + "-" * 40, file=sys.stderr)
        try:
            returncode = subprocess.run(command_list, env=env).returncode
        except FileNotFoundError:
            print(f"\n❌ Error: Command not found: {command_list[0]}", file=sys.stderr)
            returncode = 1
        finally:
            try:
                cf.revoke_token(result["id"])
                print(f"🧹 Revoked ephemeral token {result['id']}", file=sys.stderr)
            except CloudflareError as e:
                print(f"⚠️  Failed to revoke {result['id']}: {e}", file=sys.stderr)
        sys.exit(returncode)

    # LIST / INFO / REVOKE / VERIFY ---------------------------------------
    elif cmd == "list":
        _print_account_tokens(cf.list_tokens())

    elif cmd == "info":
        print(json.dumps(cf.get_token(args.token_id), indent=2))

    elif cmd == "revoke":
        cf.revoke_token(args.token_id)
        print(f"✅ Revoked token {args.token_id}")

    elif cmd == "verify":
        print(json.dumps(cf.verify_token(token=args.token or None), indent=2))

    # PERMISSION GROUPS ---------------------------------------------------
    elif cmd == "permission-groups":
        groups = cf.list_permission_groups(scope=_scope_id(args.scope) if args.scope else None)
        if args.filter:
            needle = args.filter.lower()
            groups = [g for g in groups if needle in g["name"].lower()]
        for g in groups:
            print(f"  {g['id']}  {g['name']}  [{', '.join(g.get('scopes', []))}]")


def _run_vault(args, cf, vault):
    cmd = args.command

    # INFO ----------------------------------------------------------------
    if cmd == "info":
        print(f"🏛️  Cloudflare account : {cf.account_id}")
        print(f"🧭 Zone id            : {cf.zone_id or '-'}")
        print(f"🔐 Creator token      : {'...' + cf.token[-6:] if cf.token else 'none'}")

        _print_account_tokens(cf.list_tokens())

        try:
            zones = cf._request("GET", "zones", params={"account.id": cf.account_id})
            print(f"🌐 Zones visible       : {len(zones)}")
            for z in zones[:10]:
                print(f"  ├─ {z.get('name')}  ({z.get('id')})  {z.get('status', '')}")
        except CloudflareError as e:
            print(f"⚠️  Zone listing unavailable with this token: {e}")

    # CUBBYHOLE -----------------------------------------------------------
    elif cmd == "cubbyhole":
        if args.action == "read":
            data = cf.read_cubbyhole(path=args.path)
            if data:
                safe = {k: (v if k != "account_token" else f"...{str(v)[-6:]}") for k, v in data.items()}
                print(json.dumps(safe, indent=2))
            else:
                print(f"ℹ️ Nothing at cubbyhole/{args.path}")
        elif args.action == "clear":
            if cf.clear_cubbyhole(path=args.path):
                print(f"✅ Cleared cubbyhole/{args.path}")


def _dispatch(build_parser, run):
    args = build_parser().parse_args()
    cf, vault = _connect(args)
    try:
        run(args, cf, vault)
    except CloudflareError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)


def main_token():
    _dispatch(build_token_parser, _run_token)


def main_vault():
    _dispatch(build_vault_parser, _run_vault)


if __name__ == "__main__":
    main_token()
