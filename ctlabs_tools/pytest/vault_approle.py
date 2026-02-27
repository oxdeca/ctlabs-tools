# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/pytest/vault_approle.py
# Purpose : Generic Administrative CLI for AppRole Management
# -----------------------------------------------------------------------------

import argparse
import sys
import json
from .helper import HashiVault

def get_args():
    parser = argparse.ArgumentParser(description="Vault AppRole Administrative Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: Create/Update
    create_parser = subparsers.add_parser("setup", help="Create or update an AppRole")
    create_parser.add_argument("name", help="Name of the AppRole")
    create_parser.add_argument("--policies", required=True, help="Comma-separated list of policies")
    create_parser.add_argument("--ttl", default="1h", help="Token TTL (e.g. 1h, 30m)")

    # Command: Get Credentials
    creds_parser = subparsers.add_parser("get-creds", help="Get RoleID and generate a new SecretID")
    creds_parser.add_argument("name", help="Name of the AppRole")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault()
    
    # Ensure we have an admin token from vault-login
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    if args.command == "setup":
        policies = [p.strip() for p in args.policies.split(",")]
        if vault.create_or_update_approle(args.name, policies, ttl=args.ttl):
            print(f"✅ AppRole '{args.name}' is ready.")

    elif args.command == "get-creds":
        creds = vault.get_approle_credentials(args.name)
        if creds:
            # Output as JSON so it can be piped to other tools or Rundeck
            print(json.dumps(creds, indent=2))

if __name__ == "__main__":
    main()
