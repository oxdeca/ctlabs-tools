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
    create_parser.add_argument("--ttl", default="1h", help="Token TTL (e.g. 1h, 30m)")
    
    # Automated Policy Generation Flags
    create_parser.add_argument("--type", choices=["standard", "manager"], default="standard", 
                               help="Type of role to create (default: standard)")
    create_parser.add_argument("--target", help="Target role name (Required if type=manager)")
    create_parser.add_argument("--path", help="Vault KV path to auto-generate a minimal read policy (e.g., kv/apps/my-app)")
    
    # Manual Override
    create_parser.add_argument("--policies", help="Comma-separated list of existing policies (if not using auto-generation)")

    # Command: Get Credentials
    creds_parser = subparsers.add_parser("get-creds", help="Get RoleID and generate a new SecretID")
    creds_parser.add_argument("name", help="Name of the AppRole")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault()
    
    # Ensure we have an admin token from vault-login (or env vars)
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    if args.command == "setup":
        # Scenario 1: Setting up a Trusted Broker / Manager (like Rundeck)
        if args.type == "manager":
            if not args.target:
                print("❌ Error: --target is required when --type is 'manager'")
                sys.exit(1)
            
            pol_name = vault.create_manager_policy(args.name, args.target)
            if pol_name and vault.create_or_update_approle(args.name, [pol_name], ttl=args.ttl):
                print(f"✅ Manager AppRole '{args.name}' is ready to issue tokens for '{args.target}'.")
                
        # Scenario 2: Auto-generating a minimal read-only policy for a standard AppRole
        elif args.path:
            pol_name = vault.create_minimal_policy(args.name, args.path)
            if pol_name and vault.create_or_update_approle(args.name, [pol_name], ttl=args.ttl):
                print(f"✅ Standard AppRole '{args.name}' is ready with minimal access to '{args.path}'.")
                
        # Scenario 3: Manually supplying existing policy names
        elif args.policies:
            policies = [p.strip() for p in args.policies.split(",")]
            if vault.create_or_update_approle(args.name, policies, ttl=args.ttl):
                print(f"✅ AppRole '{args.name}' is ready with policies: {policies}")
                
        # Catch-all for missing arguments
        else:
            print("❌ Error: You must provide --path, --policies, or use '--type manager --target <role>'.")
            sys.exit(1)

    elif args.command == "get-creds":
        creds = vault.get_approle_credentials(args.name)
        if creds:
            # Output as JSON so it can be safely piped to jq or Rundeck
            print(json.dumps(creds, indent=2))

if __name__ == "__main__":
    main()
