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
    create_parser.add_argument("name",       help="Name of the AppRole")
    create_parser.add_argument("--ttl",      default="1h", help="Token TTL (e.g. 1h, 30m)")
    create_parser.add_argument("--type",     choices=["standard", "manager"], default="standard", help="Type of role to create (default: standard)")
    create_parser.add_argument("--target",   help="Target role name (Required if type=manager)")
    create_parser.add_argument("--path",     help="Vault KV path to auto-generate a minimal read policy (e.g., kvv2/apps/my-app)")
    create_parser.add_argument("--policies", help="Comma-separated list of existing policies (if not using auto-generation)")

    # Command: Get Credentials
    creds_parser = subparsers.add_parser("get-creds", help="Get RoleID and generate a new SecretID")
    creds_parser.add_argument("name", help="Name of the AppRole")

    # Command: List AppRoles
    subparsers.add_parser("list", help="List all existing AppRoles")

    # Command: Delete AppRole
    delete_parser = subparsers.add_parser("delete", help="Delete an AppRole and its associated default policy")
    delete_parser.add_argument("name", help="Name of the AppRole to delete")
    delete_parser.add_argument("--keep-policy", action="store_true", help="Do not delete the associated auto-generated policy")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault()
    
    # Ensure we have an admin token from vault-login (or env vars)
    if not vault.ensure_valid_token(interactive=True):
        sys.exit(1)

    if args.command == "setup":
        if args.type == "manager":
            if not args.target:
                print("❌ Error: --target is required when --type is 'manager'")
                sys.exit(1)
            pol_name = vault.create_manager_policy(args.name, args.target)
            if pol_name and vault.create_or_update_approle(args.name, [pol_name], ttl=args.ttl):
                print(f"✅ Manager AppRole '{args.name}' is ready to issue tokens for '{args.target}'.")
                
        elif args.path:
            pol_name = vault.create_minimal_policy(args.name, args.path)
            if pol_name and vault.create_or_update_approle(args.name, [pol_name], ttl=args.ttl):
                print(f"✅ Standard AppRole '{args.name}' is ready with minimal access to '{args.path}'.")
                
        elif args.policies:
            policies = [p.strip() for p in args.policies.split(",")]
            if vault.create_or_update_approle(args.name, policies, ttl=args.ttl):
                print(f"✅ AppRole '{args.name}' is ready with policies: {policies}")
                
        else:
            print("❌ Error: You must provide --path, --policies, or use '--type manager --target <role>'.")
            sys.exit(1)

    elif args.command == "get-creds":
        creds = vault.get_approle_credentials(args.name)
        if creds:
            print(json.dumps(creds, indent=2))

    elif args.command == "list":
        roles = vault.list_approles()
        if roles is not None:
            if not roles:
                print("ℹ️ No AppRoles found.")
            else:
                print("📋 Existing AppRoles:")
                for r in roles:
                    print(f"  - {r}")

    elif args.command == "delete":
        if vault.delete_approle(args.name):
            print(f"✅ Deleted AppRole '{args.name}'.")
        
        # Automatically clean up the standard policy we generated during setup
        if not args.keep_policy:
            pol_name = f"policy-{args.name}"
            if vault.delete_policy(pol_name):
                print(f"✅ Cleaned up associated policy '{pol_name}'.")
    
    elif args.command == "list":
        roles = vault.list_approles()
        if roles is not None:
            if not roles:
                print("ℹ️ No AppRoles found.")
            else:
                print("📋 Existing AppRoles:")
                for r in roles:
                    if args.details:
                        details = vault.read_approle(r)
                        if details:
                            pols = ", ".join(details.get("token_policies", []))
                            ttl = details.get("token_ttl", "default")
                            print(f"  - {r.ljust(20)} | TTL: {str(ttl).ljust(6)} | Policies: {pols}")
                        else:
                            print(f"  - {r} (Error fetching details)")
                    else:
                        print(f"  - {r}")

if __name__ == "__main__":
    main()
