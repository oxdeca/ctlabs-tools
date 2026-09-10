# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/vault_gcp.py
# Purpose : Dedicated CLI for GCP Dynamic Secrets & Identity Management
# -----------------------------------------------------------------------------

import sys
import os
import re
import argparse
import subprocess
import json
import yaml
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from .core import HashiVault

def run_gcloud(cmd_list, capture_json=False, ignore_errors=False, quiet=False, retries=1, retry_delay=5):
    """Silently runs a gcloud command with built-in polling/retry logic and smart auth detection."""
    for attempt in range(1, retries + 1):
        try:
            res = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
            if capture_json:
                return res.stdout.strip()
            return True
        except FileNotFoundError:
            print(f"\n❌ Environment Error: '{cmd_list[0]}' command not found.", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            stderr_text = e.stderr.lower()

            # 🔥 SMART UX: Fail fast on authentication errors
            if "reauthentication failed" in stderr_text or "gcloud auth login" in stderr_text:
                print(f"\n🔐 GCP Authentication Error: Your gcloud session has expired or is missing.", file=sys.stderr)
                print(f"👉 Fix this by running: gcloud auth login", file=sys.stderr)
                sys.exit(1)

            if attempt < retries:
                if not quiet:
                    cmd_name = cmd_list[1] if len(cmd_list) > 1 else "command"
                    print(f"  ⏳ GCP not ready. Retrying '{cmd_name}' in {retry_delay}s (Attempt {attempt}/{retries})...")
                time.sleep(retry_delay)
                continue
            if ignore_errors:
                return False
            print(f"\n❌ GCP Command Failed: {' '.join(cmd_list)}\nError output: {e.stderr.strip()}", file=sys.stderr)
            sys.exit(1)

def resolve_gcp_folder_id(input_str, org_id=None):
    """
    Looks up a GCP Folder ID from a potential Display Name.
    Requires org_id if input_str is a display name.
    """
    if input_str and input_str.strip().isdigit():
        return input_str.strip()

    # Check for required context
    if not org_id:
        print(f"  ⚠️ Cannot resolve Display Name '{input_str}': Missing --organization context.", file=sys.stderr)
        return input_str # Fallback to original string

    print(f"  🔍 Resolving GCP Folder Display Name '{input_str}' inside Organization '{org_id}'...", file=sys.stderr)
    cmd = [
        "gcloud", "resource-manager", "folders", "list",
        f"--organization={org_id}", # 🌟 UPDATED: Context added!
        f'--filter=displayName:"{input_str}"',
        "--format=json"
    ]

    json_result = run_gcloud(cmd, capture_json=True, ignore_errors=True, quiet=True)

    # (Existing parsing logic remains the same below)
    if json_result:
        try:
            folder_list = json.loads(json_result)
            if folder_list:
                numeric_id = folder_list[0]['name'].split('folders/')[-1]
                print(f"  ✅ Resolved Display Name '{input_str}' to Folder ID '{numeric_id}'.", file=sys.stderr)
                return numeric_id
        except Exception:
            pass

    print(f"  ⚠️ Could not resolve Display Name '{input_str}' (Lookup failed). Passing string directly...", file=sys.stderr)
    return input_str

def gcp_rest(method, url, token, body=None, ignore_errors=False):
    """Fire a REST call against a Google Cloud API using a JIT token (No gcloud required)."""
    import urllib.request, urllib.error
    import ssl

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context()) as res:
            return json.loads(res.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        if ignore_errors:
            return {"error": {"code": e.code, "message": error_body}}
        print(f"❌ GCP API Error ({e.code}): {error_body}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if ignore_errors:
            return {"error": {"message": str(e)}}
        print(f"❌ Error communicating with GCP API: {e}", file=sys.stderr)
        sys.exit(1)

def gcp_wait_operation(op, token, base_url):
    """Poll a Google Cloud LRO until done (soft 4-minute cap)."""
    name = op.get("name")
    if not name:
        return op
    url = f"{base_url}/{name.lstrip('/')}"
    print("  ⏳ Waiting for GCP operation to complete...", file=sys.stderr)
    for _ in range(120):
        res = gcp_rest("GET", url, token, ignore_errors=True)
        if res.get("done") is True:
            if res.get("error"):
                print(f"❌ GCP Operation failed: {json.dumps(res['error'])}", file=sys.stderr)
                sys.exit(1)
            return res
        time.sleep(2)
    print("❌ Timeout waiting for GCP operation to complete.", file=sys.stderr)
    sys.exit(1)

# -----------------------------------------------------------------------------
# SANDBOX POOL HELPERS (no gcloud; JIT token + REST only)
#
# Pool lifecycle:  free -> leased -> disabled -> free
#   - lease   : claim the first 'state=free' member, set owner/purpose/lease-until
#   - release : disable ALL enabled services + mark 'disabled' (still holds data;
#               a human runs terraform destroy, then 'reset')
#   - reset   : mark a 'disabled' project 'free' again (teardown confirmed done)
#   - list    : show pool state; --sweep auto-releases expired leases
# -----------------------------------------------------------------------------
CRM_V1 = "https://cloudresourcemanager.googleapis.com/v1"
SERVICEUSAGE_V1 = "https://serviceusage.googleapis.com/v1"

def sandbox_expire_dt(days):
    """leash-until timestamp stored as ISO-8601 UTC string."""
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

def sandbox_parse_dt(iso_str):
    try:
        return datetime.fromisoformat(iso_str)
    except (ValueError, TypeError):
        return None

def sandbox_pool(token, folder_id):
    """List pool members: direct children of the folder (consistent index)."""
    filt = quote(f"parent.type:folder parent.id:{folder_id}")
    res = gcp_rest("GET", f"{CRM_V1}/projects?filter={filt}", token)
    return [p for p in res.get("projects", []) if p.get("lifecycleState") == "ACTIVE"]

def sandbox_get_project(token, project_id):
    return gcp_rest("GET", f"{CRM_V1}/projects/{project_id}", token)

def sandbox_patch_project(token, project_id, display_name=None, labels=None):
    """PATCH displayName + labels (requires resourcemanager.projects.update, in roles/editor)."""
    body, mask = {}, []
    if display_name is not None:
        body["displayName"] = display_name
        mask.append("displayName")
    if labels is not None:
        body["labels"] = labels
        mask.append("labels")
    if not mask:
        return {}
    return gcp_rest("PATCH", f"{CRM_V1}/projects/{project_id}?updateMask={','.join(mask)}", token, body)

def sandbox_disable_all_services(token, project_id):
    """Best-effort: disable every enabled API so the project can't spend."""
    res = gcp_rest("GET", f"{SERVICEUSAGE_V1}/projects/{project_id}/services?filter=state:ENABLED", token, ignore_errors=True)
    enabled = [
        s["name"].rsplit("/", 1)[-1]
        for s in res.get("services", [])
        if s.get("state") == "ENABLED"
    ]
    if not enabled:
        return 0
    op = gcp_rest("POST", f"{SERVICEUSAGE_V1}/projects/{project_id}/services:batchDisable", token, {"serviceIds": enabled})
    gcp_wait_operation(op, token, SERVICEUSAGE_V1)
    return len(enabled)

def sandbox_enable_services(token, project_id, service_ids):
    op = gcp_rest("POST", f"{SERVICEUSAGE_V1}/projects/{project_id}/services:batchEnable", token, {"serviceIds": service_ids})
    gcp_wait_operation(op, token, SERVICEUSAGE_V1)

def sandbox_slug(value, maxlen=20):
    """Owner local-part / purpose slug for display names."""
    local = value.split("@")[0] if "@" in value else value
    s = re.sub(r"[^a-z0-9-]", "-", local.lower()).strip("-")
    s = re.sub(r"-+", "-", s)
    return s[:maxlen].rstrip("-") or "user"

def sandbox_display_name(project_id, state, owner=None, purpose=None):
    if state == "leased" and owner:
        slug = sandbox_slug(owner)
        suffix = sandbox_slug(purpose, maxlen=10)
        name = f"sbox-{slug}-{suffix}"
        name = re.sub(r"-+", "-", name).strip("-")
        if not name[0].isalpha():
            name = f"sbox-{name}"
        return name[:30]
    if state == "free":
        return f"{project_id} (free)"
    if state == "disabled":
        return f"{project_id} (disabled)"
    return project_id

def get_args():
    parser = argparse.ArgumentParser(description="Vault GCP Identity & Engine Manager")
    parser.add_argument("--timeout", type=int, default=90, help="API HTTP timeout in seconds")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. INFO
    p_info = subparsers.add_parser("info", help="Introspect the current GCP session/token")
    p_info.add_argument("token", nargs="?", default="", help="Optional token string (defaults to env var)")

    # 2. EXEC
    p_exec = subparsers.add_parser("exec", help="Run a command with JIT GCP credentials")
    p_exec.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>, e.g. sandbox-dev)")
    p_exec.add_argument("roleset", nargs="?", default="terraform-runner", help="Roleset name (default: terraform-runner)")
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, help="The command to execute (prefix with '--')")

    # 3. GET-TOKEN (Print a raw JIT token for scripting/exports)
    p_token = subparsers.add_parser("get-token", help="Print a JIT GCP OAuth token for a roleset")
    p_token.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_token.add_argument("roleset", help="Roleset name")

    # 4. ENGINE (Bootstrapping the Secrets Engine)
    p_engine = subparsers.add_parser("engine", help="Manage Vault GCP Secrets Engines (Broker Setup)")
    p_engine.add_argument("action", choices=["create", "delete", "list", "read", "info", "update"])
    p_engine.add_argument("mount_name", nargs="?", default="", help="Mount name (Vault mount point: gcp/<mount_name>, e.g. sandbox-dev)")
    p_engine.add_argument("--project", dest="sa_project", default="", help="GCP Project ID where the Broker SA lives (defaults to <mount_name>)")
    p_engine.add_argument("--sa-name", default="vault-gcp-broker", help="Custom name for the Broker SA (defaults to vault-gcp-broker)")
    p_engine.add_argument("--folder", help="SCOPE: Target a Folder ID (scopes Broker SA to the folder level)")
    p_engine.add_argument("--project-only", action="store_true", help="SCOPE: Strict least-privilege (scopes Broker SA only locally to its project)")
    p_engine.add_argument("--billing-accounts", help="Optional: Comma-separated list of Billing Account IDs (requires Billing Admin permissions)")
    p_engine.add_argument("--organization", help="Optional Organization ID (Required if using Folder Display Names)")
    p_engine.add_argument("--ttl", help="Update default lease TTL (e.g., '1h')")

    # 4. ROLESET
    p_role = subparsers.add_parser("role", help="Manage GCP rolesets (team service accounts)")
    p_role.add_argument("action", choices=["create", "update", "read", "delete", "list", "info"], help="Action to perform")
    p_role.add_argument("mount_name", nargs="?", default="", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_role.add_argument("roleset_name", nargs="?", default="", help="Name of the roleset (max 14 chars)")
    p_role.add_argument("--project", dest="target_project", default="", help="The GCP Project ID the roleset binds to (required for create/update)")
    p_role.add_argument("--roles", default="roles/editor", help="Comma-separated roles (for simple create)")
    p_role.add_argument("--bindings", help="Path to YAML/HCL bindings file (for advanced/cross-project)")
    p_role.add_argument("--folder", help="Target a Folder ID instead of the Project (e.g., 123456789)")

    # 5. CLEANUP (New Teardown)
    p_cleanup = subparsers.add_parser("cleanup", help="Revoke Vault's GCP access and delete the broker SA")
    p_cleanup.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_cleanup.add_argument("--project", dest="sa_project", default="", help="The GCP Project ID where the Vault Broker SA lives (defaults to <mount_name>)")
    p_cleanup.add_argument("--folder-id", help="Optional: The GCP Folder ID where Vault's permissions were scoped")

    # 6. GKE CREDENTIALS (Zero-Dependency Kubeconfig)
    p_gke = subparsers.add_parser("get-gke-credentials", help="Fetch GKE cluster credentials via REST API (No gcloud required)")
    p_gke.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_gke.add_argument("location", help="GCP Location (e.g., us-central1)")
    p_gke.add_argument("cluster", help="GKE Cluster Name")
    p_gke.add_argument("--project", dest="target_project", default="", help="GCP Project ID hosting the cluster (defaults to <mount_name>)")
    p_gke.add_argument("--roleset", default="gke-admin", help="The Vault GCP Roleset (suggested: gke-admin for bootstrapping)")

    # 7. LEASES (Management)
    p_leases = subparsers.add_parser("leases", help="Manage dynamic GCP OAuth tokens and Service Account keys")
    leases_subs = p_leases.add_subparsers(dest="action", required=True)
    p_leases_list = leases_subs.add_parser("list", help="List active GCP leases")
    p_leases_list.add_argument("mount_name", nargs="?", default="", help="Mount name (leave blank to search all gcp/* mounts)")
    p_leases_revoke = leases_subs.add_parser("revoke", help="Revoke GCP leases")
    p_leases_revoke.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_leases_revoke.add_argument("--id", help="Revoke a specific lease ID")
    p_leases_revoke.add_argument("--force", action="store_true", help="Force wipe all leases under this project")

    # 8. SANDBOX (Leasable Pool of Pre-Provisioned Projects, No gcloud Required)
    p_sandbox = subparsers.add_parser("sandbox", help="Lease/release projects from a pre-provisioned sandbox pool (no gcloud required)")
    sandbox_subs = p_sandbox.add_subparsers(dest="action", required=True)

    p_sbox_lease = sandbox_subs.add_parser("lease", help="Lease the first free pool project for a fixed TTL")
    p_sbox_lease.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_sbox_lease.add_argument("roleset", help="Roleset name with 'roles/editor' on the sandbox folder")
    p_sbox_lease.add_argument("--folder", required=True, help="Numeric sandbox folder ID (the pool projects live here)")
    p_sbox_lease.add_argument("--owner", required=True, help="Lease owner (email or username) recorded in the 'owner' label")
    p_sbox_lease.add_argument("--ttl", type=int, default=14, help="Lease length in days (default: 14)")
    p_sbox_lease.add_argument("--purpose", default="sandbox", help="Short purpose slug used in the display name (default: sandbox)")
    p_sbox_lease.add_argument("--services", default="", help="Comma-separated API services to enable on the leased project")
    p_sbox_lease.add_argument("--pool", default="", help="Force a specific pool member by project ID (default: first free)")

    p_sbox_release = sandbox_subs.add_parser("release", help="Disable all services and mark a leased project 'disabled' (kept until 'reset')")
    p_sbox_release.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_sbox_release.add_argument("roleset", help="Roleset name with editor rights on the pool")
    p_sbox_release.add_argument("project", help="Pool project ID to release")

    p_sbox_reset = sandbox_subs.add_parser("reset", help="Mark a 'disabled' pool project free again after its resources were torn down")
    p_sbox_reset.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_sbox_reset.add_argument("roleset", help="Roleset name with editor rights on the pool")
    p_sbox_reset.add_argument("project", help="Pool project ID to reset")

    p_sbox_list = sandbox_subs.add_parser("list", help="List pool projects and their lease state")
    p_sbox_list.add_argument("mount_name", help="Mount name (Vault mount point: gcp/<mount_name>)")
    p_sbox_list.add_argument("roleset", help="Roleset name with read rights on the pool")
    p_sbox_list.add_argument("--folder", required=True, help="Numeric sandbox folder ID (the pool projects live here)")
    p_sbox_list.add_argument("--sweep", action="store_true", help="Auto-release (mark 'disabled') any leases past their TTL")

    return parser.parse_args()

def main():
    args = get_args()
    vault = HashiVault(timeout=args.timeout)
    if not vault.ensure_valid_token(interactive=False):
        sys.exit(1)

    cmd = args.command

    # -------------------------------------------------------------------------
    # 1. INFO
    # -------------------------------------------------------------------------
    if cmd == "info":
        token = args.token or os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN")
        if not token:
            print("❌ Error: No token provided and $GOOGLE_OAUTH_ACCESS_TOKEN is not set.", file=sys.stderr)
            sys.exit(1)

        print("🔍 Introspecting GCP Token...", file=sys.stderr)
        metadata = vault.get_gcp_token_info(token)
        if metadata and "expires_in" in metadata:
            email = metadata.get("email", "Vault Managed Account (Scope hidden)")
            expires_in = int(metadata.get("expires_in", 3600))
            print(f"👤 Authenticated as : {email}")
            print(f"⏳ Time Remaining  : {expires_in // 60} minutes ({expires_in}s)")
            if "scope" in metadata: print(f"🌐 Granted Scopes  : {metadata['scope']}")
            sys.exit(0)
        else:
            print(f"⚠️ Token validation failed: {metadata.get('error', metadata)}", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 2. EXEC
    # -------------------------------------------------------------------------
    elif cmd == "exec":
        mount_point = f"gcp/{args.mount_name}"
        command_list = args.exec_cmd
        if command_list and command_list[0] == "--":
            command_list = command_list[1:]

        if not command_list:
            print("❌ Error: No command provided to execute.", file=sys.stderr)
            sys.exit(1)

        print(f"🔒 Fetching secure token for '{args.roleset}' from '{mount_point}'...", file=sys.stderr)
        token = vault.get_gcp_token(roleset_name=args.roleset, mount_point=mount_point)
        if not token: sys.exit(1)

        os.environ["GOOGLE_OAUTH_ACCESS_TOKEN"] = token
        os.environ["CLOUDSDK_AUTH_ACCESS_TOKEN"] = token
        print(f"🚀 Executing: {' '.join(command_list)}\n" + "-"*40, file=sys.stderr)
        try:
            sys.exit(subprocess.run(command_list, env=os.environ).returncode)
        except FileNotFoundError:
            print(f"\n❌ Error: Command not found: {command_list[0]}", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 3. GET-TOKEN
    # -------------------------------------------------------------------------
    elif cmd == "get-token":
        mount_point = f"gcp/{args.mount_name}"
        token = vault.get_gcp_token(roleset_name=args.roleset, mount_point=mount_point)
        if not token: sys.exit(1)
        print(token)
        sys.exit(0)

    # -------------------------------------------------------------------------
    # 4. ENGINE MANAGEMENT (Unified Broker Setup)
    # -------------------------------------------------------------------------
    elif cmd == "engine":
        action = args.action

        if action == "list":
            engines = vault.list_engines(backend_type="gcp") or []
            if not engines:
                print("ℹ️ No GCP secrets engines currently mounted.")
            else:
                for e in sorted(engines):
                    print(f"  ├─ {e.strip('/')}/")
            sys.exit(0)

        mount_name = args.mount_name
        if not mount_name:
            print("❌ Error: Mount name required.", file=sys.stderr)
            sys.exit(1)

        sa_project = args.sa_project or mount_name
        sa_name = args.sa_name # Unified flag!
        sa_email = f"{sa_name}@{sa_project}.iam.gserviceaccount.com"
        mount_point = f"gcp/{mount_name}"

        if action == "delete":
            print(f"🧹 Tearing down Vault engine at '{mount_point}/'...")
            vault.teardown_gcp_engine(mount_point=mount_point)
            sys.exit(0)

        if action in ["read", "info"]:
            config = vault.read_gcp_engine_config(mount_point)
            if not config:
                print(f"❌ Engine config not found at '{mount_point}/'.", file=sys.stderr)
                sys.exit(1)
            if config.get('credentials'):
                config['credentials'] = "[REDACTED — Broker SA private key]"
            if action == "read":
                print(json.dumps(config, indent=2))
            else:
                print(f"🏛️  GCP Engine: {mount_point}/")
                for k, v in config.items():
                    print(f"  ├─ {k}: {v}")
            sys.exit(0)

        if action in ["create", "update"]:
            print(f"🚀 Initializing GCP Broker Engine at '{mount_point}'...")
            print(f"  ├─ Logical Path: {mount_point}/")
            print(f"  ├─ Broker SA home: {sa_project}")

            # (Enable Necessary Services...)
            print(f"  ├─ Enabling necessary GCP Services...")
            run_gcloud(["gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "iamcredentials.googleapis.com", "--project", sa_project], retries=2)

            # (Create the Service Account...)
            print(f"  ├─ Creating Service Account '{sa_name}'...")
            run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, "--display-name=Vault GCP Broker", "--project", sa_project], ignore_errors=True)

            # Base roles Vault ALWAYS needs on its Home Project to spawn temporary SAs
            base_roles = [
                "roles/iam.serviceAccountAdmin",
                "roles/iam.serviceAccountKeyAdmin",
                "roles/resourcemanager.projectIamAdmin"
            ]

            # 🌟 Always grant Home Base permissions on the host project!
            print(f"  ├─ Granting SA Management on home project: {sa_project}...")
            for role in base_roles:
                run_gcloud(["gcloud", "projects", "add-iam-policy-binding", sa_project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

            # 🌟 STEP 3: Smart Scoping based on arguments
            if args.folder:
                print(f"  ├─ SCOPE: Scoping Vault's Jurisdiction to FOLDER: {args.folder}...")
                resolved_folder_id = resolve_gcp_folder_id(args.folder, args.organization)

                # Notice base_roles are removed from here! Only Jurisdiction roles applied to the folder.
                folder_roles = [
                    "roles/resourcemanager.projectIamAdmin",
                    "roles/resourcemanager.folderIamAdmin",
                    "roles/resourcemanager.projectCreator"
                ]
                for role in folder_roles:
                    run_gcloud(["gcloud", "resource-manager", "folders", "add-iam-policy-binding", resolved_folder_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

            elif args.project_only:
                print(f"  ├─ SCOPE: Sandboxing Vault strictly to PROJECT: {sa_project}...")
                project_roles = ["roles/resourcemanager.projectIamAdmin"]
                for role in project_roles:
                    run_gcloud(["gcloud", "projects", "add-iam-policy-binding", sa_project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)
            else:
                print("\n❌ SCOPE REQUIRED: Must provide either '--folder <id>' or '--project-only'.")
                sys.exit(1)

            # 🌟 STEP 4: THE BILLING FIX 🌟
            if getattr(args, 'billing_accounts', None):
                print(f"  ├─ 💳 Assigning Billing Admin role to Vault Broker SA...")
                billing_ids = [b.strip() for b in args.billing_accounts.split(",")]
                for billing_id in billing_ids:
                    # Note: gcloud beta is required for billing account IAM
                    run_gcloud([
                        "gcloud", "beta", "billing", "accounts", "add-iam-policy-binding", billing_id,
                        f"--member=serviceAccount:{sa_email}",
                        "--role=roles/billing.admin"
                    ], ignore_errors=True)
                    print(f"  │  ├─ Granted access to Billing Account: {billing_id}")

            # (Generate JSON Key and write to Vault...)
            print("  ├─ 🔑 Generating JSON Key and updating Vault...")
            creds_json = run_gcloud(["gcloud", "iam", "service-accounts", "keys", "create", "-", f"--iam-account={sa_email}", "--project", sa_project], capture_json=True)

            if vault.setup_gcp_engine(creds_json=creds_json, mount_point=mount_point):
                print(f"🎉 Vault GCP Broker Engine configured successfully at '{mount_point}/'!")
                if getattr(args, 'ttl', None):
                    vault.update_gcp_engine_config(mount_point, ttl=args.ttl)
            else:
                print("❌ Failed to configure Vault engine.", file=sys.stderr)
                sys.exit(1)

    # -------------------------------------------------------------------------
    # 4. ROLESET
    # -------------------------------------------------------------------------
    elif cmd == "role":
        action = args.action
        mount_name = args.mount_name
        target_project = args.target_project
        roleset_name = args.roleset_name
        mount_point = f"gcp/{mount_name}" if mount_name else None

        if action == "list":
            if mount_name:
                engines_to_check = [mount_point]
            else:
                print("🔍 Searching across all active GCP engines...")
                engines = vault.list_engines(backend_type="gcp") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("gcp/")]

            if not engines_to_check:
                print("ℹ️ No GCP secrets engines currently mounted.")
                sys.exit(0)

            found_any = False
            for mount in engines_to_check:
                all_roles = []
                
                # Fetch Dynamic Rolesets
                dynamic_roles = vault.list_gcp_rolesets(mount_point=mount)
                if dynamic_roles:
                    all_roles.extend(dynamic_roles)
                
                # Fetch Static Accounts
                try:
                    res_static = vault._get_client().list(f"{mount}/static-account")
                    if res_static and 'data' in res_static and 'keys' in res_static['data']:
                        for key in res_static['data']['keys']:
                            all_roles.append(f"{key} (Static Account)")
                except Exception:
                    pass

                if all_roles:
                    found_any = True
                    print(f"\n👥 Active Rolesets at '{mount}/':")
                    # Sort alphabetically so static and dynamic are cleanly mixed
                    for r in sorted(all_roles):
                        print(f"  ├─ {r}")

            if not found_any:
                print("\nℹ️ No rolesets found.")
            sys.exit(0)

        if not mount_point or not roleset_name:
            print("❌ Error: Mount name and roleset_name are required.", file=sys.stderr)
            sys.exit(1)

        if action in ["info", "read"]:
            # 1. Try to read as a Dynamic Roleset first
            data = None
            is_static = False
            try:
                res = vault._get_client().read(f"{mount_point}/roleset/{roleset_name}")
                if res and 'data' in res:
                    data = res['data']
            except Exception:
                pass

            # 2. If not found, try reading as a Static Account
            if not data:
                try:
                    res = vault._get_client().read(f"{mount_point}/static-account/{roleset_name}")
                    if res and 'data' in res:
                        data = res['data']
                        is_static = True
                except Exception:
                    pass

            if not data:
                print(f"❌ Roleset or Static Account '{roleset_name}' not found.")

            # 🌟 RAW JSON OUTPUT (For automation/debugging)
            elif action == "read":
                print(json.dumps(data, indent=2))

            # 🌟 USER-FRIENDLY OUTPUT (Human readable info)
            elif action == "info":
                print(f"👥 GCP {'Static Account' if is_static else 'Roleset'}: {roleset_name}")
                print(f"  ├─ Engine      : {mount_point}/")
                print(f"  ├─ Secret Type : {data.get('secret_type', 'Unknown')}")
                if not is_static:
                    print(f"  ├─ Project     : {data.get('project', 'Unknown')}")

                sa_email = data.get('service_account_email', 'Unknown')
                print(f"  ├─ SA Email    : {sa_email}")

                scopes = data.get('token_scopes', [])
                print(f"  ├─ Scopes      : {', '.join(scopes) if scopes else 'None'}")

                if is_static:
                    print(f"  ├─ Bindings    : 🔍 Scanning GCP for active IAM roles (this may take a moment)...")

                    scan_project = target_project or mount_name
                    bindings_found = []

                    try:
                        # Scan 1: Project Level
                        proj_out = subprocess.check_output(["gcloud", "projects", "get-iam-policy", scan_project, "--format=json"], stderr=subprocess.DEVNULL)
                        for b in json.loads(proj_out).get('bindings', []):
                            if any(sa_email in m for m in b.get('members', [])):
                                bindings_found.append(f"Project ({scan_project}) -> {b.get('role')}")

                        # Scan 2: Billing Accounts
                        ba_out = subprocess.check_output(["gcloud", "beta", "billing", "accounts", "list", "--format=value(name)"], stderr=subprocess.DEVNULL)
                        for ba in ba_out.decode('utf-8').strip().split():
                            if not ba: continue
                            ba_id = ba.split('/')[-1]
                            try:
                                ba_pol = subprocess.check_output(["gcloud", "beta", "billing", "accounts", "get-iam-policy", ba_id, "--format=json"], stderr=subprocess.DEVNULL)
                                for b in json.loads(ba_pol).get('bindings', []):
                                    if any(sa_email in m for m in b.get('members', [])):
                                        bindings_found.append(f"Billing ({ba_id}) -> {b.get('role')}")
                            except Exception:
                                pass

                        # Scan 3: Folders via Cloud Asset Inventory (Catches everything else)
                        org_out = subprocess.check_output(["gcloud", "projects", "get-ancestors", scan_project, "--format=json"], stderr=subprocess.DEVNULL)
                        org_id = next((a['id'] for a in json.loads(org_out) if a.get('type') == 'organization'), None)

                        if org_id:
                            try:
                                asset_out = subprocess.check_output([
                                    "gcloud", "asset", "search-all-iam-policies",
                                    f"--scope=organizations/{org_id}",
                                    f"--query=policy:{sa_email}",
                                    "--format=json"
                                ], stderr=subprocess.PIPE)

                                asset_data = json.loads(asset_out) if asset_out.strip() else []

                                for p in asset_data:
                                    res_name = p.get('resource', '').split('/')[-1]
                                    res_type = p.get('resource', '').split('/')[-2] if '/' in p.get('resource', '') else 'Folder/Org'

                                    for b in p.get('policy', {}).get('bindings', []):
                                        if any(sa_email in m for m in b.get('members', [])):
                                            entry = f"{res_type.capitalize()} ({res_name}) -> {b.get('role')}"
                                            # Prevent duplicating the exact same resource + role combination
                                            is_dupe = False
                                            for existing in bindings_found:
                                                if res_name in existing and b.get('role') in existing:
                                                    is_dupe = True
                                                    break
                                            if not is_dupe:
                                                bindings_found.append(entry)
                            except subprocess.CalledProcessError as e:
                                err_msg = e.stderr.decode('utf-8').strip().split('\n')[0]
                                bindings_found.append(f"⚠️ Folder scan failed: Asset API error or missing Org permissions -> {err_msg}")
                            except Exception as e:
                                bindings_found.append(f"⚠️ Folder scan failed: {str(e)}")
                        else:
                            bindings_found.append("⚠️ Folder scan skipped: Could not resolve Organization ID.")

                    except Exception as e:
                        bindings_found.append(f"⚠️ Partial results (Error querying GCP: {e})")

                    # Print out the discovered bindings
                    if bindings_found:
                        for bf in bindings_found:
                            print(f"  │  ├─ {bf}")
                    else:
                        print(f"  │  ├─ ⚠️ No active bindings found or permission denied to read them.")

                else:
                    bindings = data.get('bindings', {})
                    if bindings:
                        print(f"  ├─ Bindings    :")
                        print(f"  │  ├─ {bindings}") # Customize this to match your existing print logic

        elif action == "delete":
            # 1. Check if it's a Static Account first
            is_static = False
            sa_email = None
            try:
                res = vault._get_client().read(f"{mount_point}/static-account/{roleset_name}")
                if res and 'data' in res:
                    is_static = True
                    sa_email = res['data'].get('service_account_email')
            except Exception:
                pass

            if is_static:
                print(f"🗑️ Deleting Static Account '{roleset_name}'...")

                # Delete the Vault mapping
                try:
                    vault._get_client().delete(f"{mount_point}/static-account/{roleset_name}")
                    print(f"  ├─ Removed static-account mapping from Vault.")
                except Exception as e:
                    print(f"  ├─ ⚠️ Failed to remove from Vault: {e}")

                # Tear down the permanent Service Account in GCP
                if sa_email:
                    print(f"  ├─ Deleting permanent Service Account '{sa_email}' from GCP...")
                    run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", target_project or mount_name, "--quiet"], ignore_errors=True)

                print(f"✅ Successfully deleted static account '{roleset_name}'.")

            else:
                # 2. Fallback to normal Dynamic Roleset deletion
                print(f"🗑️ Deleting Dynamic Roleset '{roleset_name}'...")
                try:
                    vault._get_client().delete(f"{mount_point}/roleset/{roleset_name}")
                    print(f"✅ Successfully deleted roleset '{roleset_name}'.")
                except Exception as e:
                    print(f"❌ Error deleting roleset '{roleset_name}': {e}", file=sys.stderr)

        elif action in ["create", "update"]:
            if len(roleset_name) > 14:
                print(f"❌ Error: Roleset name '{roleset_name}' exceeds the 14 character Vault limit.", file=sys.stderr)
                sys.exit(1)

            bindings_hcl = ""
            requires_static_workaround = False
            yaml_config = {}

            if args.bindings:
                try:
                    with open(args.bindings, 'r') as f:
                        if args.bindings.endswith(('.yaml', '.yml')):
                            yaml_config = yaml.safe_load(f) or {}

                            # YAML is the source of truth; CLI flags act as explicit overrides
                            target_project = args.target_project or yaml_config.get('project') or ''

                            # 🌟 SMART DETECTION: Does this need Billing?
                            if 'billingAccounts' in yaml_config:
                                requires_static_workaround = True

                            resource_maps = {
                                'projects': ('cloudresourcemanager.googleapis.com', 'projects'),
                                'folders': ('cloudresourcemanager.googleapis.com', 'folders'),
                                'organizations': ('cloudresourcemanager.googleapis.com', 'organizations')
                            }

                            # We only build HCL if we are NOT doing the static workaround
                            if not requires_static_workaround:
                                for res_type, (api_domain, uri_path) in resource_maps.items():
                                    for item in yaml_config.get(res_type, []):
                                        target_name = str(item['name'])

                                        if res_type == 'projects' and target_name != target_project:
                                            # No cross-project patching: the Broker SA's rights come from
                                            # folder-level inheritance (it can create projects and assign
                                            # IAM permissions inside the managed folder). If the target is
                                            # outside that folder, Vault will correctly 403 (blast radius).
                                            print(f"  ℹ️ Binding to project '{target_name}' (different from SA placement '{target_project}').")
                                            print(f"     The Broker SA must hold folder-inherited IAM rights over this project.")

                                        roles_str = ", ".join([f'"{r.strip()}"' for r in item.get('roles', [])])
                                        bindings_hcl += f'\nresource "//{api_domain}/{uri_path}/{target_name}" {{\n  roles = [{roles_str}]\n}}\n'
                            print(f"📄 Parsed YAML bindings (project: {target_project or 'from --project'}).")
                        else:
                            bindings_hcl = f.read()
                except Exception as e:
                    print(f"❌ Error reading bindings: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                roles_list = [f'"{r.strip()}"' for r in args.roles.split(",")]
                if args.folder:
                    resource_uri = f"//cloudresourcemanager.googleapis.com/folders/{args.folder}"
                    print(f"📁 Binding permissions at the FOLDER level (Folder ID: {args.folder})")
                else:
                    resource_uri = f"//cloudresourcemanager.googleapis.com/projects/{target_project}"
                    print(f"🏗️ Binding permissions at the PROJECT level ({target_project})")
                bindings_hcl = f'\nresource "{resource_uri}" {{\n  roles = [{", ".join(roles_list)}]\n}}\n'

            if not target_project:
                print("❌ Error: No target GCP project specified. Set 'project' in the YAML or pass '--project <target>'.", file=sys.stderr)
                sys.exit(1)

            # 🌟 ROUTING LOGIC 🌟
            if requires_static_workaround:
                print(f"💡 Billing permissions detected. Routing via intelligent static-account engine...")

                # GCP SA Names have a strict 30 character limit.
                sa_name = f"vlt-{roleset_name}"[:30].rstrip('-')
                sa_email = f"{sa_name}@{target_project}.iam.gserviceaccount.com"

                print(f"  ├─ Creating permanent Service Account '{sa_name}' in GCP...")
                run_gcloud(["gcloud", "iam", "service-accounts", "create", sa_name, f"--display-name=Vault Managed: {roleset_name}", "--project", target_project], ignore_errors=True, quiet=True)

                print(f"  ├─ Applying IAM Bindings natively via gcloud...")
                for item in yaml_config.get('folders', []):
                    for role in item.get('roles', []):
                        run_gcloud(["gcloud", "resource-manager", "folders", "add-iam-policy-binding", str(item['name']), f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

                for item in yaml_config.get('projects', []):
                    for role in item.get('roles', []):
                        run_gcloud(["gcloud", "projects", "add-iam-policy-binding", str(item['name']), f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

                for item in yaml_config.get('billingAccounts', []):
                    for role in item.get('roles', []):
                        run_gcloud(["gcloud", "beta", "billing", "accounts", "add-iam-policy-binding", str(item['name']), f"--member=serviceAccount:{sa_email}", f"--role={role}"], quiet=True)

                print(f"  ├─ Registering with Vault as a managed static account...")
                try:
                    vault._get_client().write(
                        f"{mount_point}/static-account/{roleset_name}",
                        service_account_email=sa_email,
                        secret_type="access_token",
                        token_scopes=["https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email"]
                    )
                    print(f"✅ Successfully created roleset '{roleset_name}'!")
                except Exception as e:
                    print(f"❌ Error registering static account in Vault: {e}", file=sys.stderr)
                    sys.exit(1)

            else:
                # 🌟 NORMAL VAULT ROLESET CREATION 🌟
                print(f"🚀 Creating Dynamic Roleset '{roleset_name}'...")
                vault.create_gcp_roleset(name=roleset_name, project_id=target_project, bindings_hcl=bindings_hcl, mount_point=mount_point)


    # -------------------------------------------------------------------------
    # 5. CLEANUP
    # -------------------------------------------------------------------------
    elif cmd == "cleanup":
        mount_name = args.mount_name
        sa_project = args.sa_project or mount_name
        folder_id = args.folder_id
        sa_name = "vault-gcp-broker"
        sa_email = f"{sa_name}@{sa_project}.iam.gserviceaccount.com"
        mount_point = f"gcp/{mount_name}"

        print(f"🧹 Starting Vault GCP Broker cleanup for mount '{mount_name}'...")

        base_roles = [
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountKeyAdmin"
        ]

        if folder_id:
            print(f"  ├─ 📁 Removing Vault's access from FOLDER: {folder_id}...")
            folder_roles = base_roles + ["roles/resourcemanager.projectIamAdmin", "roles/resourcemanager.folderIamAdmin", "roles/resourcemanager.projectCreator"]
            for role in folder_roles:
                run_gcloud(["gcloud", "resource-manager", "folders", "remove-iam-policy-binding", folder_id, f"--member=serviceAccount:{sa_email}", f"--role={role}"], ignore_errors=True, quiet=True)
        else:
            print(f"  ├─ 📄 Removing Vault's access from PROJECT: {sa_project}...")
            project_roles = base_roles + ["roles/resourcemanager.projectIamAdmin"]
            for role in project_roles:
                run_gcloud(["gcloud", "projects", "remove-iam-policy-binding", sa_project, f"--member=serviceAccount:{sa_email}", f"--role={role}"], ignore_errors=True, quiet=True)

        print(f"  ├─ 🗑️ Deleting Service Account '{sa_name}'...")
        run_gcloud(["gcloud", "iam", "service-accounts", "delete", sa_email, "--project", sa_project, "--quiet"], ignore_errors=True)

        print(f"  ├─ 🧹 Tearing down Vault engine at '{mount_point}/'...")
        vault.teardown_gcp_engine(mount_point=mount_point)

        print("✅ Cleanup complete. Vault's GCP access has been fully revoked.")


    # -------------------------------------------------------------------------
    # 6. GKE CREDENTIALS (Zero-Dependency API Call)
    # -------------------------------------------------------------------------
    elif cmd == "get-gke-credentials":
        mount_name = args.mount_name
        location = args.location
        cluster = args.cluster
        mount_point = f"gcp/{mount_name}"

        print(f"🔒 Fetching ephemeral GCP token for roleset '{args.roleset}'...", file=sys.stderr)
        gcp_token = vault.get_gcp_token(roleset_name=args.roleset, mount_point=mount_point)
        if not gcp_token:
            sys.exit(1)

        print(f"🌐 Querying Google Container REST API for cluster details...", file=sys.stderr)
        import urllib.request
        import urllib.error
        import ssl

        url = f"https://container.googleapis.com/v1/projects/{args.target_project or mount_name}/locations/{location}/clusters/{cluster}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {gcp_token}"})

        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, context=ctx) as response:
                data = json.loads(response.read().decode())

            endpoint = data.get("endpoint")
            ca_cert = data.get("masterAuth", {}).get("clusterCaCertificate")

            if not endpoint or not ca_cert:
                print("❌ Error: Cluster endpoint or CA cert not found in API response.", file=sys.stderr)
                sys.exit(1)

            kubeconfig = f"""apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: {ca_cert}
    server: https://{endpoint}
  name: {cluster}
contexts:
- context:
    cluster: {cluster}
    user: {cluster}-user
  name: {cluster}-context
current-context: {cluster}-context
users:
- name: {cluster}-user
  user:
    token: {gcp_token}
"""
            kube_dir = os.path.expanduser("~/.kube")
            os.makedirs(kube_dir, exist_ok=True)
            kube_file = os.path.join(kube_dir, f"config-gke-{cluster}")

            with open(kube_file, "w") as f:
                f.write(kubeconfig)

            print(f"✅ GKE Credentials successfully generated! (No gcloud needed)")
            print(f"👉 1. Activate it  : export KUBECONFIG={kube_file}")
            print(f"👉 2. Test it      : kubectl get nodes")
            print(f"👉 3. Mount to Vault: vault-k8s engine create {cluster}")

        except urllib.error.HTTPError as e:
            error_body = e.read().decode()
            print(f"❌ GCP API Error ({e.code}): {error_body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error communicating with GKE API: {e}", file=sys.stderr)
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 8. SANDBOX (Ephemeral Project Lifecycle, No gcloud Required)
    # -------------------------------------------------------------------------
    elif cmd == "sandbox":
        mount_point = f"gcp/{args.mount_name}"
        print(f"🔒 Fetching ephemeral GCP token for roleset '{args.roleset}'...", file=sys.stderr)
        gcp_token = vault.get_gcp_token(roleset_name=args.roleset, mount_point=mount_point)
        if not gcp_token:
            sys.exit(1)

        if args.action == "lease":
            if not args.folder.strip().isdigit():
                print("❌ Error: --folder must be a numeric Folder ID.", file=sys.stderr)
                sys.exit(1)

            pool = sandbox_pool(gcp_token, args.folder.strip())
            if not pool:
                print("❌ Error: no pool projects found under the folder. Did Prereq B provision them?", file=sys.stderr)
                sys.exit(1)

            def project_state(p):
                return (p.get("labels") or {}).get("state", "free")

            if args.pool:
                target = next((p for p in pool if p.get("projectId") == args.pool), None)
                if not target:
                    print(f"❌ Error: '{args.pool}' is not an ACTIVE project under the folder.", file=sys.stderr)
                    sys.exit(1)
            else:
                target = next((p for p in pool if project_state(p) == "free"), None)
                if not target:
                    print("❌ Error: pool exhausted — no 'free' member. Check 'sandbox list' (released ones need 'sandbox reset').", file=sys.stderr)
                    sys.exit(1)

            project_id = target["projectId"]
            lease_until = sandbox_expire_dt(args.ttl)
            display_name = sandbox_display_name(project_id, "leased", args.owner, args.purpose)
            labels = {
                "state": "leased",
                "owner": args.owner,
                "purpose": args.purpose,
                "lease-until": lease_until,
            }
            print(f"⚙️  Leasing '{project_id}' to {args.owner} until {lease_until} (display name: '{display_name}')...", file=sys.stderr)
            sandbox_patch_project(gcp_token, project_id, display_name=display_name, labels=labels)
            print(f"✅ Leased '{project_id}'.")

            if args.services:
                service_ids = [s.strip() for s in args.services.split(",") if s.strip()]
                print(f"⚙️  Enabling services: {', '.join(service_ids)}...", file=sys.stderr)
                sandbox_enable_services(gcp_token, project_id, service_ids)
                print(f"✅ Services enabled on '{project_id}'.")

            print(f"👉 Operate: vault-gcp exec {args.mount_name} {args.roleset} -- <cmd>", file=sys.stderr)
            print(f"👉 Release when done: vault-gcp sandbox release {args.mount_name} {args.roleset} {project_id}", file=sys.stderr)

        elif args.action == "release":
            project = sandbox_get_project(gcp_token, args.project)
            labels = project.get("labels") or {}
            state = labels.get("state", "free")
            if state not in ("leased", "disabled"):
                print(f"⚠️  Project '{args.project}' is not leased (state='{state}'); nothing to release.", file=sys.stderr)
                sys.exit(1)

            print(f"🗑️  Disabling all services on '{args.project}'...", file=sys.stderr)
            disabled = sandbox_disable_all_services(gcp_token, args.project)
            print(f"✅ Disabled {disabled} service(s).", file=sys.stderr)

            labels["state"] = "disabled"
            labels.pop("lease-until", None)
            display_name = sandbox_display_name(args.project, "disabled")
            sandbox_patch_project(gcp_token, args.project, display_name=display_name, labels=labels)
            print(f"✅ Project '{args.project}' marked 'disabled'. It stays RESERVED.")
            print(f"👉 Tear down resources (terraform destroy), then: vault-gcp sandbox reset {args.mount_name} {args.roleset} {args.project}")

        elif args.action == "reset":
            project = sandbox_get_project(gcp_token, args.project)
            labels = project.get("labels") or {}
            if labels.get("state") != "disabled":
                print(f"⚠️  Project '{args.project}' is not 'disabled' (state='{labels.get('state', 'free')}'); nothing to reset.", file=sys.stderr)
                sys.exit(1)

            for key in ("owner", "purpose", "lease-until"):
                labels.pop(key, None)
            labels["state"] = "free"
            display_name = sandbox_display_name(args.project, "free")
            sandbox_patch_project(gcp_token, args.project, display_name=display_name, labels=labels)
            print(f"✅ Project '{args.project}' returned to the pool (state=free).")

        elif args.action == "list":
            if not args.folder.strip().isdigit():
                print("❌ Error: --folder must be a numeric Folder ID.", file=sys.stderr)
                sys.exit(1)

            pool = sandbox_pool(gcp_token, args.folder.strip())
            if not pool:
                print("ℹ️ No pool projects found under the folder.", file=sys.stderr)
                sys.exit(0)

            now = datetime.now(timezone.utc)

            def row(p):
                labels = p.get("labels") or {}
                state = labels.get("state", "free")
                lease_until = None
                if labels.get("lease-until"):
                    dt = sandbox_parse_dt(labels["lease-until"])
                    lease_until = dt if dt else labels["lease-until"]
                expired = state == "leased" and isinstance(lease_until, datetime) and lease_until < now
                return (p.get("projectId"), state, labels.get("owner", ""), str(lease_until)[:19], p.get("name", ""), expired)

            rows = [row(p) for p in pool]

            if args.sweep:
                for project_id, state, _, until, _, expired in rows:
                    if not expired:
                        continue
                    print(f"⏰ Lease expired on '{project_id}' ({until}) — releasing...", file=sys.stderr)
                    labels = dict((sandbox_get_project(gcp_token, project_id).get("labels") or {}))
                    disabled = sandbox_disable_all_services(gcp_token, project_id)
                    labels["state"] = "disabled"
                    labels.pop("lease-until", None)
                    sandbox_patch_project(gcp_token, project_id, display_name=sandbox_display_name(project_id, "disabled"), labels=labels)
                    print(f"✅ '{project_id}' released (disabled {disabled} service(s)).", file=sys.stderr)
                pool = sandbox_pool(gcp_token, args.folder.strip())
                rows = [row(p) for p in pool]

            print(f"{'PROJECT':<20} {'STATE':<9} {'OWNER':<22} {'LEASE-UNTIL':<20} NAME")
            print("-" * 100)
            for project_id, state, owner, until, name, expired in sorted(rows):
                flag = " ⚠️ EXPIRED-or-MISSING" if expired else ""
                print(f"{project_id:<20} {state:<9} {str(owner):<22} {str(until or '-'):<20} {name}{flag}")

    # ---------------------------------------------------------------------
    # 7. LEASES
    # ---------------------------------------------------------------------
    elif cmd == "leases":
        action = args.action

        if action == "list":
            if args.mount_name:
                engines_to_check = [f"gcp/{args.mount_name}"]
            else:
                print("🔍 Searching across all active GCP engines...")
                engines = vault.list_engines(backend_type="gcp") or []
                engines_to_check = [e.strip('/') for e in engines if e.startswith("gcp/")]

            if not engines_to_check:
                print("ℹ️ No GCP Engines currently mounted.")
                sys.exit(0)

            found_any = False
            for m in engines_to_check:
                for token_type in ["token/", "key/"]:
                    rolesets = vault.list_leases(f"{m}/{token_type}")
                    if rolesets:
                        for roleset in rolesets:
                            lease_ids = vault.list_leases(f"{m}/{token_type}{roleset}")
                            if lease_ids:
                                if not found_any: print("")
                                print(f"📁 Active Leases in {m}/{token_type}{roleset}:")
                                for lid in lease_ids:
                                    print(f"  ├─ {m}/{token_type}{roleset}{lid}")
                                    found_any = True

            if not found_any:
                print("✅ No active GCP leases found.")

        elif action == "revoke":
            mount_point = f"gcp/{args.mount_name}"

            if getattr(args, "id", None):
                print(f"🗑️ Revoking specific lease '{args.id}'...")
                if vault.revoke_lease(args.id):
                    print("✅ GCP lease successfully revoked.")
            elif getattr(args, "force", False):
                print(f"🔥 Force revoking ALL leases under '{mount_point}/'...")
                if vault.force_revoke_prefix(mount_point):
                    print("✅ All GCP leases forcefully wiped.")
            else:
                print("⚠️ You must provide either '--id <lease_id>' or use '--force' to wipe the engine.")

if __name__ == "__main__":
    main()
