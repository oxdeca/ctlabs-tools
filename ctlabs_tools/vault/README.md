# 🔐 CTLabs Vault & Identity Suite

A dedicated suite of CLI utilities and Python APIs for managing HashiCorp Vault, Zero Standing Privileges (JIT Access) in Google Cloud, and Enterprise Identity.

## 📦 Architecture & Philosophy
This module strictly separates the three pillars of Cloud Security:
1. **Authentication & Policy (`vault-auth`)**: Who are you, and what are you allowed to do?
2. **Cloud Identity (`vault-gcp`)**: Just-In-Time, ephemeral access to cloud infrastructure.
3. **Static Data (`vault-secret`)**: Managing key-value payloads and reading raw Vault APIs.

---

## 💻 CLI Utilities

### 1. Authentication & Session Cache (`vault-login`)
Authenticate to Vault and securely cache a GPG-encrypted session token locally.
```bash
# Log in manually (LDAP/Userpass)
vault-login user my-username -a https://vault.example.com

# Log in as a Machine (AppRole)
vault-login approle my-role-id

# Inspect your active session token and policies
vault-login info

# Securely log out and clear the cache
vault-login clear
```

### 2. Identity & Access Management (`vault-auth`)
Manage users, machine identities, LDAP groups, and ACL policies.
```bash
# Users (LDAP / Userpass)
vault-auth user list                      # Lists all users (smart aggregation)
vault-auth user create alice --method ldap

# Groups (Map LDAP groups to Vault Policies)
vault-auth group create devops --policies "vpc-admin, default"
vault-auth group list

# Machine Identities (AppRole)
vault-auth approle create ci-runner --policies "terraform-deployer"
vault-auth approle read ci-runner         # Get RoleID and SecretID

# Policies (ACLs)
vault-auth policy create vpc-admin --file policies/vpc-admin.hcl
vault-auth policy list
```

### 3. Google Cloud JIT Access (`vault-gcp`)
Bootstrap dynamic secrets engines and execute tools with Zero Standing Privileges.

**🚀 Bootstrap & Rolesets:**
```bash
# Initialize a new GCP Secrets Engine (Zero-Touch IAM setup)
vault-gcp engine create ctlabs-prj-2025101601

# Create a simple roleset
vault-gcp roleset create ctlabs-prj-2025101601 devops --roles "roles/editor"

# Create an advanced roleset using YAML (Auto-patches cross-project IAM for Shared VPCs!)
vault-gcp roleset create ctlabs-prj-2025101601 vpc-admin --bindings vpc-admin.yaml
```

**📄 Example `vpc-admin.yaml`:**
```yaml
projects:
  - name: ctlabs-prj-2025101601
    roles: [ "roles/owner" ]
  - name: shared-vpc-host-project-id
    roles: [ "roles/compute.networkUser" ]
```

**🔒 Just-In-Time Execution (Zero Credentials on Disk):**
*Securely wraps tools by injecting short-lived GCP tokens purely into process memory.*
```bash
# Run a single Terraform command
vault-gcp exec ctlabs-prj-2025101601 devops -- terraform plan

# Open an authenticated subshell
vault-gcp exec ctlabs-prj-2025101601 devops -- bash

# Run an ephemeral, authenticated Docker container
vault-gcp exec ctlabs-prj-2025101601 devops -- \
  docker run --rm -it -e GOOGLE_OAUTH_ACCESS_TOKEN -e CLOUDSDK_AUTH_ACCESS_TOKEN google/cloud-sdk:latest bash
```

### 4. Static Secrets & Data (`vault-secret`)
Manage standard KVv2 data and inspect raw Vault endpoints.
```bash
# Manage KV secrets
vault-secret write kvv2/apps/my-service --data '{"api_key": "123"}'
vault-secret read kvv2/apps/my-service
vault-secret list kvv2/apps
vault-secret search kvv2/apps "api_key"

# Read Raw API endpoints
vault-secret raw identity/oidc/.well-known/keys
```

---

## 🐍 Python API Integration
You can use the `HashiVault` core class directly in any Python script for deep automation.

```python
from ctlabs_tools.vault.core import HashiVault

vault = HashiVault()
if vault.ensure_valid_token():
    token = vault.get_gcp_token("devops", "gcp/my-project")
    print("Obtained JIT token!")
```
