# 🛠️ CTLabs Tools

A comprehensive collection of Python helpers for infrastructure testing with Terraform, Ansible, Policy Checks (ConfTest), and HashiCorp Vault.

## 📦 Installation

Install directly from GitHub using pip:

```bash
# Install latest from main
pip install git+[https://github.com/oxdeca/ctlabs-tools.git](https://github.com/oxdeca/ctlabs-tools.git)

# or from the dev branch
pip install git+[https://github.com/oxdeca/ctlabs-tools.git@dev](https://github.com/oxdeca/ctlabs-tools.git@dev)
```

## 🧩 Importing in your Tests
Once installed, your imports are clean and location-independent:

```python
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest
from ctlabs_tools.pytest.helper import HashiVault, GCPSecretManager, RemoteDesktop
```

---

## 🔐 The Vault Workflow: Identity vs. Data

HashiCorp Vault strictly separates **Who you are** (Identity) from **What you are accessing** (Data). Our toolkit reflects this separation to keep your CI/CD pipelines secure.

1. **`vault-login`**: The human administrator authenticates to Vault.
2. **`vault-secret`**: The administrator stores the actual sensitive data (e.g., a database password) or bootstraps dynamic identity engines (like GCP).
3. **`vault-approle`**: The administrator creates a Machine Identity (AppRole) and a policy that grants it read-only access to that specific path.
4. **CI/CD / Rundeck**: The orchestrator fetches a one-time-use token for the AppRole and injects it into the Pytest environment. Pytest uses this disposable token to read the data and run the infrastructure tests.

---

## 📜 Required Vault Policies for GCP Tokens

To successfully generate and manage GCP tokens, Vault requires specific policies. You can enforce granular, team-based access by restricting which users/AppRoles can generate tokens for which rolesets.

### 1. Team-Based Consumption Policies (The "Runner")
Your developers or automated CI/CD runners only need the `read` capability on the exact roleset path they are authorized to use.

```hcl
# The DevOps Policy: Can only generate tokens for the 'devops' roleset
path "gcp/ctlabs-0815-123abc-05a-03/token/devops" {
  capabilities = ["read"]
}

# The Data Science Policy: Can only generate tokens for the 'data-science' roleset
path "gcp/ctlabs-0815-123abc-05a-03/token/data-science" {
  capabilities = ["read"]
}
```
*If a Data Scientist tries to request the DevOps token, Vault will block them with a 403 Permission Denied error.*

### 2. The Administrator Policy (Engine Manager)
The human or automation configuring the backend needs permissions to mount engines, configure the GCP master credentials, and manage rolesets.

```hcl
# Allow mounting and unmounting the GCP secrets engine
path "sys/mounts/gcp/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Allow checking if an engine is mounted (Used by the 'list' and 'destroy' commands)
path "sys/mounts" {
  capabilities = ["read"]
}

# Allow configuring the engine and creating rolesets
path "gcp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

---

## 💻 Vault CLI Utilities
The installation automatically registers these CLI commands in your terminal for managing your Vault environment.

### 1. Interactive Login (`vault-login`) 🧑‍💻
Authenticate to Vault and securely cache a GPG-encrypted session token locally for your dev tools.
```bash
# Log in manually (LDAP/Userpass)
vault-login user my-username -a [https://vault.example.com](https://vault.example.com)

# Log in as a Machine (AppRole)
vault-login approle my-role-id

# Inspect the currently active session token, expiration, and policies
vault-login info

# Clear the local cache and log out securely
vault-login clear
```
*(Tip: Set `export VAULT_ADDR="https://..."` in your bashrc to avoid typing `-a` every time!)*

### 2. Secret Data Management & Dynamic Engines (`vault-secret`) ⚙️
Manage static JSON payloads in Vault's KVv2 engine, and seamlessly bootstrap dynamic GCP credential engines.

**🚀 Bootstrap a Zero-Touch GCP Secrets Engine:**
*Uses your local `gcloud` session to safely build a Master Service Account entirely in memory, inject it into Vault, and elegantly handle Google Cloud IAM replication delays via smart polling.*
```bash
# Create the engine with default names (vault-gcp-master & terraform-runner)
vault-secret backend gcp create ctlabs-0815-123abc-05a-03

# Create the engine with custom Service Account and Roleset names
vault-secret backend gcp create ctlabs-0815-123abc-05a-03 --sa-name ci-admin --roleset-name tf-deployer

# List active GCP engines mounted in Vault
vault-secret backend gcp list

# Tear it down and cleanly delete the Master Service Account from GCP
vault-secret backend gcp destroy ctlabs-0815-123abc-05a-03
```

**👥 Team-Based Roleset Management:**
*Create distinct identities inside GCP (Rolesets) mapped to different Vault ACL policies for granular audit logging.*
```bash
# List all active rolesets (teams) in a project
vault-secret roleset list gcp/ctlabs-0815-123abc-05a-03

# Create a new roleset for the DevOps team using inline basic roles
vault-secret roleset create gcp/ctlabs-0815-123abc-05a-03 devops --roles "roles/editor, roles/iam.securityAdmin"

# Create a roleset using advanced YAML bindings (Supports cross-project/Shared VPC setup)
vault-secret roleset create gcp/ctlabs-0815-123abc-05a-03 vpc-admin --bindings vpc-admin.yaml

# Inspect the configuration of an existing roleset
vault-secret roleset read gcp/ctlabs-0815-123abc-05a-03 devops

# Delete a roleset and its underlying GCP Service Account
vault-secret roleset delete gcp/ctlabs-0815-123abc-05a-03 devops
```

**📄 Example `vpc-admin.yaml` structure:**
```yaml
projects:
  # The local service project
  - name: ctlabs-prj-2025101601
    roles:
      - roles/owner
      - roles/compute.networkAdmin
  # The Shared VPC Host Project (Cross-Project access)
  - name: shared-vpc-host-project-id
    roles:
      - roles/compute.networkUser
# organizations:
#   - name: "1234567890"
#     roles:
#       - roles/compute.xpnAdmin
```

**🔒 Just-In-Time (JIT) Execution:**
*Securely wraps tools (Terraform, gcloud, Docker) by injecting short-lived Vault GCP tokens purely into process memory, leaving no stale credentials on disk.*
```bash
# Run a single Terraform command using the 'devops' roleset
vault-secret exec gcp/ctlabs-0815-123abc-05a-03 devops -- terraform plan

# Run Google Cloud SDK commands
vault-secret exec gcp/ctlabs-0815-123abc-05a-03 devops -- gcloud compute instances list

# 🧠 Open an authenticated subshell (stay authenticated until you type 'exit')
vault-secret exec gcp/ctlabs-0815-123abc-05a-03 devops -- bash

# 🐳 Run an ephemeral Docker container authenticated to GCP
vault-secret exec gcp/ctlabs-0815-123abc-05a-03 devops -- \
  docker run --rm -it -e GOOGLE_OAUTH_ACCESS_TOKEN -e CLOUDSDK_AUTH_ACCESS_TOKEN google/cloud-sdk:latest bash
```

**🔍 Introspect Active Tokens:**
*Verify your current GCP authentication state, time remaining, and granted scopes.*
```bash
# Checks the $GOOGLE_OAUTH_ACCESS_TOKEN environment variable by default
vault-secret info gcp
```

**📋 Track Active Leases:**
*Check how many active tokens/keys are currently issued for any dynamic engine (requires `sys/leases/lookup/*` policy).*
```bash
# Track GCP leases for a specific team
vault-secret leases gcp/ctlabs-0815-123abc-05a-03 devops
```

**🗄️ Manage Static KVv2 Secrets:**
```bash
# Write a new secret to the kvv2 engine
vault-secret write kvv2/apps/my-service --data '{"api_key": "12345", "db_pass": "supersecret"}'

# Read a secret payload back
vault-secret read kvv2/apps/my-service

# List Vault paths (folders), OR list the specific data keys if pointed at a secret
vault-secret list kvv2/apps/my-service

# Safely search folder names, secret names, and payload keys using Regex
vault-secret search kvv2/ansible "onetick|dev_pass"
```

**🧠 Smart API Reading:**
*The CLI automatically routes system paths (like `sys/`, `auth/`, `identity/`) to bypass the KVv2 wrapper, letting you read core Vault configuration naturally.*
```bash
# Read a system policy
vault-secret read sys/policies/acl/my-policy
```

**🔬 Read Raw API Paths:**
*For ultimate control, bypass all logic. Add a trailing slash `/` to perform a LIST operation instead of a GET.*
```bash
# GET a specific key
vault-secret raw identity/oidc/.well-known/keys > vault-keys.json

# LIST active human/machine logins (Token Accessors)
vault-secret raw auth/token/accessors/
```

### 3. Automated AppRole Setup (`vault-approle`) 🤖
Manage machine identities and permissions for CI/CD or Orchestrators (like Rundeck).
```bash
# Set up a new AppRole with an auto-generated minimal policy for a specific path
vault-approle create my-service --path "kvv2/apps/my-service"

# Inspect detailed configuration of a specific AppRole (TTLs, Policies, CIDRs)
vault-approle info my-service

# Set up a "Manager" role (e.g., for Rundeck) to issue SecretIDs for another role
vault-approle create rundeck-mgr --type manager --target my-service

# Retrieve RoleID and generate a new SecretID (JSON output)
vault-approle get-creds my-service

# List all AppRoles (add --details to see TTLs and attached policies)
vault-approle list --details

# Delete an AppRole (automatically cleans up its auto-generated policy)
vault-approle delete my-service
```

---

## 🧪 Pytest Integration (Recommended Workflow)
To handle the `--interactive` flag and cleanly manage Vault authentication across your suite, create a `conftest.py`.

### Configure `conftest.py`
```python
import pytest
from ctlabs_tools.pytest.helper import Terraform, HashiVault

def pytest_addoption(parser):
    parser.addoption("--interactive", action="store_true", default=False)

@pytest.fixture(scope="session")
def is_interactive(request):
    return request.config.getoption("--interactive")

@pytest.fixture(scope="session")
def vault_auth():
    v = HashiVault()
    # Supports both human GPG cache and automated VAULT_ROLE_ID/VAULT_SECRET_ID env vars
    v.ensure_valid_token(interactive=True) 
    return v
```

### ☁️ GCP Dynamic Authentication Fixture
Seamlessly wrap Terraform execution with dynamic Google Cloud OAuth tokens generated by Vault.

```python
import os
import pytest
from ctlabs_tools.pytest.helper import Terraform

@pytest.fixture(scope="session")
def tf(is_interactive, vault_auth):
    # 1. Ask Vault for a temporary GCP token for the devops team
    gcp_token = vault_auth.get_gcp_token(
        roleset_name="devops", 
        mount_point="gcp/ctlabs-0815-123abc-05a-03"
    )
    
    # 2. Inject it securely into the local environment for both Terraform and Google Cloud SDK
    if gcp_token:
        os.environ["GOOGLE_OAUTH_ACCESS_TOKEN"] = gcp_token
        os.environ["CLOUDSDK_AUTH_ACCESS_TOKEN"] = gcp_token
        print("✅ Injected dynamic GCP credentials for Terraform and gcloud.")
    else:
        print("⚠️ Failed to get GCP token from Vault. APIs may fail to authenticate.")

    # 3. Start Terraform!
    t = Terraform(
        wd="./terraform", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token 
    )
    yield t
    t.cleanup()
    
    # 4. Clean up the environment variables afterward
    if "GOOGLE_OAUTH_ACCESS_TOKEN" in os.environ:
        del os.environ["GOOGLE_OAUTH_ACCESS_TOKEN"]
    if "CLOUDSDK_AUTH_ACCESS_TOKEN" in os.environ:
        del os.environ["CLOUDSDK_AUTH_ACCESS_TOKEN"]
```

---

## 🏗️ Terraform Testing Examples

### 1. Plan Integrity & Ephemeral Values
Verify the plan doesn't violate core requirements before applying. Ephemeral values (Terraform 1.10+) don't exist in the state file, so use `search_plan` to verify them during the planning phase.

```python
def test_plan_secrets_and_changes(tf):
    tf.plan()
    
    if not tf.has_changes():
        pytest.skip("No changes detected.")
        
    # Verify ephemeral secrets are correctly retrieved by the module
    secret_val = tf.search_plan("planned_values.outputs.secrets.value.api_key")
    assert secret_val is not None
    
    # Ensure critical resources aren't being deleted
    bucket_diff = tf.search_plan("resource_changes[?address=='aws_s3_bucket.data'] | [0]")
    assert "delete" not in bucket_diff["change"]["actions"]
```

### 2. Post-Apply Verification
Verify live state after infrastructure is stood up.

```python
def test_apply_and_verify(tf):
    tf.apply()
    
    # Search the live state JSON using JMESPath
    live_vm = tf.search_state("values.root_module.resources[?address=='aws_instance.web'] | [0]")
    assert live_vm["values"]["instance_state"] == "running"
```

---

## 🛡️ ConfTest / Policy Evaluation
Evaluate your Terraform plans against OPA/Rego policies before applying them.

```python
def test_policies(tf, is_interactive, vault_auth):
    tf.plan()
    
    if tf.has_changes():
        policy_checker = ConfTest(
            wd=".", 
            input="tfplan.json", 
            interactive=is_interactive,
            auth_callback=vault_auth.ensure_valid_token
        )
        
        # Will pause interactively or abort pytest if a policy fails
        policy_checker.run(ns="main")
```

---

## 🐧 Ansible Examples
Run configuration management against your newly provisioned infrastructure.

```python
from ctlabs_tools.pytest.helper import Ansible

def test_config_management(vault_auth, is_interactive):
    ansible = Ansible(
        wd="./ansible", 
        inventory="./inventories/prod.ini", 
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token
    )

    # Runs standard playbook with Extra Vars
    ansible.run(roles="setup,config", opts=["-b", "-e", "CTLABS_ENV=prod"]) 
```

---

## 📦 Google Cloud Secret Manager (GSM) Integration
If you are bootstrapping identities via Google Cloud, you can fetch them securely.

```python
from ctlabs_tools.pytest.helper import GCPSecretManager

def test_fetch_gsm_bootstrap():
    gsm = GCPSecretManager()
    if gsm.is_available:
        # Fetches projects/my-project/secrets/my-secret/versions/latest
        secret_payload = gsm.get_secret("my-project", "my-secret")
        assert secret_payload is not None
```

---

## 🖥️ Remote Desktop Helper
Launch native RDP sessions dynamically based on deployment results (RoyalTSX on macOS, FreeRDP on Linux).

```python
from ctlabs_tools.pytest.helper import RemoteDesktop

def test_rdp_access(tf):
    # Retrieve dynamic IP from state
    ip = tf.search_state("values.outputs.vm_ip.value")
    
    RemoteDesktop.launch(
        hostname=ip, 
        username="admin", 
        password="SuperSecretPassword123!"
    )
```
