# 🔐 CTLabs Vault & Identity Suite

A dedicated suite of CLI utilities and Python APIs for managing HashiCorp Vault, Zero Standing Privileges (JIT Access) in Google Cloud and Kubernetes, and Enterprise Identity.

## 📦 Architecture & Philosophy
This module strictly separates the pillars of Cloud Security:
1. **Authentication & Policy (`vault-auth`)**: Who are you, and what are you allowed to do?
2. **Cloud Identity (`vault-gcp`)**: Just-In-Time, ephemeral access to Google Cloud infrastructure.
3. **Cluster Identity (`vault-k8s`)**: Just-In-Time, ephemeral access to Kubernetes clusters.
4. **Static Data (`vault-secret`)**: Managing key-value payloads and reading raw Vault APIs.

---

## 💻 CLI Utilities

### 1. Authentication & Session Cache (`vault-login`)
Authenticate to Vault and securely cache a GPG-encrypted session token locally.
```bash
# Log in manually (LDAP/Userpass)
vault-login user my-username -a [https://vault.example.com](https://vault.example.com)

# Log in as a Machine (AppRole)
vault-login approle my-role-id

# Inspect your active session token and policies
vault-login info

# Securely log out and clear the cache
vault-login clear
```

### 2. Identity & Access Management (`vault-auth`)
Manage users, machine identities, LDAP groups, ACL policies, and Kubernetes Auth bindings.
```bash
# Users & Groups (LDAP / Userpass)
vault-auth user list                      
vault-auth group create devops --policies "vpc-admin, default"

# Machine Identities (AppRole & Kubernetes Auth)
vault-auth approle create ci-runner --policies "terraform-deployer"
vault-auth k8s create payment-api-role --sa-names "payment-api-sa" --sa-namespaces "prod" --policies "db-writer"

# Global Entities & Aliases (Identity Engine)
vault-auth entity create peter --policies "developer-baseline"
vault-auth alias create peter p.smith --mount userpass
vault-auth alias create peter peter.smith --mount ldap

# Policies (ACLs)
vault-auth policy create vpc-admin --file policies/vpc-admin.hcl
```

### 3. Google Cloud JIT Access (`vault-gcp`)
Bootstrap dynamic secrets engines and execute tools with Zero Standing Privileges.
```bash
# Initialize a new GCP Secrets Engine (Zero-Touch IAM setup)
vault-gcp engine create ctlabs-prj-2025101601

# Create a roleset
vault-gcp roleset create ctlabs-prj-2025101601 devops --roles "roles/editor"

# JIT Execution: Securely wraps tools by injecting short-lived GCP tokens purely into process memory
vault-gcp exec ctlabs-prj-2025101601 devops -- terraform plan
vault-gcp exec ctlabs-prj-2025101601 devops -- bash
```

### 4. Kubernetes JIT Access (`vault-k8s`)


Dynamically generate ephemeral Kubernetes Service Accounts for human break-glass access or CI/CD deployments. No static `kubeconfig` required.

**🚀 Bootstrap & Roles:**
```bash
# Zero-Touch Bootstrap: Uses your active kubectl to mount the engine and bind Vault to the cluster
vault-k8s engine create prod-cluster

# Tell Vault what Kubernetes RBAC rules to generate dynamically
vault-k8s role create prod-cluster developer --rules developer-rules.json --namespaces "frontend,backend"
```

**📄 Example `developer-rules.json`:**
```json
{"rules": [{"apiGroups":[""], "resources":["pods", "pods/log"], "verbs":["get", "list"]}]}
```

**🔒 Just-In-Time Execution:**
*Securely wraps `kubectl` by injecting a dynamic, short-lived token without touching `~/.kube/config`.*
```bash
# Request a JIT token and instantly fetch logs (Token is deleted automatically by Vault!)
vault-k8s exec prod-cluster developer backend -- kubectl get pods
```

### 5. Static Secrets & Data (`vault-secret`)
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
    
    # Get a dynamic GCP token
    gcp_token = vault.get_gcp_token("devops", "gcp/my-project")
    
    # Get a dynamic Kubernetes token
    k8s_token = vault.get_k8s_secret_token("developer", "backend", "k8s/prod-cluster")
```
