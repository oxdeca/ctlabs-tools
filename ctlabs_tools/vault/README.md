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
Authenticate to Vault and securely cache a GPG-encrypted session token locally. Supports OIDC headless SSO, AppRole, and Userpass.
```bash
vault-login oidc devops
vault-login oidc devops --no-browser
vault-login user my-username -a [https://vault.example.com](https://vault.example.com)
vault-login approle my-role-id
vault-login info
vault-login clear
```

### 2. Identity & Access Management (`vault-auth`)
Manage users, machine identities, LDAP groups, ACL policies, and Cloud/Cluster Auth bindings.

**👥 Users & Groups (LDAP / Userpass)**
```bash
vault-auth user list                      
vault-auth group create devops --policies "vpc-admin, default"
```

**☁️ GCP Auth & IAM Bindings**
*Bind existing GCP Service Accounts to Vault ACL Policies so they can fetch secrets.*
```bash
vault-auth gcp create compute-role --sa-emails "vm-identity@ctlabs-prj.iam.gserviceaccount.com" --policies "app-secrets-reader"
```

**☸️ Kubernetes Auth Bindings**
*Bind K8s Service Accounts to Vault ACL Policies.*
```bash
vault-auth k8s create payment-api-role --sa-names "payment-api-sa" --sa-namespaces "prod" --policies "db-writer"
```

**📜 Policies (ACLs)**
```bash
vault-auth policy create vpc-admin --file policies/vpc-admin.hcl
```

### 3. Google Cloud JIT Access (`vault-gcp`)

Bootstrap dynamic secrets engines, manage roles, and execute tools with Zero Standing Privileges.



**🚀 Identity Broker Bootstrap (Zero-Touch Hub & Spoke):**
*Configures Vault as a Global or Folder-level Identity Broker. Automatically creates the Service Account, applies IAM inheritance bindings, and passes the JSON key directly to Vault in-memory (zero disk footprint).*
```bash
# Scope Vault's JIT powers to a specific GCP Folder (Hub & Spoke Best Practice)
vault-gcp bootstrap --project ctlabs-vault-admin --folder-id 629297822944

# Scope Vault's JIT powers locally to a single Project
vault-gcp bootstrap --project ctlabs-prj-2025101601
```

**⚙️ Engine Management (Day 2 Ops):**
*Read, update, or manually manage GCP engines.*
```bash
vault-gcp engine list
vault-gcp engine info ctlabs-vault-admin
vault-gcp engine update ctlabs-vault-admin --max-ttl "24h"
```

**🛡️ Dynamic Roles & Cross-Project Auto-Patching:**
*Create dynamic roles that generate temporary GCP tokens bound to specific IAM permissions. The tool automatically detects cross-project YAML bindings and auto-patches the target project's IAM to allow Vault access.*
```bash
# 1. Global Search: List all roles across all active GCP engines
vault-gcp role list

# 2. Folder-Scoped Role (Hub & Spoke)
vault-gcp role create ctlabs-vault-admin folder-editor --roles "roles/editor" --folder 629297822944

# 3. Simple Project-Scoped Role 
vault-gcp role create ctlabs-prj-2025101601 devops --roles "roles/editor,roles/compute.admin"

# 4. Advanced IAM Bindings (Using YAML with Auto-Patching)
vault-gcp role create ctlabs-prj-2025101601 vpc-admin --bindings vpc-admin.yml
```

**📄 Example `vpc-admin.yml`:**
```yaml
projects:
  - name: ctlabs-0815-123abc-05a-03 # The script auto-patches this external project!
    roles:
      - roles/compute.networkAdmin
      - roles/compute.securityAdmin
```

**🔒 Just-In-Time Execution & Introspection:**
*Securely wraps tools by injecting a dynamic, short-lived OAuth token directly into the environment.*
```bash
vault-gcp info
vault-gcp exec ctlabs-vault-admin folder-editor -- terraform plan
vault-gcp exec ctlabs-vault-admin folder-editor -- bash # Drops you into an authenticated JIT subshell
```

**🌉 GKE Zero-Dependency Bridge:**
*Generate a secure `kubeconfig` for GKE using purely REST APIs—no `gcloud` CLI or auth plugins required!*
```bash
vault-gcp get-gke-credentials ctlabs-prj-2025101601 us-central1 my-gke-cluster --roleset devops
```

**🧹 Teardown & Security Cleanup:**
*Revoke Vault's GCP access, strip IAM bindings, and delete the broker Service Account.*
```bash
vault-gcp cleanup --project ctlabs-vault-admin --folder-id 629297822944
```

### 4. Kubernetes JIT Access (`vault-k8s`)

Dynamically generate ephemeral Kubernetes Service Accounts for human break-glass access or CI/CD deployments. No static `kubeconfig` required.



**🚀 Engine Bootstrap & Management:**
*Zero-touch engine creation using your active `kubectl` context to auto-extract K8s API tokens and CA certs.*
```bash
# Bootstrap an engine
vault-k8s engine create prod-cluster

# Introspect or update engine config (Day 2 Ops)
vault-k8s engine list
vault-k8s engine info prod-cluster
vault-k8s engine update prod-cluster --host [https://new-api-server.local:6443](https://new-api-server.local:6443)
```

**🛡️ Dynamic K8s Roles:**
```bash
# Global Search: List all roles across all mounted K8s engines
vault-k8s role list

# Create a role mapped to specific namespaces and RBAC rules (Supports JSON or YAML)
vault-k8s role create prod-cluster dev --rules dev-rule.yml --namespaces "backend,frontend"
```

**📄 Example `dev-rule.yml`:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list"]
```

**🔒 Just-In-Time Execution & Shells:**
*Securely wraps `kubectl` by injecting a dynamic, short-lived token. Features smart local caching for API servers.*
```bash
# 1. Standard JIT Execution
vault-k8s exec prod-cluster dev backend -- kubectl get pods

# 2. Smart Server Override (Auto-injects https:// and caches it locally for future use!)
vault-k8s exec prod-cluster dev backend --server 192.168.100.163:6443 -- bash

# 3. Interactive JIT Subshell (Uses cached server & auto-configures a secure 'kc' alias)
vault-k8s exec prod-cluster dev backend -- bash
```

**🔍 Token Introspection:**
*Check the exact TTL, Namespace, and active API server of your current JIT session.*
```bash
vault-k8s info
```

### 5. Static Secrets & Data (`vault-secret`)
Manage standard KVv2 data and inspect raw Vault endpoints.
```bash
vault-secret write kvv2/apps/my-service --data '{"api_key": "123"}'
vault-secret read kvv2/apps/my-service
vault-secret list kvv2/apps
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
    k8s_token = vault.get_k8s_secret_token("dev", "backend", "k8s/prod-cluster")
```
