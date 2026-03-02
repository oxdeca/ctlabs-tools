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
vault-auth gcp create compute-role --sa-emails "vm-identity@ctlabs-prj-2025101601.iam.gserviceaccount.com" --policies "app-secrets-reader"
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


Bootstrap dynamic secrets engines and execute tools with Zero Standing Privileges.

**🚀 Bootstrap & Rolesets:**
*Create dynamic rolesets that generate temporary GCP tokens bound to specific GCP IAM Roles. Supports inline roles or advanced YAML bindings.*
```bash
# 1. Mount the GCP engine for a specific project
vault-gcp engine create ctlabs-prj-2025101601

# 2. Simple Role Assignment (Inline)
vault-gcp roleset create ctlabs-prj-2025101601 devops --roles "roles/editor,roles/compute.admin"

# 3. Advanced IAM Bindings (Using YAML/JSON)
vault-gcp roleset create ctlabs-prj-2025101601 data-eng --bindings gcp-bindings.yml
```

**📄 Example `gcp-bindings.yml`:**
```yaml
bindings:
  - resource: "//[cloudresourcemanager.googleapis.com/projects/ctlabs-prj-2025101601](https://cloudresourcemanager.googleapis.com/projects/ctlabs-prj-2025101601)"
    roles:
      - "roles/viewer"
  - resource: "//[storage.googleapis.com/projects/_/buckets/my-secure-bucket](https://storage.googleapis.com/projects/_/buckets/my-secure-bucket)"
    roles:
      - "roles/storage.objectAdmin"
```

**🔒 Just-In-Time Execution & Introspection:**
```bash
vault-gcp info
vault-gcp exec ctlabs-prj-2025101601 devops -- terraform plan
```

### 4. Kubernetes JIT Access (`vault-k8s`)


Dynamically generate ephemeral Kubernetes Service Accounts for human break-glass access or CI/CD deployments. No static `kubeconfig` required.

**🚀 Bootstrap & Roles:**
```bash
# Zero-Touch Bootstrap: Uses your active kubectl to mount the engine and bind Vault
vault-k8s engine create prod-cluster

# List available K8s roles for a specific cluster
vault-k8s role list prod-cluster

# Tell Vault what Kubernetes RBAC rules to generate dynamically (Supports JSON or YAML)
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
*Securely wraps `kubectl` by injecting a dynamic, short-lived token without touching `~/.kube/config`.*
```bash
# 1. Standard JIT Execution
vault-k8s exec prod-cluster dev backend -- kubectl get pods

# 2. NAT/Split-DNS Override (Bypass internal Vault IP and connect via public/NAT IP)
vault-k8s exec prod-cluster dev backend --server "[https://192.168.100.163:6443](https://192.168.100.163:6443)" -- kubectl get pods

# 3. Interactive JIT Subshell (Auto-configures a secure 'kc' alias!)
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
