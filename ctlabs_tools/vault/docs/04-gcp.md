### Prerequisites: Your GCP Hierarchy
For this example, let's assume your Google Cloud environment looks like this:
* **Hub Project:** `ctlabs-vault-admin` (Where Vault lives)
* **Spoke Folder:** `1234567890` (The "Engineering Workloads" folder)
* **Spoke Project:** `dev-cluster-01` (A project *inside* that folder)

---

### Step 1: Bootstrap the Engine
First, we need to create the Vault Broker Service Account inside the Hub project (`--project`), but crucially, we need to grant it the ability to manage IAM *on the Spoke folder*. The mount is namespaced per environment (`gcp/engineering`). 

Run your zero-touch bootstrap command:

```bash
vault-gcp engine create engineering \
  --project ctlabs-vault-admin \
  --folder 1234567890
```

**What this does:**
1. Creates `vault-gcp-broker@ctlabs-vault-admin.iam.gserviceaccount.com`.
2. Attaches the `roles/resourcemanager.folderIamAdmin` and `projectIamAdmin` roles to that Service Account *specifically at the Folder level* (1234567890).
3. Mounts the engine at `gcp/engineering/` in Vault and stores the Broker SA key there.

---

### Step 2: Create the Folder-Scoped Role
Now we tell Vault to create a JIT profile that grants developer access to that folder. We use the `--folder` switch. Let's create a role called `eng-editor` (roleset names are capped at 14 chars):

```bash
vault-gcp role create engineering eng-editor \
  --project ctlabs-vault-admin \
  --roles "roles/editor" \
  --folder 1234567890
```

**What this does:**
Vault saves a role configuration. When a user asks for this role, Vault will dynamically create a temporary Service Account inside the placement project (`--project`), but it will bind the `roles/editor` permission directly to Folder `1234567890`.

---

### Step 3: The Developer Workflow
Now, a developer logs in via OIDC. They need to manage infrastructure inside `dev-cluster-01` (which sits inside the Spoke folder). 

They run your wrapper:

```bash
vault-gcp exec engineering eng-editor -- bash
```

Inside that JIT bash shell, the developer is fully authenticated as the temporary Service Account. 
Because the role was scoped to the Folder, they can instantly run commands against *any* project inside it:

```bash
# This works perfectly:
gcloud compute instances list --project dev-cluster-01

# But if they try to touch the Vault admin project?
gcloud compute instances list --project ctlabs-vault-admin
# ❌ ERROR: Permission Denied! (Blast radius contained)
```

---

### Step 3b: Leasable Sandbox Pool (No Terraform Per Sandbox)

Sandboxes are a **fixed pool of pre-provisioned projects** (`sandbox-pool-01…NN`) — created once by the
terraform `sandbox` platform module and linked to billing once. Quota stays constant (no projects are ever
created or deleted at runtime; soft-deleted projects would otherwise hold quota for the 30-day purge
window). A `roles/editor` folder-scoped roleset is all the JIT token needs: `roles/editor` includes
`resourcemanager.projects.update` (rename/relabel), `serviceusage.services.enable/disable`, and read access.

The daily loop is lease → work → release → reset (lifecycle `free → leased → disabled → free`):

```bash
# 1. Claim the first free pool project for 14 days
vault-gcp sandbox lease engineering eng-editor \
  --folder 1234567890 \
  --owner wolfgang@example.com \
  --ttl 14 --purpose gke-test \
  --services compute.googleapis.com,iam.googleapis.com

# 2. Operate inside the leased project with the same JIT identity
vault-gcp exec engineering eng-editor -- bash

# 3. Done working: disable all services + mark 'disabled' (still RESERVED)
vault-gcp sandbox release engineering eng-editor sandbox-pool-02

# 4. After a terraform destroy of the leftover resources: back to 'free'
vault-gcp sandbox reset engineering eng-editor sandbox-pool-02

# 5. Overview + (opt-in) auto-release of expired leases
vault-gcp sandbox list engineering eng-editor --folder 1234567890
```

**What this does:**
1. Fetches a JIT token for the folder-scoped roleset (`roles/editor` on the sandbox folder).
2. `lease` picks the first `state=free` member (CRM `projects.list` filtered to the folder), PATCHes
   `state=leased`/`owner`/`purpose`/`lease-until` labels + display name `sbox-<owner>-<purpose>`, and
   enables the requested services via Service Usage — **no gcloud, no state**.
3. `release` disables **all** enabled services (so the project stops spending) and marks it `disabled`,
   keeping it reserved for teardown. `reset` returns it to `free` once everything is cleaned up.
4. An optional Cloud Scheduler → Cloud Function sweeper (terraform `sandbox.sweeper`, see
   `05-gcp-prerequisites.md`) automatically does the release step for leases past their TTL.

No project is ever created or deleted at runtime — billing is attached **once** at pool provisioning, so
the roleset needs none of the `billing.*` / `projectCreator` roles.

---

### The Cleanup (Optional)
If you ever need to completely tear down Vault's access to that folder, your `cleanup` command perfectly unwinds the Hub and Spoke architecture:

```bash
vault-gcp cleanup engineering \
  --project ctlabs-vault-admin \
  --folder-id 1234567890
```
