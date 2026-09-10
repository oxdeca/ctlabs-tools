### Prerequisites: Your GCP Hierarchy
For this example, let's assume your Google Cloud environment looks like this:
* **Hub Project:** `ctlabs-vault-admin` (Where Vault lives)
* **Spoke Folder:** `1234567890` (The "Engineering Workloads" folder)
* **Spoke Project:** `dev-cluster-01` (A project *inside* that folder)

---

### Step 1: Bootstrap the Engine (Day 0 & 1)
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

### Step 2: Create the Folder-Scoped Role (Day 2)
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

### Step 3: The Developer Workflow (Day 3+)
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

### Step 3b: Ephemeral Sandbox Projects (No Terraform Required)

Sandboxes are just throwaway projects — no `sandbox` module, no state files, no budgets needed.
Prerequisites (see `05-gcp-prerequisites.md` for the full detail): the Spoke folder already exists
(terraform `sandbox` module) and a dynamic roleset holds **folder-level** project creation rights
(`roles/resourcemanager.projectCreator`). A JIT token can then mint projects directly via the Cloud Resource
Manager REST API — **no gcloud, no state**, and the new project inherits IAM from the folder binding:

```bash
vault-gcp sandbox create engineering eng-editor sbox-dev-7f3a \
  --folder 1234567890 \
  --services compute.googleapis.com,iam.googleapis.com \
  --labels env=sandbox
```

**What this does:**
1. Fetches a JIT token for the folder-scoped roleset.
2. Calls `POST cloudresourcemanager.googleapis.com/v1/projects` under the folder (creation rights come from the folder binding).
3. Optionally enables the requested API services via Service Usage.
4. Projects are created **UNBILLED** — GCP has **no folder-level "default billing account"**. Attaching
   billing requires `billing.resourceAssociations.create` (= `roles/billing.user`) on the billing account,
   which a dynamic roleset can never hold (billing accounts can't be bound by Vault). Attach it afterwards
   with a billing-authorized identity (a Vault static account with `roles/billing.user`, or a billing admin).

Tear-down is just as easy:

```bash
vault-gcp sandbox delete engineering eng-editor sbox-dev-7f3a
```

Project deletion via the CRM API is a **soft-delete** (permanently purged after 30 days), so
accidental deletes are recoverable and abandoned sandboxes can be reclaimed at the folder level.

---

### The Cleanup (Optional)
If you ever need to completely tear down Vault's access to that folder, your `cleanup` command perfectly unwinds the Hub and Spoke architecture:

```bash
vault-gcp cleanup engineering \
  --project ctlabs-vault-admin \
  --folder-id 1234567890
```
