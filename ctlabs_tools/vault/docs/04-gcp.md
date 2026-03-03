### Prerequisites: Your GCP Hierarchy
For this example, let's assume your Google Cloud environment looks like this:
* **Hub Project:** `ctlabs-vault-admin` (Where Vault lives)
* **Spoke Folder:** `1234567890` (The "Engineering Workloads" folder)
* **Spoke Project:** `dev-cluster-01` (A project *inside* that folder)

---

### Step 1: Bootstrap the Hub (Day 0 & 1)
First, we need to create the Vault Master Service Account inside the Hub project, but crucially, we need to grant it the ability to manage IAM *on the Spoke folder*. 

Run your zero-touch bootstrap command:

```bash
vault-gcp bootstrap \
  --project ctlabs-vault-admin \
  --folder-id 1234567890
```

**What this does:**
1. Creates `vault-gcp-broker@ctlabs-vault-admin.iam.gserviceaccount.com`.
2. Attaches the `roles/resourcemanager.folderIamAdmin` and `projectIamAdmin` roles to that Service Account *specifically at the Folder level* (1234567890).
3. Mounts the engine at `gcp/ctlabs-vault-admin/` in Vault.

---

### Step 2: Create the Folder-Scoped Role (Day 2)
Now we tell Vault to create a JIT profile that grants developer access to that folder. We use the `--folder` switch. Let's create a role called `engineering-editor`:

```bash
vault-gcp role create ctlabs-vault-admin engineering-editor \
  --roles "roles/editor" \
  --folder 1234567890
```

**What this does:**
Vault saves a role configuration. When a user asks for this role, Vault will dynamically create a temporary Service Account inside `ctlabs-vault-admin`, but it will bind the `roles/editor` permission directly to Folder `1234567890`.

---

### Step 3: The Developer Workflow (Day 3+)
Now, a developer logs in via OIDC. They need to manage infrastructure inside `dev-cluster-01` (which sits inside the Spoke folder). 

They run your wrapper:

```bash
vault-gcp exec ctlabs-vault-admin engineering-editor -- bash
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

### The Cleanup (Optional)
If you ever need to completely tear down Vault's access to that folder, your `cleanup` command perfectly unwinds the Hub and Spoke architecture:

```bash
vault-gcp cleanup \
  --project ctlabs-vault-admin \
  --folder-id 1234567890
```
