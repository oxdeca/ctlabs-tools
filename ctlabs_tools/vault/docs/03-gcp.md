# 📖 `vault-gcp` Advanced Bindings & Auto-Patching

This guide explains how the `vault-gcp` CLI translates user-friendly YAML configurations into HashiCorp Vault's native HCL format.

---

## 🏗️ The Model: Folder Inheritance (no patching)
The Broker SA is provisioned in a **dedicated admin project** and granted folder-level rights inside a **managed folder** — `roles/resourcemanager.projectCreator` (creates new projects), `roles/resourcemanager.projectIamAdmin` and `roles/resourcemanager.folderIamAdmin` (assigns permissions). 

Every project created under that folder **inherits** those IAM rights, so binding a roleset to any project inside the folder needs no cross-project patching — Vault applies the bindings directly. Projects *outside* the folder are simply out of scope: Vault returns `403 Permission Denied` (blast radius contained).

---

## 🏗️ The Problem: Vault's Native HCL
By default, Vault's GCP Secrets Engine requires roleset bindings to be written in a specific HashiCorp Configuration Language (HCL) format. Writing raw HCL can be error-prone and tedious for developers who are more accustomed to standard YAML or JSON.

**Native Vault HCL Example:**
```hcl
resource "//[cloudresourcemanager.googleapis.com/projects/ctlabs-0815-123abc-05a-03](https://cloudresourcemanager.googleapis.com/projects/ctlabs-0815-123abc-05a-03)" {
  roles = ["roles/compute.networkAdmin", "roles/compute.securityAdmin"]
}
```

To solve this, `vault-gcp` includes a **smart YAML parser** that translates simple YAML arrays into valid Vault HCL on the fly.



---

## 🛠️ The YAML Structure — Single Source of Truth
The `vault-gcp` parser expects a dictionary categorized by the GCP resource type: `projects`, `folders`, or `organizations`. 

Inside each category, you define a list of target `name`s and the `roles` you want to grant.

**Example `vpc-admin.yml`:**
```yaml
project: play-sandboxdev-05a03                        # placement: the project the temp SA is created in

projects:
  - name: play-sandboxdev-05a03
    roles:
      - roles/compute.networkAdmin
      - roles/compute.securityAdmin

folders:
  - name: 1234567890
    roles:
      - roles/viewer
```

When using `--bindings`, the YAML is the source of truth: it carries everything (SA placement `project`, bindings, billing). CLI flags (`--project`, `--folder`, `--roles`) become explicit overrides — they are only mandatory in the flag-driven quick-create mode.

```bash
# YAML-driven (everything comes from the file):
vault-gcp role create sandbox-dev vpcadmin --bindings vpc-admin.yml

# Flag-driven quick create (equivalent):
vault-gcp role create sandbox-dev vpcadmin \
  --project play-sandboxdev-05a03 --roles "roles/editor"
```

Role sets live under the mount (`gcp/sandbox-dev/roleset/vpcadmin`). Roleset names are limited to **14 characters** by Vault's GCP engine.

---

## ⚙️ The Translation Engine (How it Works)

When you run `vault-gcp role create <mount> <roleset> --bindings vpc-admin.yml`, the tool performs three distinct steps:

### Step 1: Parsing & Resource Mapping
The Python script reads the YAML and maps your simple keys to Google's official Cloud Resource Manager URIs.
* `projects` becomes `//cloudresourcemanager.googleapis.com/projects/...`
* `folders` becomes `//cloudresourcemanager.googleapis.com/folders/...`

### Step 2: Cross-Project Bindings (no patching)
If the YAML binds to a target project **different** from the SA placement `project`, the tool does *not* run any `gcloud` commands. Folder inheritance gives the Broker SA authority over every project inside the managed folder; it just flags the cross-project reference so you can confirm the target really is within the managed folder's scope.

*Projects outside the folder are out of scope: Vault returns `403 Permission Denied` — the intended blast-radius containment.*

### Step 3: HCL Generation & API Call
Finally, the script stitches together the HCL string and sends it to the Vault API. 

The underlying API payload sent to `POST /v1/gcp/<mount>/roleset/<name>` looks like this:

```json
{
  "project": "play-sandboxdev-05a03",
  "secret_type": "access_token",
  "bindings": "\nresource \"//[cloudresourcemanager.googleapis.com/projects/ctlabs-0815-123abc-05a-03](https://cloudresourcemanager.googleapis.com/projects/ctlabs-0815-123abc-05a-03)\" {\n  roles = [\"roles/compute.networkAdmin\", \"roles/compute.securityAdmin\"]\n}\n"
}
```

---

## 🎯 Summary
By using `vault-gcp` with YAML bindings:
1. **Developers** write clean, readable YAML.
2. **The Tool** translates it into valid Vault HCL (no gcloud side-effects — folder inheritance covers IAM reach).
3. **Vault** receives perfectly formatted HCL and enforces the bindings via short-lived credentials.
