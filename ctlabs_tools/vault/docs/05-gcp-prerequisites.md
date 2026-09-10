# 📘 `vault-gcp` Sandbox Pool — Prerequisites & Bootstrap

Detailed instructions for setting up the **one-time prerequisites** that make a
*leased sandbox pool* work through Vault JIT tokens:

1. **GCP platform (Terraform)** — the sandbox folder, a folder-scoped budget, the
   **pool of pre-provisioned projects**, and an optional TTL sweeper.
2. **Vault GCP engine** — the broker SA and `gcp/<mount>` engine keyed to the folder.
3. **A folder-scoped roleset** — a JIT identity with `roles/editor` on the folder.

> ⚠️ **Where you need `gcloud`:** only step 2 (engine create). The Terraform and
> daily lease/release flows run **without gcloud** (JIT tokens + REST APIs).

---

## 0. The Model at a Glance

```
                      ┌───────────────────────────────────────────────────┐
   GCP (Terraform)    │ sandbox folder ── folder-scoped budget            │  ◄── one-time
                      │   pool projects  sandbox-pool-01..NN              │
                      │   state=free │ owner=  │ lease-until=             │
                      └───────────────┬───────────────────────────────────┘
                                      │  folder IAM (roles/editor) inherited
   GCP (billing)      │ EXISTING billing account                          │  ◄── one-time
                      │ linked once to every pool project AT creation     │
   Vault  engine      │ gcp/<mount>   broker SA  (vault-gcp-broker)       │  ◄── one-time
                      │ vault-gcp engine create --project ADMIN --folder SBOX
   Vault  roleset     │ <roleset> (≤14 chars)  JIT SA per token           │  ◄── one-time
                      │ bindings: folders/SBOX  roles/editor              │
   Sweeper (optional) │ Cloud Scheduler → Cloud Function (static SA)      │  ◄── one-time
                      │ disables services + marks expired leases disabled │
```

**Pool lifecycle:** `free → leased → disabled → free`

```
   free     provisioned, waiting (labels: state=free)
   leased   claimed by an owner for a TTL (state=leased, owner, purpose, lease-until)
   disabled services disabled so it can't spend (state=disabled); still RESERVED
   free     returned to the pool after a terraform destroy of leftover resources
```

**Why a pool instead of creating/deleting projects?**
- A project pending deletion (`DELETE_REQUESTED`) **still counts toward project quota**
  until it is purged after 30 days — so create/delete churn both wastes quota and never
  reclaims it quickly (Resource Manager docs confirm this).
- The pool keeps a **constant project count** (quota never moves) and recycles instantly.
- Billing only needs to happen **once per pool member** at provisioning time, so the daily
  loop needs **zero billing permissions** — this removes the entire billing-account IAM
  problem from day-to-day operation.

---

## 1. Prereq A — GCP Organization & Billing Account (manual)

Only if not already present. Signed in as a domain **super admin / billing admin**:

1. Organization exists automatically once a Google Workspace/Cloud Identity user creates
   the first project or billing account (see *Cloud Resource Manager* docs).
2. Billing account: **Billing ▸ Manage billing accounts ▸ Create billing account**. Note
   its ID (`XXXXXX-XXXXXX-XXXXXX`).
3. **(Optional console convenience)** Billing ▸ *Default Billing Account*: setting an
   **organization-level** default only pre-selects that account when a *human* picks a
   billing account in the console. It is **not** a hierarchy attach and does **not**
   auto-bill API-created projects. Treat it as a convenience, not a requirement.

Anything else in this doc only needs an **existing** billing account.

---

## 2. Prereq B — GCP Platform via Terraform (folder + budget + pool)

Run once, from any workstation holding GCP credentials with:

- `resourcemanager.folders.create` and `resourcemanager.projects.create` (org or parent
  folder admin), **and**
- `roles/billing.user` **on the billing account** (so every pool project links on creation)
  plus `billing.budgets.create` (budget).

### The module

`/root/ctlabs-terraform/modules/gcp/sandbox` creates:

| Resource | Purpose |
|---|---|
| `google_folder.sandbox` | The sandbox folder — the inheritance point for the Vault roleset binding |
| `google_billing_budget.sandbox` | **Folder-scoped** budget covering the whole pool (abandoned projects included) |
| `google_project.pool` | `sandbox.projects` leasable projects `sandbox-pool-01…NN`, **linked to billing at creation**, labels `state=free` |
| `google_folder_iam_binding.extra` | Optional pre-bindings on the folder |
| sweeper resources | Optional TTL sweeper (Cloud Scheduler → Cloud Function) |

Data is defined in the **consumer's** `config.yml` and passed to the module via the `sandbox` object
variable — same pattern as `ctlabs-dev-standalone` (see
`/root/ctlabs-terraform/ctlabs-dev-standalone/main.tf`). Example wrapper root:

```yaml
# <wrapper-root>/config.yml
sandbox:
  name    : sandbox
  billing : 0123AB-4567CD-89EF01   # existing account; pool projects link to it once
  budget  : 200
  oid     : "123456789012"         # or: fid: "<parent folder>"
  # projects  : 5                  # pool size (default 5)
  # sweeper   :                    # optional TTL enforcement
  #   project  : gcp-vault-admin-2026042601
  #   schedule : "0 2 * * *"       # daily 02:00 UTC
  #   time_zone: UTC
  iam_bindings: []                # e.g. extra folder bindings
```

```hcl
# <wrapper-root>/main.tf — same structure as ctlabs-dev-standalone/main.tf
locals {
  config = yamldecode(file("./config.yml"))
}

module "sandbox" {
  source = "../modules/gcp/sandbox"
  sandbox = local.config.sandbox
}
```

```bash
terraform init && terraform plan && terraform apply
```

Grab the outputs: `folder_id` → value like `folders/1234567890` (the `--folder` argument
used everywhere below) and `pool_ids` → the leasable projects.

### What about budgets?

The folder-scoped budget covers **all** pool projects — including ones whose owner
abandoned them. There is no per-sandbox budget and no enforcer; the sweeper + budget are
the backstops, and pool members are permanent (module default `delete_policy = "PREVENT"`).

---

## 3. Prereq C — Vault GCP Engine (one host WITH gcloud + creds)

The broker SA gets the folder's IAM here (`engine create` performs those grants itself —
terraform does NOT need to pre-grant it).

```bash
vault-gcp engine create sandbox \
  --project gcp-vault-admin-2026042601 \
  --folder 1234567890
```

This:
1. Creates `vault-gcp-broker@<project>.iam.gserviceaccount.com`.
2. Binds the broker SA **at the folder**: `folderIamAdmin`, `projectIamAdmin`,
   `resourcemanager.projectCreator` (so it can manage pool projects and roleset SAs under
   the folder — inheritance does the rest).
3. Mounts `gcp/sandbox/` in Vault and stores the broker SA key there.

Check it: `vault-gcp engine list` and `vault-gcp engine help` / `vault-gcp engine read sandbox`.

> This is the **only** step above the ansible char of trust that needs `gcloud` — run it
> from a host that has it (the ansible container intentionally does not).

---

## 4. Prereq D — Folder-Scoped Roleset (the JIT token identity)

The roleset drives the whole daily loop. `roles/editor` at the folder is **sufficient**:
it includes `resourcemanager.projects.update` (rename/relabel → lease/reset),
`serviceusage.services.enable/disable/use`, and project read access. No
`projectCreator`, no `billing.*`. Roleset names are capped at **14 characters** by Vault.

`sandbox-builder.yml` (YAML = single source of truth):

```yaml
project: gcp-vault-admin-2026042601      # placement: project the JIT SA is created in
folders:
  - name: 1234567890                      # the sandbox folder from Prereq B
    roles:
      - roles/editor
```

```bash
vault-gcp role create sandbox sbox-builder --bindings sandbox-builder.yml
```

The token for this roleset can:
- lease/release/reset every pool project under the folder (rename, labels, services),
- manage resources inside the leased project (`editor`),
- **never** touch the admin project, anything outside the folder, or the billing account
  (contained blast radius).

Verify: `vault-gcp get-token sandbox sbox-builder` → then
`curl -s -H "Authorization: Bearer <token>" https://oauth2.googleapis.com/tokeninfo`.

---

## 5. Prereq E — TTL Sweeper (optional, recommended)

Cloud Scheduler (default daily 02:00 UTC) calls an HTTP Cloud Function that runs as the
dedicated static SA `sandbox pool sweeper` (`roles/editor` on the folder). For every pool
project with `state=leased` and `lease-until` in the past, it:

1. disables **all** enabled API services (the project stops spending), and
2. PATCHes it to `state=disabled` (owner kept for audit, `lease-until` removed).

Enabled from the `sandbox.sweeper` block in Prereq B. Purely a safety net — a manual
`sandbox list --sweep` (with the JIT roleset) does the same on demand, and a lease holder
should normally run `sandbox release` themselves.

---

## 6. Daily Runbook (order of operations)

```bash
# 1. Bootstrap the platform (once) — per prerequisites above
terraform apply                                     # folder + budget + pool (+ sweeper)
vault-gcp engine create sandbox --project <admin> --folder 1234567890
vault-gcp role create sandbox sbox-builder --bindings sandbox-builder.yml

# 2. Claim a sandbox (no terraform, no gcloud) — pool member gets leased
vault-gcp sandbox lease sandbox sbox-builder \
  --folder 1234567890 \
  --owner wolfgang@example.com \
  --ttl 14 --purpose gke-test \
  --services compute.googleapis.com,iam.googleapis.com

# 3. Operate with JIT tokens inside the (leased) project
vault-gcp exec sandbox sbox-builder -- bash
#   GOOGLE_OAUTH_ACCESS_TOKEN is exported inside the shell

# 4. Done working: stop the bleeding + reserve the project
vault-gcp sandbox release sandbox sbox-builder sandbox-pool-02
#   … then tear down leftovers: terraform destroy … (pool project is 'disabled', held)

# 5. Return to the pool
vault-gcp sandbox reset sandbox sbox-builder sandbox-pool-02

# 6. Overview / housekeeping
vault-gcp sandbox list sandbox sbox-builder --folder 1234567890
vault-gcp sandbox list sandbox sbox-builder --folder 1234567890 --sweep   # manual sweep
```

---

## 7. Permission Reference

| Identity | Grant | Where | Why |
|---|---|---|---|
| Terraform runner (Prereq B) | `folders.create` / `projects.create` + `roles/billing.user` + budget perms | org/parent + billing account | creates folder, pool projects (linked to billing), budget |
| Broker SA (`vault-gcp-broker`) | `folderIamAdmin`+`projectIamAdmin`+`projectCreator` | folder (auto via `engine create`) | lets Vault mint/cleanup dynamic SAs + manage pool projects in-scope |
| Roleset JIT SA | `roles/editor` | folder (auto via roleset) | lease/release/reset + manage the leased project |
| Sweeper SA (Opt.) | `roles/editor` | folder (via module) | disable services + mark expired leases `disabled` |
| Billing account | — | `roles/billing.user` on the runner only | **never** needed by the daily flow; linked once at provisioning |

---

## 8. Failure to Follow (symptom → cause)

| Symptom | Cause / fix |
|---|---|
| `sandbox lease` → *"pool exhausted"* | All members leased; check `sandbox list` (expired ones need `--sweep`/sweeper; `disabled` ones need `reset`) |
| `PERMISSION_DENIED` on lease/reset | Roleset missing `roles/editor` on the *exact* folder (rename/relabel = `resourcemanager.projects.update`, included in editor) |
| `PERMISSION_DENIED` enabling/disabling services | Roleset needs `serviceusage.services.enable/disable` (in `roles/editor`) |
| `sandbox list` empty or misses members | JIT SA lacks `resourcemanager.projects.list` on the folder — check the roleset binding |
| Role create reports "name too long" | Roleset name must be ≤ 14 chars |
| `engine create` needs gcloud on ansible host | Run from a host with gcloud + creds (Prereq C note) |
| Sweeper never fires | Check the scheduler job / Cloud Function in the sweeper project; `FOLDER_ID` env var must be the numeric folder id |