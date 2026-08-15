# `infra/gcs-evidence/` — WORM evidence storage (Terraform)

Provisions the Coreline evidence storage in the **`coreline-audit`** project:
- **`coreline-audit-ir-evidence`** — production WORM bucket (7-year retention, versioned,
  lockable), write-only for the app, read-only for the auditor.
- **`coreline-audit-ir-evidence-staging`** — un-locked, disposable bucket for CI smoke tests.

This is the **ops/one-time** provisioning our design (ADR-0002, spec `docs/specs/
phase-1h-worm-evidence-storage.md`) keeps out of the application. The app only *deposits*;
immutability lives here.

## What makes it WORM
1. `retention_policy` (7y) — objects can't be deleted or overwritten before they age out; an
   attempt hard-fails with `403 retentionPolicyNotMet`.
2. `is_locked = true` — makes the policy **permanent**; not even a project owner can delete.
3. **Unique object names** — evidence uses UUIDs; registry revisions are sequence-suffixed.
   Combined with (1), each name is written exactly once and can never point to different
   content.
4. `roles/storage.objectCreator`-only on the app — it can write, never read/list/delete.

**Why NOT versioning.** On a locked bucket, versioning would *weaken* the guarantee: it lets
the live object at a key be replaced (old bytes kept only as a noncurrent version), so a name
no longer immutably maps to content. It also accrues billable noncurrent versions that a
lifecycle rule **cannot** delete inside the 7-year retention window. Retention lock + unique
names is the correct WORM construction; versioning is deliberately off.

## ⚠️ The lock is IRREVERSIBLE — use the two-step workflow
`lock_retention` defaults to `false`. **Never lock on the first apply.**

```bash
cd infra/gcs-evidence

# 1. Create everything UNLOCKED (retention set but not yet permanent)
terraform init
terraform apply \
  -var 'writer_member=principal://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/subject/<SUBJECT>' \
  -var 'auditor_member=user:secops-auditor@example.com'

# 2. Verify the policy, versioning, IAM, and location are exactly right
gcloud storage buckets describe gs://coreline-audit-ir-evidence \
  --format="yaml(retentionPolicy, versioning, iamConfiguration, location)"

# 3. Only when satisfied: LOCK it (irreversible for 7 years)
terraform apply -var 'lock_retention=true' \
  -var 'writer_member=...' -var 'auditor_member=...'
```

Recommended: test the whole flow (create → lock) on a throwaway bucket name first, and
destroy it *before* locking, so you never accidentally lock the wrong thing.

## After provisioning
```bash
# Production deploy: point Coreline at the bucket (project comes from the ambient WIF identity)
export CORELINE_EVIDENCE_BUCKET=coreline-audit-ir-evidence

# CI smoke test: point at the un-locked staging bucket
CORELINE_GCS_SMOKE=1 CORELINE_EVIDENCE_BUCKET=coreline-audit-ir-evidence-staging \
  ./.venv/bin/python -m pytest core/storage/tests/test_gcs_smoke.py -q
```

## Notes / caveats
- **Keyless:** `writer_member` should be a Workload Identity Federation principal so there's
  no downloadable key. A service account is supported but reintroduces a stealable key.
- **`objectCreator`-only is the load-bearing invariant.** If that binding ever gains a
  read/delete role, the write-only guarantee collapses silently — consider a CI/policy check
  asserting the writer holds no `objectViewer`/`objectAdmin`/`admin` on the prod bucket.
- **State matters:** the retention lock is recorded in Terraform state — use a secure remote
  backend (see `versions.tf`), not local state.
- Not validated locally (no terraform in the dev env). Run `terraform validate` + `plan`
  before applying. Flag names/provider behavior can drift across provider versions.
