# `core/storage/` — write-only evidence storage (Phase 1H)

Deposits sealed evidence artifacts into durable storage. **Custody & availability**; the
**authenticity** of what's stored is Phase 1G1's job (seals + registry root of trust). Spec:
`docs/specs/phase-1h-worm-evidence-storage.md`.

## The one-way valve
Backends expose only `put_object` — no read, list, or delete on the interface. But the
**real enforcement is IAM, not the Python surface**: the ambient identity is bound to
`roles/storage.objectCreator` **only**, so read/list/delete API calls are rejected
server-side (403). The method surface is a secondary consistency guard — an in-process
attacker could mint their own client from the same ambient token, and only IAM stops them
from reading or deleting evidence. **The `objectCreator`-only Terraform binding is therefore
the load-bearing invariant and must be verified out-of-band** (e.g. a CI check that the WIF
principal holds no read/delete role); if it ever grants read, the write-only property
collapses silently.

```
StorageBackend.put_object(name, data, *, stored_when, content_type="application/json") -> Receipt
Receipt = { backend, uri, generation, sha256, stored_at }   # factual only — no WORM claim
```

## Backends
- **`LocalFileBackend`** (`local.py`) — offline, stdlib. Writes exact bytes under a root;
  path-traversal-guarded. **NOT a WORM store** (the filesystem is mutable). For offline/dev/
  tests only — assumes a trusted local root.
- **`GCSWormBackend`** (`gcs.py`) — writes to a retention-**locked** (NOT versioned) GCS
  bucket and captures the **generation** number. Write-once-per-name immutability = the
  locked retention policy + unique object names (evidence UUIDs; registry revisions
  sequence-suffixed); a same-name overwrite of a not-yet-expired object hard-fails (403).
  **Keyless by construction**: build it with
  `GCSWormBackend.keyless(bucket)`, which uses ambient Workload-Identity/ADC credentials —
  **no key-file parameter exists**, so there is no downloadable key to steal.
  `google-cloud-storage` is imported lazily (only in `keyless()`), so the module imports and
  unit-tests run without the library.

## Honest posture (why no "WORM" claim)
A write-only app **cannot read a bucket's retention policy**, so it never claims "WORM" or
"immutable" — it only reports a factual `Receipt`. Immutability is a **platform + ops**
property (bucket-lock + retention, provisioned via Terraform) and is verified **out-of-band**
by an auditor. This structurally prevents the prior design's false-WORM assurance (ASSESSMENT
C2).

## Environments (never test against prod)
GCS **bucket-lock is irreversible**; a locked bucket accrues undeletable objects for the
retention period (7 years in prod). So:
- The bucket is resolved from `CORELINE_EVIDENCE_BUCKET` with **no production default** —
  `resolve_evidence_bucket()` fails loud if unset (`config.py`).
- **Prod:** the locked **`coreline-audit-ir-evidence`** bucket (in the `coreline-audit`
  project, alongside Google SecOps+). **Test/staging:** a separate **UN-locked** bucket.
  Note: `coreline-audit` is the *project*; the bucket is the lowercase, globally-unique name.
- The real-GCS **smoke test** (`tests/test_gcs_smoke.py`) is **skipped by default** and
  refuses to run against the prod bucket; enable with
  `CORELINE_GCS_SMOKE=1 CORELINE_EVIDENCE_BUCKET=<staging>`.

## Non-goals (this phase)
Provisioning/managing the bucket-lock + retention (ops/Terraform); reading/verifying evidence
through the app (write-only; auditor tooling is out-of-band & deferred); rollback enforcement
(`registry_sequence`, deferred); Drive mirror (deferred). `core/evidence/` never imports this
package — storage is a separate, swappable layer (ADR-0002).
