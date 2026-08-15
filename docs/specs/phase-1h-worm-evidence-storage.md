# Spec: Phase 1H — WORM Evidence Storage Backend (GCS)

- **Status:** DRAFT — decisions locked (2026-07-06); requesting approval to implement
- **Mode:** spec-driven · source-driven · TDD (red-first) · security-and-hardening
- **Depends on:** Phase 1B–1G1 (hashing/manifest/custody/seal/registry + root of trust)
- **Controlling decision:** [ADR-0002](../adr/0002-ai-independent-platform.md) — this is the
  connector/storage layer; GCS is a *backend*, not a change to the crypto core.
- **Complements:** GCS = **custody & availability**; Phase 1G1 = **authenticity**.

## 0. Decisions locked
1. **Keyless (Workload Identity Federation)** — no downloadable SA key; Cloud Run gets
   short-lived tokens tied to the container identity. Removes the stolen-key vector entirely.
2. **Coreline is strictly WRITE-ONLY (`roles/storage.objectCreator`).** No read/list/delete.
   Coreline never reads evidence back — a "mailbox slot." Reading & verification are **out-of-band**
   by an auditor principal (Console / dedicated tool), **out of scope for 1H**.
3. **Drive mirror: deferred** to a later phase.
4. **7-year production retention (locked) + a separate un-locked / short-retention TEST
   bucket.** Never run CI/tests against a locked bucket (undeletable for 7 years).
5. **In-memory GCS fake for unit tests + one CI-gated real smoke test** against an un-locked
   staging bucket.

**Consequence of #2 — how we avoid the old C2 false-WORM bug:** a write-only app *cannot*
read the bucket's retention policy, so **Coreline makes no "WORM" claim at all.** It deposits
bytes and reports a receipt (uri + immutable generation number). The retention lock is
established by **ops at provisioning** and verified **out-of-band** (auditor + a CI smoke
test), never asserted by the app. Honest by construction.

---

## 1. Objective (mini-spec)

Stream sealed artifacts — `evidence_<case>_<uuid>.json` + its `.seal.json`, and the signer
registry + its `.seal.json` — to the retention-locked (NOT versioned) `coreline-audit-ir-evidence` bucket
through a **write-only, keyless** identity, so that once written they are **immutable and
undeletable for the retention period, even to a project owner or a compromised app**.
Authenticity is already guaranteed by 1G1; this adds tamper-proof custody + availability.

**Success criteria (testable).**
- SC1 Evidence core stays storage-agnostic: a `StorageBackend` interface + offline
  `LocalFileBackend` + `GCSWormBackend`, interchangeable; `core/evidence/*` unchanged.
- SC2 Write path is **write-only by construction** — the backend exposes only `put_object`;
  no read/list/delete method exists or is reachable.
- SC3 A write captures GCS's immutable **generation number** into a durable `Receipt`.
- SC4 **No unverifiable claims.** Coreline reports the write receipt (uri + generation), and
  **never** labels a write "WORM"/"immutable" (it cannot verify that write-only). Fixes C2.
- SC5 **Write-once-per-name via unique names + locked retention (NOT versioning).** Distinct
  names produce independent objects; a same-name overwrite of a not-yet-expired object
  hard-fails server-side (403 retentionPolicyNotMet). Bucket versioning is deliberately OFF
  (it would let a key's live object be replaced and accrue un-cleanable noncurrent versions).
- SC6 Keyless auth: the `GCSWormBackend` uses ambient/ADC credentials (WIF) — **no key file
  path** is accepted or read.

**Explicitly NOT in 1H (deferred follow-ups):**
- Auditor **read/verify-from-GCS** tooling (out-of-band; uses 1G1 verify fns on fetched bytes).
- **Retention-lock verification** as an app feature (out-of-band: ops provisioning + CI smoke).
- **Rollback enforcement (R2)** — the monotonic `registry_sequence` + verifier floor is a
  verify-side concern; deferred to a dedicated phase to keep 1H tight.
- **Drive view-only mirror** — deferred (Decision #3).

---

## 2. Source-Driven Findings

**Current tree:** `core/evidence/*` is storage-agnostic; **no storage backend exists**. GCS
code lives only in the orphaned Gen-4 `gui.py`.

**Prior art (reference, not the design):** `CORELINE_OLD_DESIGN/gui.py:427` `write_manifest`
(`blob.upload_from_string`), `archive/tools/evidence_bot.py`, `archive/infra/*.tf` (WORM
buckets w/ retention).

| Legacy element | Verdict |
|---|---|
| `blob.upload_from_string(bytes, content_type)` write mechanic | **Reuse** |
| GCS retention lock via Terraform (one-time ops) | **Reuse** (ops, not app) |
| GCS object versioning | **Discard** — weakens name→content immutability on a locked bucket + accrues un-cleanable noncurrent cost; use unique names instead |
| `validate_bucket` checks IAM only, then claims "WORM" (C2 false assurance) | **Discard & invert** — app makes no WORM claim (SC4); verification is out-of-band |
| GCS via operator OAuth + full `auth/drive`; downloaded SA key; placeholder project | **Discard** — keyless WIF, write-only, real project |
| Read+write on one identity | **Discard** — Coreline is write-only; auditor reads out-of-band |

---

## 3. Threat Model (STRIDE over the storage boundary)

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| Tampering | Overwrite/delete stored evidence | bucket-lock + retention (403 on overwrite) + `objectCreator`-only (no delete) + unique names | none while retention holds |
| Spoofing | Compromised app writes *fake* evidence | write access ≠ trust: authenticity is 1G1 — unsigned/untrusted evidence fails verification regardless of who wrote it | app can add noise (DoS row) |
| Repudiation | Deny a write happened | Cloud Audit Logs (data-write) — partial R4 | not a full app audit log |
| Info disclosure | Stolen identity exfiltrates evidence | **keyless (no key to steal)** + `objectCreator` has **no read/list** → cannot read/enumerate | Audit-Log metadata |
| DoS | App floods bucket with junk objects | quota + monitoring/alerting (ops) | create-only can still write garbage; **cannot** delete real evidence |
| EoP | Project owner / compromised SA deletes evidence | **bucket-lock defeats even the project owner** for the retention period | org-level takeover (out of scope) |

**Abuse case → first test:** "attacker compromises the app" → assert the backend has *only*
`put_object`; a read/delete is neither coded nor reachable, and no key file is loadable.

---

## 4. Trust Boundaries

```
Coreline app  ──(WRITE-ONLY, keyless WIF: objectCreator)──▶  GCS coreline-audit
   evidence.json + .seal + registry + registry.seal        (retention-locked, not versioned)
                                                                  │ immutable generations
Auditor (separate, out-of-band, OUT OF 1H SCOPE) ◀─ objectViewer ─┘  + Cloud Audit Logs
```
- **Standing credential:** none downloadable — WIF issues ephemeral, container-bound tokens.
- **Platform-enforced immutability:** Google's retention lock; the app only deposits.
- **Strict one-way valve:** Coreline can drop objects in; it cannot read, list, or delete. A full
  app compromise cannot pull evidence out or destroy it.

---

## 5. Design Decisions — Legacy → Proposed → Rationale

- **D1 Identity.** *Legacy:* operator OAuth + full `auth/drive`, or a downloaded SA key.
  *Proposed:* **keyless WIF**, `roles/storage.objectCreator` only (ambient ADC credentials).
  *Rationale:* least privilege + no stealable key (Decision #1/#2).
- **D2 No WORM claim.** *Legacy:* claimed "WORM" after an IAM check (C2). *Proposed:* the app
  reports only a factual `Receipt` (uri + generation); immutability is asserted by ops and
  verified out-of-band. *Rationale:* never overclaim what a write-only app can't verify.
- **D3 Write-only by construction.** *Proposed:* `StorageBackend` exposes **only**
  `put_object`; no get/list/delete anywhere. *Rationale:* a compromised app can't read or
  destroy evidence (Decision #2).
- **D4 Storage-agnostic core.** *Proposed:* `LocalFileBackend` (stdlib, offline) +
  `GCSWormBackend` behind the interface; `core/evidence/*` never imports GCS. *Rationale:*
  keeps the crypto core dependency-free + offline-testable (ADR-0002).
- **D5 Unique names + receipt (no versioning).** *Proposed:* achieve write-once-per-name via
  a locked retention policy + unique object names (evidence UUIDs; registry revisions
  sequence-suffixed); capture the returned **generation** into `Receipt`. *Rationale:* on a
  locked bucket, versioning *weakens* the name→content immutability (it permits replacing a
  key's live object) and accrues noncurrent-version cost that lifecycle can't reclaim inside
  the retention window — so versioning is off and uniqueness carries the guarantee.

---

## 6. Data model / interfaces

```
StorageBackend (interface):
    put_object(name: str, data: bytes, *, content_type: str = "application/json") -> Receipt
    # NO get / list / delete — write-only by construction.

Receipt (frozen):
    backend: "local" | "gcs"
    uri: str                 # gs://coreline-audit/... or file://...
    generation: str | None   # GCS immutable generation number (None for local)
    sha256: str              # of bytes written (ties storage to 1B hashing)
    stored_at: str           # ISO-8601 UTC (caller-supplied; deterministic in tests)

LocalFileBackend(root)                 -> writes under root; generation=None
GCSWormBackend(bucket, *, client=None) -> keyless ADC; objectCreator upload; capture generation
```
Object layout: `incidents/<incident_id>/evidence_<uuid>.json` (+ `.seal.json`);
`registry/registry-<sequence>.json` (+ `.seal.json`) — unique per revision; no versioning.

---

## 7. Test plan (red-first)

New `core/storage/` + `core/storage/tests/`. All Small/Medium; **no real GCS** in unit tests.

| # | Test | SC |
|---|---|---|
| 1 | `LocalFileBackend.put_object` writes bytes; `receipt.sha256 == sha256(bytes)` | SC1 |
| 2 | backends interchangeable behind the interface (same `Receipt` contract) | SC1 |
| 3 | `GCSWormBackend` against an **in-memory fake** uploads + captures a generation | SC3/SC5 |
| 4 | same-name re-write ⇒ **new generation**, not overwrite | SC5 |
| 5 | backend exposes **only** `put_object` (introspection: no get/list/delete attr) | SC2 |
| 6 | receipt is factual — no "WORM"/"immutable" claim string anywhere in the API | SC4 |
| 7 | `GCSWormBackend` accepts **no key-file path** (keyless; ambient creds only) | SC6 |
| — | CI-gated **real staging smoke test** (un-locked bucket): real API call shape | (Large) |

Doubles: in-memory fake implementing the client surface for units; one CI-gated staging
smoke test (un-locked bucket) for real-API shape.

---

## 8. Implementation plan (vertical slices — for review)

```
Task 1 StorageBackend interface + Receipt + LocalFileBackend   [foundation, stdlib, offline]
   └─▶ Task 2 GCSWormBackend (keyless ADC, objectCreator write, generation capture)
          via an in-memory fake  [Medium tests]
   └─▶ Task 3 write-only guarantee + factual-receipt tests (SC2/SC4/SC6)
   └─▶ Task 4 env separation (prod locked vs test un-locked) + CI staging smoke test + docs
```
Checkpoints after Task 1 (offline backend green) and Task 3 (write-only + honest posture
proven) → human review; final: `/review` five-axis + security audit, ship.

## 9. Rollback plan
Purely additive (`core/storage/`). Crypto core unchanged; GCS behind an interface (swap to
`LocalFileBackend` to disable). No data migration. Reset points: 1G1 `9dc157d`; `c54cd6d`.

## 10. Explicit non-goals
Provisioning/managing the bucket-lock + retention (ops/Terraform, one-time); app-side
retention verification (out-of-band); reading/verifying evidence through the app (write-only;
auditor tooling is separate & deferred); rollback enforcement / `registry_sequence` (R2,
deferred); Drive mirror (deferred); write-identity IAM administration; full connector
framework (only the storage slice); DoS/quota prevention beyond monitoring.

## 11. Open questions
All resolved (see §0). None blocking.
