# Coreline — Session Summary · 2026-07-06

Handoff doc to resume tomorrow. TL;DR: the **evidence-integrity spine is built, reviewed,
and green** through WORM storage. Next up (spec written, **awaiting your go**): **Phase 1G2 —
rollback enforcement**.

---

## Where we are

The reboot established one coherent target and then built the evidence pillar of it end-to-end.

**Architecture of record — ADR-0002 (`docs/adr/0002-ai-independent-platform.md`):** Coreline is an
**AI-independent incident-response platform**. Coreline is the system of record + deterministic
engine; LLMs are replaceable, advisory plugins (and optional). Interfaces (CLI/GUI/Claude
skill) are front-ends. Evidence integrity is a core capability. (ADR-0001 superseded.)

**Working mode:** workflow-pack discipline — spec → plan → TDD (red-first) → security-and-
hardening → review-before-commit → ship-only-green. Each phase spec'd, gated at checkpoints,
and reviewed by two independent subagents (five-axis + adversarial security) before shipping.

**Repo facts:** git initialized this session (restore point `c54cd6d`). `.venv` at repo root
(gitignored) has `pynacl`, `keyring`, `pytest`. `google-cloud-storage` is intentionally NOT
installed — the GCS backend imports it lazily and all unit tests run offline.

**Run the tests:** `./.venv/bin/python -m pytest core/ -q`
**Current status:** **125 passed, 1 skipped** (the GCS smoke test, gated), 6 subtests. Clean.

---

## What shipped today (16 commits)

| Phase | Commits | What |
|---|---|---|
| **0** | `9266d0d` (+ `c54cd6d` restore point) | Platform skeleton (`core/ ai/ interfaces/ connectors/`); lifted the PyNaCl crypto core into `core/evidence/integrity/`; **deleted WordPress dead code** |
| **1A** | `5cf8f6a` | Rewired the lifted crypto to import as `core.evidence.integrity.*`; 30 tests |
| **1B** | `114dc75` | Deterministic integrity layer: `hashing` (SHA-256), `manifest`, `custody` (hash-linked). Canonical JSON, stable `manifest_hash()` |
| **1C** | `4547b91` | Detached **Ed25519 seal** over a manifest hash (`seal.py`); fail-closed |
| **1D** | `6cd7509`, `acd8209` | **Trusted signer registry** (TRUSTED/REVOKED/UNKNOWN/UNTRUSTED); + retrospective spec/review |
| **1G1** | `a73168b`, `c6d1cfc`, `9099284`, `9dc157d` | **Registry root of trust**: seal v2 with `subject` domain separation; root-signed registry verified against a pinned root key; end-to-end `verify_sealed_manifest_with_signed_registry` (registry-seal failure dominates) |
| **1H** | `1953e00`, `506da0a`, `adae8c8`, `456d372` | **WORM evidence storage**: `StorageBackend` (write-only), `LocalFileBackend`, keyless `GCSWormBackend`, conformance contract, env separation + CI smoke test |
| docs | `2af9163` | Tracked the 1G1/1H specs + 1G1 task plan |

The full evidence chain now exists and is reviewed:
**hash → manifest → chain-of-custody → detached Ed25519 seal → trusted-signer registry →
root of trust → write-only WORM storage.**

---

## Key properties (and where the guarantee actually lives)

- **Authenticity:** evidence/registry are Ed25519-signed; a registry is trusted only if its
  root seal verifies against an **externally-pinned root public key** (never self-describing).
- **Domain separation:** seals carry a `subject` — a manifest seal can't be replayed as a
  registry seal (or vice-versa).
- **Custody/availability (1H):** write-only storage. **The write-only guarantee is enforced by
  IAM** (`objectCreator`-only), not the Python surface — the Terraform IAM binding is the
  load-bearing, verify-out-of-band invariant. Keyless (WIF/ADC); no key file to steal.
- **Honesty:** no code claims "WORM"/immutable it can't verify (fixes the old false-WORM bug,
  ASSESSMENT C2). Immutability is platform/ops (bucket-lock + versioning), verified out-of-band.
- **Fail-closed everywhere**; deterministic (timestamps injected, canonical JSON).

---

## Open residuals / deferred work (tracked)

- **R2 — signed-registry rollback/replay** → **THIS IS NEXT** (spec written, see below).
- Auditor **read/verify-from-GCS tooling** (Coreline is write-only by design; reading is out-of-band).
- **Retention-lock verification** (out-of-band: ops provisioning + CI smoke).
- Root **private-key custody / rotation** (caller-supplied; recommend WIF/offline).
- **Audit logging** of registry edits / verify decisions (R4).
- **Drive view-only mirror** (deferred).
- The **orphaned Gen-4 GUI** (`gui.py`/`auth.py`/`storage.py` at repo root) and the
  `CORELINE_OLD_DESIGN/` fossil are still present — not part of the new platform; cleanup TBD.
- **Sensitive file:** `CORELINE_OLD_DESIGN/archive/Coreline_Incident_Report_TruffleHog_Auth0_2026-05-26.docx`
  is a real incident report tracked in git history. **Do not push this repo to a remote
  until it's scrubbed** (would need history rewrite, e.g. git-filter-repo).

---

## ▶ Resume here tomorrow: Phase 1G2 — Rollback Enforcement

**Status: spec written, AWAITING APPROVAL. No code yet.**
Spec: `docs/specs/phase-1g2-rollback-enforcement.md` (untracked — commit or revise).

**Goal:** close R2. Add a monotonic **`sequence`** to the registry (covered by the root seal)
and a verifier **floor** (`min_sequence`) that rejects any registry below it — defeating replay
of an older validly-signed registry.

**3 open questions to answer before Task 1** (my recommendations):
1. Auto-advance sequence on every add/revoke, or explicit `bump()` per signed revision? →
   **explicit `bump()`**.
2. Floor default `min_sequence=0` (backward-compatible)? → **yes**, docs urge a real floor.
3. Add advisory `generated_at` metadata? → **skip** (avoid implying it's a freshness control).

**Plan (3 red-first tasks):** (1) registry `sequence` field + `to_dict`/`from_dict` default +
`bump` guard; (2) verify-side `min_sequence` floor across all four verify entry points; (3)
docs. Checkpoint after Task 2; final five-axis + security review before ship.

**To restart:** reply `go` (accepting the 3 recommendations) or adjust them.

---

## Handy references
- Assessment: `ASSESSMENT.md` · ADRs: `docs/adr/` · Specs: `docs/specs/`
- Evidence layer: `core/evidence/` (+ `integrity/` crypto) · Storage: `core/storage/`
- Tests: `./.venv/bin/python -m pytest core/ -q`
