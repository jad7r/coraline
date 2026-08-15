# Implementation Plan: Phase 1G1 — Registry Root of Trust

Spec: `docs/specs/phase-1g1-registry-root-of-trust.md`. **Planning only — do not implement
until this plan is approved.** Strict red-first TDD for every task.

## Overview
Anchor the Phase 1D trusted-signer registry with a root Ed25519 signature so tampering
(add-entry, flip revoked→trusted, substitution) is cryptographically detected. Reuse the
Phase 1C detached-seal machinery; the only thing a deployment pins is a small stable root
*public* key.

## Architecture decisions
- **AD1** Reuse `seal.py` (detached Ed25519 over a canonical hash) rather than a bespoke
  format — the registry becomes "just another sealable document."
- **AD2** Add **domain separation** (`subject`) so a manifest seal ≠ a registry seal.
  This bumps the seal payload to v2 and touches shipped 1C (Open Question #1).
- **AD3** Verification **fails closed**: no seal / bad seal / non-root key / tampered
  registry ⇒ nothing trusted. Registry-seal failure dominates a valid manifest seal.
- **AD4** Root **private** key custody stays out of scope; the root **verify** key is
  supplied explicitly (pinned by caller/config).

## Dependency graph
```
Task 1  seal v2 domain separation (subject + content_hash)   [touches 1C — foundation]
   │
   ▼
Task 2  registry sealing/verification (seal_registry, verify_registry_seal)
   │
   ▼
Task 3  signed-registry load + end-to-end fail-closed verification
   │
   ▼
Task 4  root-key pinning convention + docs/README
```
Bottom-up; strictly sequential (each depends on the prior). No parallelism.

## Task list

### Phase A: Foundation
- [ ] **Task 1 — Seal v2 domain separation.** Add `subject`, rename `manifest_hash →
  content_hash`, bump `SEAL_VERSION="2"`; migrate manifest sealing; `verify_seal` requires
  expected `subject`. Update `test_seal.py`. *(Gated on Open Question #1.)*

### Checkpoint A
- [ ] `test_seal.py` green under v2; full `core/` suite green (1C manifest sealing intact).
- [ ] Review with human before proceeding.

### Phase B: Registry sealing
- [ ] **Task 2 — Registry seal create/verify.** `seal_registry` / `verify_registry_seal`
  in `registry.py`, composed over `seal.py` with `subject="signer-registry"`.

### Phase C: Trust integration
- [ ] **Task 3 — Signed-registry load + end-to-end verify.** `load_signed_registry`
  (fail-closed) and `verify_sealed_manifest_with_signed_registry`; registry-seal failure
  dominates.

### Checkpoint C
- [ ] SC1–SC5 tests green; end-to-end trusted only when both signatures verify.
- [ ] Review with human.

### Phase D: Provisioning + docs
- [ ] **Task 4 — Root-key pinning convention + docs.** Document how the root verify key is
  provided/pinned; update `core/evidence/README.md`; note non-goals (private key custody).

### Checkpoint D (complete)
- [ ] All SC1–SC6 met; full `core/` suite green; spec success criteria satisfied.
- [ ] `/review` (five-axis) before commit; ship only after green.

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Seal v2 breaks shipped 1C consumers | Med | Bump version; full 1C test migration in Task 1; alternative = separate registry-seal module (no 1C change) |
| Root key custody undefined ⇒ false sense of security | High | Explicit non-goal + doc; verify-only this phase; flag as next dependency |
| Root key compromise | High | Inherent PKI-root risk; document; rotation is a later phase |
| Availability (registry/seal deletion) | Med | Fail-closed is safe; WORM as later defense-in-depth |

## Open questions
See spec §10 (seal v2 approval; root-key pin location; seal filename). **Blocking Task 1.**
