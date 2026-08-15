# Phase 1G1 — Task Checklist (Registry Root of Trust)

Spec: `docs/specs/phase-1g1-registry-root-of-trust.md` · Plan: `tasks/plan.md`
**Do not start until approved. Strict red-first TDD: write the failing test, observe it
fail, then implement.**

---

## Task 1: Seal v2 — domain separation
**Description:** Bind each seal to what it signs. Add `subject` field, rename
`manifest_hash → content_hash`, bump `SEAL_VERSION="2"`; `verify_seal` takes an expected
`subject`. Migrate manifest sealing to set `subject="evidence-manifest"`.
**Acceptance criteria:**
- [ ] Seal payload carries `subject` and `content_hash`; `seal_version == "2"`.
- [ ] `verify_seal` rejects a seal whose `subject` ≠ expected.
- [ ] Phase 1C manifest seal/verify still works (regression).
**Verify:** `./.venv/bin/python -m pytest core/evidence/tests/test_seal.py -q` and full `core/`.
**Dependencies:** None (gated on Open Question #1).
**Files:** `core/evidence/seal.py`, `core/evidence/tests/test_seal.py`.
**Scope:** S–M.

## Task 2: Registry seal create/verify
**Description:** `seal_registry(registry, root_signing_key, *, signer, sealed_when)` and
`verify_registry_seal(registry, seal, root_verify_key)`, composed over `seal.py` with
`subject="signer-registry"` and `content_hash=registry.registry_hash()`.
**Acceptance criteria:**
- [ ] Valid root-signed registry verifies; tampered registry (add-entry, flip status) fails.
- [ ] Registry signed by a non-root key is rejected.
- [ ] A manifest seal is rejected as a registry seal (subject mismatch), and vice versa.
**Verify:** `./.venv/bin/python -m pytest core/evidence/tests/test_registry_seal.py -q`
**Dependencies:** Task 1.
**Files:** `core/evidence/registry.py`, `core/evidence/tests/test_registry_seal.py`.
**Scope:** S.

## Task 3: Signed-registry load + end-to-end verify
**Description:** `load_signed_registry(registry_path, seal_path, root_verify_key)`
(fail-closed) and `verify_sealed_manifest_with_signed_registry(...)` where registry-seal
failure dominates a valid manifest seal.
**Acceptance criteria:**
- [ ] Missing/malformed registry seal ⇒ RegistryError / UNTRUSTED (no raise to caller).
- [ ] End-to-end returns TRUSTED **iff** registry-seal verifies AND signer is trusted/not revoked.
- [ ] Bad registry seal + valid manifest seal ⇒ UNTRUSTED.
**Verify:** `./.venv/bin/python -m pytest core/evidence/tests/test_registry_seal.py -q` and full `core/`.
**Dependencies:** Task 2.
**Files:** `core/evidence/registry.py`, `core/evidence/tests/test_registry_seal.py`.
**Scope:** S–M.

## Task 4: Root-key pinning convention + docs
**Description:** Document how the root verify key is supplied/pinned (explicit param this
phase); update README; state non-goals (private-key custody, rotation, WORM).
**Acceptance criteria:**
- [ ] README documents the root-of-trust model, the pin, and the non-goals.
- [ ] No private-key storage introduced.
**Verify:** doc review; full `core/` suite green.
**Dependencies:** Task 3.
**Files:** `core/evidence/README.md`, spec cross-links.
**Scope:** XS–S.

---

## Checkpoints
- [ ] **After Task 1:** `test_seal.py` + full `core/` green (1C intact) → human review.
- [ ] **After Task 3:** SC1–SC5 green; end-to-end correct → human review.
- [ ] **After Task 4:** SC1–SC6 met; `/review` five-axis; ship only after green.
