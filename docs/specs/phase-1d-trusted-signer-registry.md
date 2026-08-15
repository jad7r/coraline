# Phase 1D — Trusted Signer Registry · Spec & Review Gate

- **Status:** RETROSPECTIVE (code already implemented in commit `6cd7509`; this doc applies
  the workflow-pack discipline to validate or reject it)
- **Mode:** spec-driven · TDD · security-and-hardening · source-driven · review-before-commit
- **Depends on:** Phase 1C sealing (`core/evidence/seal.py`, commit `4547b91`)
- **Controlling decision:** [ADR-0002](../adr/0002-ai-independent-platform.md)

> **Reconciliation note.** Phase 1D was implemented before this operating-mode switch was
> received. This document reconstructs the spec it *should* have been built from and
> reviews the delivered code against it. Verdict and gaps are in §8.

---

## 1. Mini-spec

**Goal.** Turn "this seal has a valid signature" into "this seal was made by a *trusted*
signer." Phase 1C proves a key signed a manifest hash; it does not say whether that key is
one Coreline trusts. 1D supplies that trust decision, locally and offline.

**In scope**
- A local trusted-signer registry: signer identity, Ed25519 verify key, key fingerprint,
  status, `created_at`, optional `revoked_at`.
- Verification of a sealed manifest *against the registry* (not a caller-supplied key).
- Outcomes: **TRUSTED**, **REVOKED**, **UNKNOWN**, plus **UNTRUSTED** for everything else.

**Out of scope (explicit).** Private key storage; key rotation beyond status/revocation;
WORM storage; CLI; audit log; state machine; connectors; AI; network; presentation.

**Functional requirements**
- FR1 Registry stores the six fields above per signer, keyed by key fingerprint.
- FR2 `verify_against_registry(manifest, seal, registry) → VerificationResult`.
- FR3 A file-level helper loads a registry from disk and verifies, failing closed on any
  load/parse problem.
- FR4 Support pinning a known-good registry hash to detect on-disk tampering.

**Non-functional requirements**
- NFR1 Deterministic canonical JSON (sorted keys, entries sorted by fingerprint).
- NFR2 Fail-closed: any structural/decoding/consistency/signature error ⇒ non-TRUSTED.
- NFR3 Local/offline only; no network; no presentation dependency.
- NFR4 Stays out of `core.evidence.__init__` so the deterministic layer remains stdlib-only.

**Acceptance:** the six required test cases (§5) pass, plus determinism and round-trip;
full `core/` suite green.

---

## 2. Threat model

Assets: (A1) the trust decision itself; (A2) the registry file; (A3) signer verify keys.

| # | Threat | Vector | Mitigation (delivered) | Residual risk |
|---|---|---|---|---|
| T1 | Forged seal by untrusted key accepted | attacker signs with own key | fingerprint not in registry ⇒ UNKNOWN; fail closed | none within model |
| T2 | Use of a compromised/retired key | old key still presents seals | `revoke()` + REVOKED outcome | revocation is not time-scoped (see §8 G3) |
| T3 | Swapped-key registry tamper | edit entry's `verify_key`, keep fingerprint index | verify recomputes `fingerprint(verify_key)` and checks ⇒ UNTRUSTED "fingerprint mismatch" | none for *inconsistent* edits |
| T4 | Consistent registry tamper | attacker adds own consistent trusted entry, or flips `revoked→trusted` | `expected_hash` pin ⇒ UNTRUSTED on any change | **unmitigated without a pin / WORM / signed registry (G1)** |
| T5 | Malformed/corrupt registry causes crash or fail-open | bad JSON, missing fields, bad key | strict `from_dict`; file helper catches → UNTRUSTED | none |
| T6 | Manifest altered after sealing | swap evidence post-seal | reuse of `verify_seal` ⇒ manifest-hash mismatch | none |
| T7 | Signer impersonation (key ≠ person) | enroll attacker key as "alice" | — | **out of scope; no enrollment/identity proofing (G2)** |

---

## 3. Trust boundaries

```
[evidence files] --hash--> [manifest (deterministic, stdlib)]  ── trust boundary 1 ──>
[seal: signature over manifest_hash]  ── trust boundary 2 ──>
[registry: which fingerprints are trusted]  ==> VerificationResult
```
- **TB1 manifest↔seal:** crossed by cryptographic signature (Phase 1C). Fail-closed.
- **TB2 seal↔trust:** crossed by the registry lookup (Phase 1D). The registry is the
  **trust anchor**. Its integrity is only as strong as the file — pinning/WORM/signing is
  what actually anchors it (the load-bearing residual, §8 G1).
- **Process boundary:** none — all in-process, local, offline. No network or IPC.
- **Key custody boundary:** private signing keys are NOT handled here (out of scope);
  only public verify keys are stored.

---

## 4. Data model

```
SignerEntry (frozen):
  signer: str                 # descriptive identity (NOT authenticated)
  verify_key: str             # base64 Ed25519 public key
  key_fingerprint: str        # "SHA256:<hex>"  — registry index / claim
  status: "trusted"|"revoked"
  created_at: str             # ISO-8601 UTC
  revoked_at: str | null

TrustedSignerRegistry:
  version: "1"
  entries: {fingerprint -> SignerEntry}      # sorted by fingerprint on serialize
  registry_hash() = sha256(canonical_json(to_dict()))

VerificationResult (frozen):
  outcome: TRUSTED|REVOKED|UNKNOWN|UNTRUSTED
  signer: str|null
  reason: str
  .trusted -> outcome is TRUSTED
```
On-disk registry = canonical JSON; `sha256(file) == registry_hash()`. `from_dict` validates
structure only (fields/types/status/decodable key); fingerprint↔key *consistency* is
enforced at verify time so a tampered entry surfaces as UNTRUSTED.

---

## 5. Test plan (TDD — required cases → delivered tests)

| Required case | Test (`core/evidence/tests/test_registry.py`) | Expected |
|---|---|---|
| trusted signer succeeds | `test_trusted_signer_succeeds` | TRUSTED |
| unknown signer fails | `test_unknown_signer_fails` | UNKNOWN |
| revoked signer fails | `test_revoked_signer_fails` | REVOKED |
| fingerprint mismatch fails | `test_fingerprint_mismatch_fails` | UNTRUSTED |
| tampered registry entry fails | `test_tampered_registry_entry_fails_when_pinned` | UNTRUSTED (pinned) |
| malformed registry fails closed | `test_malformed_registry_fails_closed` | UNTRUSTED + RegistryError |
| (extra) determinism | `test_deterministic_regardless_of_add_order` | equal JSON/hash |
| (extra) persistence | `test_save_load_roundtrip` | stable hash |

Delivered result: **8 passed; full `core/` suite 79 passed.**
TDD honesty note: tests were written *alongside* the module in the same phase, not strictly
red-first — flagged as a process gap for this retrospective (§8 P1).

---

## 6. Implementation plan (as delivered; would-be small phases)

Single module `core/evidence/registry.py` reusing Phase 1C `verify_seal`:
1. `SignerEntry` + strict `from_dict`.
2. `TrustedSignerRegistry` (add/revoke/get, canonical `to_dict`/`to_json`/`registry_hash`).
3. `save_registry`/`load_registry` (+ `expected_hash` pin).
4. `verify_against_registry` / `verify_with_registry_file` (fail-closed).
Kept out of `__init__` (opt-in crypto-bound import). No changes to seal/manifest/crypto.

---

## 7. Rollback plan

1D is **purely additive and unreferenced by any prior module** (`__init__` untouched;
seal/manifest/crypto unchanged). Rollback is therefore clean and side-effect-free:
- **Full revert:** `git revert 6cd7509` (or `git reset --hard 4547b91` to land back on
  Phase 1C). No data migrations, no schema in use elsewhere, no persisted production state.
- **Partial:** delete `core/evidence/registry.py` + `tests/test_registry.py` and the README
  stanza; nothing else imports them.
- **Restore point** `c54cd6d` remains the ultimate fallback.

---

## 8. Review verdict & gaps

**Verdict:** the delivered 1D **meets the functional spec and all six required cases**, is
deterministic, offline, and fail-closed. Recommend **accept**, with the following tracked
gaps (none require reverting 1D; they are follow-on work):

- **G1 (High) — registry integrity has no root of trust.** Consistent tampering (add a
  trusted entry; flip revoked→trusted) is undetectable without an `expected_hash` pin, and
  the pin just relocates the trust question. Needs a signed registry or WORM/read-only
  storage. *This is the load-bearing gap.*
- **G2 (High) — no key enrollment / identity proofing.** `signer` is unauthenticated
  metadata; nothing binds a key to a real person.
- **G3 (Med) — revocation is not time-scoped.** A seal made while a key was trusted fails
  identically to one made after revocation (no `revoked_at` vs `sealed_at` comparison).
- **G4 (Med) — no observability.** Registry edits (add/revoke) and verify decisions emit no
  events/logs. (Audit log is out of scope, but per the observability discipline this should
  be designed for now and wired when the audit phase lands.)
- **P1 (Process) — tests were not strictly red-first.** Written same-phase as code; future
  phases run true TDD (failing test committed/observed first).

---

## Decision requested
Accept 1D as-is with G1–G4/P1 tracked as follow-on phases? Or roll back and re-run 1D
strictly test-first? Recommend **accept + schedule G1 (registry root of trust) as the next
phase**.
