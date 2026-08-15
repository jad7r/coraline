# Spec: Phase 1G1 — Registry Root of Trust

- **Status:** DRAFT — planning only, stop for review before implementation
- **Mode:** spec-driven · planning-and-task-breakdown · TDD (strict red-first) · security-and-hardening · source-driven
- **Depends on:** Phase 1C sealing (`core/evidence/seal.py`), Phase 1D registry (`core/evidence/registry.py`)
- **Closes gap:** G1 from `docs/specs/phase-1d-trusted-signer-registry.md` §8
- **Controlling decision:** [ADR-0002](../adr/0002-ai-independent-platform.md)

---

## 1. Objective (mini-spec)

**What / why.** The Phase 1D trusted-signer registry decides *which keys are trusted*, but
the registry file itself has **no root of trust**: anyone with write access can add a
consistent trusted entry or flip `revoked → trusted`, and verification still passes. The
`expected_hash` pin only relocates trust to "where is the pin stored?". Phase 1G1 anchors
registry integrity so **tampering is cryptographically detected**, without depending on a
caller remembering an out-of-band hash.

**Success criteria (testable).**
- SC1 A registry not carrying a valid root signature is **not trusted** (fail closed).
- SC2 Any change to a registry's contents or a signer's status **invalidates** its root
  signature (detects the G1 attack: add-entry, flip revoked→trusted).
- SC3 A registry signature made by a **non-root** key is rejected.
- SC4 A **manifest** seal cannot be replayed as a **registry** seal (domain separation).
- SC5 End-to-end: a manifest verifies as TRUSTED **only if** (a) the registry's root
  signature verifies against the pinned root key **and** (b) the manifest seal verifies
  against a trusted, non-revoked entry in that registry. Registry-seal failure dominates.
- SC6 The only thing a deployment must pin is a **small, stable root *public* key** — not
  the whole mutable registry file.

**Tech.** Python 3, stdlib + PyNaCl (already present). Reuses `seal.py` detached-seal
machinery and `signing.py` Ed25519 primitives. Local/offline. No new dependencies.

**Commands.**
- Test (phase): `./.venv/bin/python -m pytest core/evidence/tests/test_registry_seal.py -q`
- Regression: `./.venv/bin/python -m pytest core/ -q`

---

## 2. Threat model (STRIDE over the registry trust boundary)

**Assets:** A1 the trust decision; A2 the registry file; A3 the root key pair.

| # | STRIDE | Threat | Mitigation (this phase) | Residual |
|---|---|---|---|---|
| T1 | Tampering | Add own consistent trusted entry to registry file | root signature over registry hash ⇒ invalid after edit (SC2) | requires root **private** key to forge |
| T2 | Tampering | Flip `revoked → trusted` (the G1 gap) | same — any content change breaks the signature | as T1 |
| T3 | Spoofing | Sign registry with attacker's own key | verify against **pinned root verify key** only (SC3) | root key must be authentically pinned |
| T4 | Spoofing | Replay a valid *manifest* seal as a *registry* seal | **domain separation** via `subject` field (SC4) | none within model |
| T5 | Repudiation | Deny who edited the registry | root signer identity in the seal payload | not a full audit log (G4, deferred) |
| T6 | DoS | Delete the registry or its seal | fail closed ⇒ nothing trusted (safe default) | availability loss; WORM (deferred) mitigates |
| T7 | EoP | Root private key compromise | — | **out of scope**; inherent PKI-root risk; rotation deferred |

**Abuse cases → first tests:** "attacker flips a revocation" → SC2 test; "attacker swaps in
their own signed registry" → SC3 test; "attacker reuses a manifest seal" → SC4 test.

---

## 3. Trust boundaries

```
pinned ROOT verify key  ──anchors──▶  registry root-seal
                                            │ verifies integrity+origin of
                                            ▼
                                      signer registry  ──▶ per-signer trust
                                            │
manifest ── seal (signer key) ──────────────┴──▶ VerificationResult
```
- **New boundary (this phase):** *pinned root key ↔ registry*. Crossed by an Ed25519
  signature over the registry's canonical hash. This replaces "trust the file" with "trust
  one small pinned public key + the secrecy of its private half."
- **Unchanged:** manifest↔seal (Phase 1C), seal↔signer-trust (Phase 1D).
- **What still must be trusted out-of-band:** the **root verify key** (public, small,
  stable) — pinned via an explicit parameter/config, not baked secretly. This is a strictly
  better anchor than pinning a whole file hash that changes on every signer add/revoke.

---

## 4. Options analysis

| Option | Mechanism | Pros | Cons | Verdict |
|---|---|---|---|---|
| **A. Signed registry (offline/root key)** | Ed25519 detached seal over the registry hash; verify against a pinned root verify key | Cryptographic tamper + origin detection; forging needs the root *private* key; reuses `seal.py`; root key can live offline | Introduces a root key to protect; bootstrapping needs the root *public* key pinned; root rotation is hard | **Core of recommendation** |
| **B. WORM / read-only storage** | Platform-enforced immutable store (GCS retention lock, OS immutability) | No keys; strong if platform truly enforces; aligns with WORM evidence goal | Infra-dependent; not local/offline pure-Python; OS perms bypassable by same-UID/root; doesn't stop *substitution* without an identity anchor; **explicitly deferred** | Defense-in-depth later, not sufficient alone |
| **C. Detached pinned hash stewardship** | Pin the known-good registry hash (already in 1D `expected_hash`) | Zero new crypto; already built; trivial | Relocates trust to "where's the pin + who updates it"; pin must change on *every* signer edit; brittle at scale | Keep as a fallback knob; insufficient as the anchor |
| **D. Hybrid (RECOMMENDED)** | **A** as primary + pin only the small stable **root public key** (C applied to the key, not the file) + **B** as optional defense-in-depth when available | Cryptographic integrity; best pin target (stable key vs mutable file); layered availability protection later | Root key custody + rotation remain (bounded, deferred) | **Recommended** |

---

## 5. Recommended architecture

**Root-signed registry, reusing the Phase 1C detached-seal pattern, with domain separation.**

1. **Domain separation (seal v2).** Generalize the seal payload so a signature is bound to
   *what it signs*: add `subject ∈ {"evidence-manifest","signer-registry"}` and rename
   `manifest_hash → content_hash`. `verify_seal` requires the expected `subject`. This
   prevents a manifest seal from being accepted as a registry seal (T4). *This touches the
   shipped Phase 1C format — flagged as an "Ask first" decision (see Open Questions).*
2. **Registry sealing** (thin composition over `seal.py`):
   - `seal_registry(registry, root_signing_key, *, signer, sealed_when)` →
     seal with `subject="signer-registry"`, `content_hash=registry.registry_hash()`.
   - `verify_registry_seal(registry, seal, root_verify_key)` → reuse `verify_seal` with the
     registry hash + `subject="signer-registry"`.
3. **Signed-registry load (fail closed):**
   - `load_signed_registry(registry_path, seal_path, root_verify_key) → TrustedSignerRegistry`
     — loads registry (1D strict parse), loads its seal, verifies against `root_verify_key`;
     raises `RegistryError` if the seal is missing/invalid. Only a root-verified registry is
     returned.
4. **End-to-end verification (fail closed):**
   - `verify_sealed_manifest_with_signed_registry(manifest, manifest_seal, registry_path,
     registry_seal_path, root_verify_key) → VerificationResult`. Registry-seal failure ⇒
     `UNTRUSTED` regardless of manifest-seal validity (SC5).
5. **Root key provisioning:** the root **verify** key is supplied explicitly (pinned by the
   caller/config). Where the root **private** key lives is **out of scope** (see §8).

This is almost entirely composition of existing primitives — the registry becomes "just
another sealable canonical document," consistent with how manifests are sealed.

---

## 6. Data model changes

**Seal payload → v2 (in `seal.py`, shared by manifest + registry):**
```
{ seal_version: "2",
  subject: "evidence-manifest" | "signer-registry",   # NEW — domain separation
  content_hash: "<sha256 hex>",                        # RENAMED from manifest_hash
  content_hash_algorithm: "sha256",
  signature_algorithm: "ed25519",
  signer: str,
  key_fingerprint: "SHA256:<hex>",
  sealed_at: "<ISO-8601 UTC>" }
signature: base64 over canonical_json(payload)
```
**Registry:** unchanged on disk (Phase 1D format). Its integrity now comes from a **detached
`<registry>.seal.json`** sibling (same seal v2 shape, `subject="signer-registry"`).
**No change** to `EvidenceItem`, `EvidenceManifest`, `SignerEntry`, `VerificationResult`.

---

## 7. Red-first TDD test plan

Strict red-first (P1 correction): each test is written and **observed failing** before the
code that satisfies it. New file `core/evidence/tests/test_registry_seal.py`; seal v2 changes
also update `core/evidence/tests/test_seal.py`.

| # | Test (RED first) | Asserts | SC |
|---|---|---|---|
| 1 | `test_valid_root_sealed_registry_loads` | root-sealed registry verifies & loads | SC1 |
| 2 | `test_missing_registry_seal_fails_closed` | no seal ⇒ RegistryError / UNTRUSTED | SC1 |
| 3 | `test_tampered_registry_breaks_seal` | flip revoked→trusted ⇒ registry seal invalid | SC2 |
| 4 | `test_added_entry_breaks_seal` | add trusted entry ⇒ registry seal invalid | SC2 |
| 5 | `test_non_root_key_rejected` | registry signed by non-root key ⇒ rejected | SC3 |
| 6 | `test_manifest_seal_not_accepted_as_registry_seal` | subject mismatch ⇒ reject | SC4 |
| 7 | `test_registry_seal_not_accepted_as_manifest_seal` | subject mismatch ⇒ reject | SC4 |
| 8 | `test_end_to_end_trusted_only_when_both_verify` | TRUSTED iff registry-seal ok AND signer trusted | SC5 |
| 9 | `test_registry_seal_failure_dominates_valid_manifest` | bad registry seal + valid manifest seal ⇒ UNTRUSTED | SC5 |
| 10 | `test_malformed_registry_seal_file_fails_closed` | garbage seal file ⇒ UNTRUSTED, no raise | SC1 |
| 11 | `test_seal_v2_manifest_roundtrip_still_verifies` | Phase 1C manifest sealing still works under v2 | regression |

Test doubles: real PyNaCl keys (fast, deterministic); no mocks. All tests **Small** (no I/O
beyond tempfiles). Coverage target: every new public function + every fail-closed branch.

---

## 8. Explicit non-goals

- **Root private key storage / custody** (HSM, keychain, offline media) — caller-supplied
  this phase; consistent with the Phase 1D private-key non-goal.
- **Root key rotation / re-keying** — only signer status/revocation exists; root rotation is
  a separate hard problem.
- **WORM / read-only enforcement** — recommended later as defense-in-depth (Option B).
- **Key enrollment / identity proofing** (G2), **time-scoped revocation** (G3), **audit
  logging** (G4) — tracked, later phases.
- **CLI, state machine, connectors, AI, network, presentation** — untouched.

---

## 9. Rollback plan

- **Task 2–4 are additive** (new `registry` seal functions + a new test file); rollback =
  delete them / `git revert` the commit. Nothing else imports them.
- **Task 1 (seal v2) touches shipped Phase 1C** — the only blast radius. Mitigations:
  gate behind `seal_version` bump; if problematic, revert to seal v1 and fall back to the
  **lower-blast-radius alternative** (a *separate* registry-seal module that never touches
  `seal.py`, accepting minor duplication).
- **Reset points:** Phase 1D `6cd7509`; restore point `c54cd6d`. No persisted production
  state or migrations to unwind.

---

## 10. Open questions (need human decision at review)

1. **Seal v2 domain separation touches shipped 1C** (rename `manifest_hash → content_hash`,
   add `subject`, bump to v2, update 8 tests). Approve this, or take the separate-module
   alternative to leave 1C untouched? *(Recommend: approve v2 — domain separation is a real
   security property and the change is small and fully tested.)*
2. **Root verify key pinning location** — explicit function parameter only (this phase), or
   also a documented config path (e.g., `~/.config/coreline/root_verify_key`)? *(Recommend:
   parameter now; config path when the CLI/interface phase lands.)*
3. **Registry seal file naming** — `<registry>.seal.json` sibling (consistent with manifest
   seals)? *(Recommend: yes.)*
