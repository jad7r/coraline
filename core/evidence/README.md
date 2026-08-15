# `core/evidence/` — evidence architecture

Owns evidence records and their integrity. Evidence integrity is a **core platform
capability** (ADR-0002 §5), layered:

1. **Baseline (deterministic, stdlib-only) — built (Phase 1B):** SHA-256 hashing
   (`hashing.py`), manifest generation (`manifest.py`), chain-of-custody (`custody.py`).
   Canonical deterministic JSON; a stable `manifest_hash()`. *(WORM preservation: later.)*
2. **Sealing (opt-in bridge) — built (Phase 1C, seal v2 in 1G1):** `seal.py` produces/verifies
   a **detached** Ed25519 seal that binds an artifact's hash to a signer's key, without
   embedding crypto in the artifact. Seal v2 adds a `subject`
   (`evidence-manifest` | `signer-registry`) for **domain separation** — a seal made for one
   artifact type cannot be replayed as a seal for another. Verification fails closed.
2b. **Trusted signer registry (opt-in bridge) — built (Phase 1D):** `registry.py` decides
   whether a valid signature is *trusted*. A local, deterministic-JSON registry maps a key
   fingerprint → signer entry (identity, verify key, status, created/revoked). Verification
   returns `TRUSTED | REVOKED | UNKNOWN | UNTRUSTED` and fails closed.
2c. **Registry root of trust (opt-in bridge) — built (Phase 1G1):** `registry.py`
   `seal_registry` / `verify_registry_seal` / `load_signed_registry` /
   `verify_sealed_manifest_with_signed_registry`. See the section below.
2d. **Rollback enforcement (opt-in bridge) — built (Phase 1G2):** a monotonic
   `sequence` in the registry's signed content plus a verifier `min_sequence` floor
   that rejects an older, validly-signed registry. Closes residual R2. See below.
3. **Cryptographic (`integrity/`):** PyNaCl — X25519 encrypted evidence bundles
   (`crypto.py`, `envelope.py`), Ed25519 signing (`signing.py`), key handling
   (`keystore.py`). Lifted from the prior secure enclave; local/offline first.

**Import purity:** `core.evidence.__init__` exports only the stdlib deterministic layer
(hashing/manifest/custody). `seal.py` is imported explicitly (`from core.evidence.seal
import …`) because it pulls in the crypto subsystem — this keeps the deterministic layer
dependency-free.

**Hard rule:** the integrity subsystem must never be coupled to WordPress, any CMS,
publishing, or a portal. Presentation is always a separate consumer so the crypto core
can be independently audited and reused.

---

## Registry root of trust (Phase 1G1)

**Problem.** A trusted-signer registry (Phase 1D) says *which keys are trusted*, but the
registry file has no root of trust: anyone with write access could add a self-consistent
trusted entry or flip `revoked → trusted` and verification would still pass.

**Model.** The registry is anchored by a **detached root Ed25519 signature** over its
canonical `registry_hash()`, produced with a **root key whose role is distinct from the
per-signer keys** inside the registry. The seal is a separate `<registry>.seal.json`
document (`subject="signer-registry"`); the registry file itself is never modified. A
manifest is `TRUSTED` only if **(a)** the registry's root seal verifies against the pinned
root key **and** **(b)** the manifest seal verifies against a trusted, non-revoked signer
in that registry — **registry-seal failure dominates** a valid manifest seal.

**The pin (the one thing you must trust out-of-band).** The **root *verify* key** is
supplied by the caller and is never read from the registry or the seal (an embedded,
self-describing anchor would be forgeable). Pinning a small, stable root *public* key is a
strictly better trust anchor than pinning a whole mutable registry-hash. Provisioning:

```python
root_vk = decode_verify_key(PINNED_ROOT_VERIFY_KEY_B64)   # from code/config, pinned once
res = verify_sealed_manifest_with_signed_registry(
    manifest, manifest_seal, "registry.json", "registry.seal.json", root_vk)
assert res.trusted   # else UNTRUSTED / REVOKED / UNKNOWN, fail-closed
```

**Operational hygiene.** Keep the root key **out of the signer set** (role separation), so
revoking a signer never touches the trust anchor. Using one key as both is permitted and
not a confused-deputy risk (domain separation blocks manifest↔registry seal reuse), but
separating the roles keeps the blast radius small.

**Explicit non-goals (this phase).**
- **Root *private* key storage / custody** — the caller supplies the signing key; keep it
  offline/air-gapped. Not stored by this module.
- **Root key rotation / re-keying** — only signer status/revocation exists.
- **WORM / read-only enforcement** — recommended later as defense-in-depth.
- Key enrollment / identity proofing (who owns a key); audit logging of edits/verifications;
  CLI, state machine, connectors, AI, network, presentation.

**Residual risks (documented, not closed here).** R1 root private-key custody & rotation;
R3 anchor authenticity depends on correct out-of-band pinning of the root public key;
R4 no audit log of registry edits / verify decisions. (R2 rollback/replay is closed by
Phase 1G2 below when a real floor is supplied.)

Full spec: `docs/specs/phase-1g1-registry-root-of-trust.md`.

## Rollback enforcement (Phase 1G2)

**Problem (residual R2).** The root seal proves a registry is *authentic* but not *fresh*.
An attacker with write access can restore an **older, still-validly-root-signed**
`(registry, seal)` pair — e.g. from before a key was revoked — and it verifies. The
revocation is undone **without ever touching the root private key** (a classic downgrade
against any detached-signature-without-monotonic-state design).

**Model.** The registry carries a **monotonic integer `sequence`** inside its canonical
form, so it is covered by `registry_hash()` and therefore by the root seal (tamper-evident
inherited from 1G1). The author advances it with `registry.bump(n)` — a **strictly-
increasing** guard — **once per signed revision**; ordinary edits (`add_signer`/`revoke`)
deliberately do *not* auto-advance it. Every verify entry point takes an optional
`min_sequence` **floor** and rejects, fail-closed, any registry whose `sequence` is below
it — before returning trust:

```python
res = verify_sealed_manifest_with_signed_registry(
    manifest, manifest_seal, "registry.json", "registry.seal.json", root_vk,
    min_sequence=CURRENT_FLOOR)   # reject anything older than CURRENT_FLOOR
assert res.trusted   # else UNTRUSTED — reason "registry sequence N below floor M"
```

A monotonic integer is chosen over a `generated_at`/TTL timestamp on purpose: a timestamp
is attacker-replayable and clock-dependent; a monotonic counter gives unambiguous ordering.

**The floor is the new thing you must supply (mechanism vs policy).** This phase ships the
*mechanism* — the `sequence` field and the `min_sequence` parameter. It deliberately does
**not** invent a new local store for the authoritative floor (that would recurse the same
rollback problem). Pin the floor where you already pin trust: alongside the root verify key
in the trust store, **or** derive it from the WORM-latest generation — write each revision
under a unique, sequence-suffixed name (`registry/registry-<sequence>.json`) into the
retention-locked bucket (Phase 1H) and take the **highest sequence** present as the floor.
Because the bucket is immutable and undeletable, an attacker cannot delete newer revisions
to lower that maximum. Deriving the floor from the max-sequence object is auditor-side
(a 1H follow-on, out of scope here).

**Backward-compat.** `from_dict` defaults a missing `sequence` to 0, and every
`min_sequence` defaults to 0 — so existing registries and callers are unchanged and get
**no** rollback protection until they pass a real floor. A floor > 0 rejects a sequence-0
(legacy, pre-sequence) registry rather than silently trusting it.

**Explicit non-goals (this phase).** *Storage* of the authoritative floor (WORM-latest read
/ pinned trust store) — mechanism only; the floor's trusted source is auditor/1H
integration. Also excluded: root key custody/rotation (R1), audit logging (R4), auditor
read-from-GCS tooling, and time-based freshness (`generated_at`/TTL, rejected above).

**Residual (documented).** Rolling back the **floor itself** is out of scope — the floor
must live in a trusted/pinned/WORM source (R3-adjacent). The mechanism is only as strong as
that floor's source.

Full spec: `docs/specs/phase-1g2-rollback-enforcement.md`.
