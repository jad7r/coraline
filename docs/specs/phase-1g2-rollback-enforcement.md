# Spec: Phase 1G2 — Signed-Registry Rollback Enforcement

- **Status:** IMPLEMENTED & reviewed (five-axis + adversarial security, both APPROVE) — R2 closed
  when a real floor is supplied. Shipped green (144 passed, 1 skipped).
- **Mode:** spec-driven · source-driven · TDD (red-first) · security-and-hardening
- **Depends on:** Phase 1G1 (registry root of trust), composes with Phase 1H (WORM storage)
- **Closes residual:** **R2** (signed-registry rollback/replay), confirmed by both 1G1 and 1H
  security audits as the highest-value remaining hardening.
- **Controlling decision:** [ADR-0002](../adr/0002-ai-independent-platform.md)

---

## 1. Objective (mini-spec)

**The gap.** A root-signed registry (1G1) proves *authenticity* but not *freshness*. An
attacker with write access can restore an **older, still-validly-root-signed** `(registry,
seal)` pair — e.g. from before a key was revoked — and it verifies. The revocation is undone
**without the root private key.** Both audits reproduced this (a classic downgrade against
any detached-signature-without-monotonic-state design).

**The fix.** Bind a **monotonic `sequence`** inside the registry (so it's covered by
`registry_hash()` and therefore by the root seal), and have the verifier **reject any
registry whose `sequence` is below a trusted floor.**

**Success criteria (testable).**
- SC1 `sequence` is part of the registry's canonical form → any change to it breaks the root
  seal (tamper-evident, inherited from 1G1).
- SC2 Verification with a floor **rejects** a registry whose `sequence < min_sequence`
  (fail-closed), and **accepts** `sequence >= min_sequence`.
- SC3 Rollback replay is defeated: an old validly-signed registry (lower sequence) presented
  against a floor at the newer sequence → **UNTRUSTED/REVOKED preserved**, not un-revoked.
- SC4 Monotonic authoring: `add_signer`/`revoke` (registry mutations) advance the sequence;
  a helper enforces strictly-increasing sequence.
- SC5 Backward-compatible parse: a registry dict lacking `sequence` loads with a defined
  default (0) rather than raising — but a floor > 0 then rejects it (no silent trust).
- SC6 **No new trust anchor invented:** the floor is caller-supplied (pinned alongside the
  root key, or derived from the WORM-latest generation); this phase provides the *mechanism*,
  not the floor's storage.

---

## 2. Source-Driven Findings

Current `core/evidence/registry.py`: `TrustedSignerRegistry` has `version` + `entries`;
`to_dict()` → `{version, signers[...]}`; `registry_hash()` = sha256 of canonical. Root seal
(1G1) signs that hash. **No sequence/ordering exists.** Adding `sequence` to `to_dict()` is
the minimal change that makes it signed content.

Prior art: the legacy WordPress directory (1G1 findings) used `generated_at` + TTL for
*network cache freshness* — **discard** (timestamp is attacker-replayable and clock-
dependent; TTL is a network concern we don't have). A **monotonic integer sequence** is the
correct primitive for anti-rollback.

1H composition (corrected — no versioning): each registry revision is written under a
**unique, sequence-suffixed name** (`registry/registry-<sequence>.json`) into the
retention-locked bucket, so every past revision is immutable and undeletable. The auditor
(which has read/list; the app is write-only) lists the registry objects and takes the
**highest sequence** as the floor — and an attacker cannot delete newer revisions to lower
that max. This phase makes the registry *carry* the sequence and the verifier *enforce* a
floor; deriving the floor from the max-sequence object is auditor-side (1H follow-on).

---

## 3. Threat Model (delta)

| STRIDE | Threat | Mitigation (this phase) | Residual |
|---|---|---|---|
| Tampering | Edit `sequence` in the file | covered by root seal (SC1) — breaks signature | needs root key to forge |
| **Spoofing/Replay** | **Restore an old validly-signed `(registry,seal)` to un-revoke a key** | **sequence floor rejects `sequence < min` (SC2/SC3)** | only as strong as the floor's source (below) |
| Tampering | Present a registry with no `sequence` to dodge the check | default 0 + floor > 0 rejects (SC5) | — |
| EoP | Roll back the **floor** itself | out of scope — floor must live in a trusted/pinned/WORM source (R3-adjacent) | documented residual |

**Abuse case → first test:** "attacker replays yesterday's registry (bob TRUSTED) after bob
was revoked (sequence bumped)" → SC3 test: floor at the new sequence rejects the old one.

---

## 4. Design Decisions — Legacy → Proposed → Rationale

- **D1 Freshness primitive.** *Legacy:* none (or `generated_at`+TTL in the WP directory).
  *Proposed:* a **monotonic integer `sequence`** in the registry's signed content.
  *Rationale:* unambiguous ordering; not clock-dependent; not replayable like a timestamp.
- **D2 Enforcement.** *Legacy:* any validly-signed registry trusted. *Proposed:* verifier
  takes an optional `min_sequence` floor and rejects `sequence < min_sequence` (fail-closed),
  before returning trust. *Rationale:* defeats replay of an older signed registry.
- **D3 Floor source (mechanism vs policy).** *Proposed:* the floor is **caller-supplied** —
  pinned in the trust store next to the root key, or read from the WORM-latest generation
  (1H). This phase ships the *mechanism* (`min_sequence` param + sequence field); the
  authoritative floor *storage* is out-of-band/auditor. *Rationale:* avoid inventing a new
  mutable local anchor that recurses the same rollback problem; reuse existing trusted anchors.
- **D4 Backward-compat parse.** *Proposed:* `from_dict` defaults `sequence` to 0 when absent;
  authoring always sets/advances it. *Rationale:* doesn't break existing registries/tests,
  yet a floor > 0 still rejects a legacy no-sequence registry (no silent trust).
- **D5 Monotonic authoring.** *Proposed:* mutations (`add_signer`/`revoke`) advance the
  sequence; a guard rejects a non-increasing set. *Rationale:* the floor is only meaningful if
  authoring actually increments.

---

## 5. Data model / API delta

```
TrustedSignerRegistry:
  + sequence: int = 0                         # monotonic; part of to_dict() → signed by root seal
  to_dict() -> {version, sequence, signers}   # sequence now in canonical form
  + bump(sequence: int)                       # set to a strictly-greater value (guarded)
  add_signer(...) / revoke(...)               # advance sequence (or require explicit bump)
  from_dict(d): sequence = int(d.get("sequence", 0))   # backward-compatible default

verify_registry_seal(registry, seal, root_vk, *, min_sequence: int = 0) -> (ok, reason)
verify_against_registry(..., *, min_sequence: int = 0) -> VerificationResult
load_signed_registry(registry_path, seal_path, root_vk, *, min_sequence: int = 0)
verify_sealed_manifest_with_signed_registry(..., *, min_sequence: int = 0)
   # reject (fail-closed, reason "registry sequence N below floor M") when sequence < min
```

---

## 6. Test plan (red-first)

Extend `core/evidence/tests/test_registry_seal.py` (+ maybe `test_registry.py` for the
data-model bits).

| # | Test | SC |
|---|---|---|
| 1 | `sequence` appears in `to_dict()` and changing it changes `registry_hash()` | SC1 |
| 2 | tampering `sequence` in a sealed registry breaks the root seal | SC1 |
| 3 | `verify_*` with `min_sequence=N` accepts `sequence==N` and `sequence>N` | SC2 |
| 4 | `verify_*` with `min_sequence=N` rejects `sequence<N` (fail-closed, clear reason) | SC2 |
| 5 | **rollback replay:** old registry (seq 1, bob trusted) vs floor 2 (bob revoked) ⇒ rejected | SC3 |
| 6 | `add_signer`/`revoke` advance the sequence; `bump` rejects a non-increasing value | SC4/SC5 |
| 7 | `from_dict` of a dict without `sequence` defaults to 0; floor 1 then rejects it | SC5 |
| 8 | default `min_sequence=0` preserves existing behavior (no floor ⇒ no rollback protection) | compat |

---

## 7. Implementation plan (vertical slices — for review)

```
Task 1 registry data model: sequence field + to_dict + from_dict default + bump/advance guard
   └─▶ Task 2 verify-side floor: min_sequence on verify_registry_seal / verify_against_registry /
              load_signed_registry / verify_sealed_manifest_with_signed_registry (fail-closed)
          └─▶ Task 3 docs (README root-of-trust section) + note the floor-source options
```
Checkpoint after Task 2 (SC1–SC5 green) → human review; final `/review` + security audit.

## 8. Rollback plan
Additive + backward-compatible (`sequence` defaults to 0; `min_sequence` defaults to 0 = old
behavior). Touches shipped `registry.py` — mitigated by the default-off floor and full test
migration. Reset points: 1H `456d372`; 1G1 `9dc157d`; `c54cd6d`.

## 9. Explicit non-goals
- **Storage of the authoritative floor** (WORM-latest read / pinned trust store) — mechanism
  only this phase; the floor's trusted source is auditor/1H-integration, out of scope.
- Root key custody/rotation; audit logging; auditor read-from-GCS tooling; CLI/state/AI.
- Time-based freshness (`generated_at`/TTL) — rejected in favor of monotonic sequence.

## 10. Open questions (for review)
1. **Advance sequence automatically on `add_signer`/`revoke`, or require an explicit
   `bump()`** at authoring time? *Recommend: explicit `bump()`* — registry edits are often
   batched (add several signers, then re-sign once); auto-increment-per-mutation would inflate
   the sequence and muddy "one signed revision = one sequence." Author bumps once per signed revision.
2. **Floor default** — `min_sequence=0` (backward-compatible, no protection unless a floor is
   passed)? *Recommend: yes*, with docs strongly urging callers to pass a real floor.
3. Include an advisory `generated_at` in the registry as *metadata only* (never trusted for
   ordering)? *Recommend: skip* to avoid implying it's a freshness control.
