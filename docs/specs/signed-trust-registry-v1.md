# Signed trust-registry releases v1

## Purpose and threat model

Coreline snapshots and independent-anchor receipts identify Ed25519 signing keys.
A mutable public-key file cannot prove which keys were authorized after rotation or
revocation. Signed registry releases provide an authenticated, monotonic history of
that authorization state.

V1 detects modified, removed, reordered, substituted, duplicated, cross-registry,
and conflicting releases; status rollback; reactivation of retired/revoked keys;
self-signed attacker registries; untrusted roots; bundle rollback; and local release
rollback when an independently retained expected tip remains newer.

It does not protect against compromise of the pinned registry root, compromise of
both local and expected-tip storage, malicious authorized releases, destruction of
all copies, denial of service, or false operator transition reasons. Release time is
signed metadata, not independently trusted time. This is a narrow public-key trust
history rather than generic PKI, IAM, certificates, secrets management, or consensus.

## Root and trust chain

```text
independently pinned registry root public key
                    |
                    v
        R1 --------> R2 --------> R3
                                 |
                ACTIVE / RETIRED / REVOKED keys
                    |                     |
                    v                     v
          authenticated snapshots   anchor receipts

        independently retained expected registry tip = R3
```

The root pin contains `registry_id`, root key ID, and public verification key. It
must be distributed and protected independently of releases and incident data. A
release never authenticates its own root. The default pin under `home/trust` is a
deployment convenience; high-assurance deployments should set `CORELINE_TRUST_ROOT`
to read-only, separately managed material.

Registry-root private keys and artifact private keys stay outside Coreline home.
Releases and portable bundles contain public material only.

## Canonical release format

Each envelope is `{payload, signature}`. The payload contains exactly:

```text
domain = "coreline.trust-registry-release.v1"
schema_version = 1
registry_id
generation
release_id
previous_release_id | null
previous_release_digest | null
created_at
created_by
transition = {kind, reason}
keys[]
root_key_id
signature_algorithm = "ed25519"
```

Each key record binds `key_id`, `purpose` (`SNAPSHOT_SIGNER` or
`ANCHOR_SIGNER`), scope (`default` or anchor ID), operator identity, public key,
status, introduction generation, status generation, and reason. Key ID is the
existing Ed25519 public-key fingerprint. Release ID is SHA-256 of the canonical
payload without `release_id`; predecessor digest covers the complete predecessor
envelope.

Canonical bytes reuse Snapshot v1: UTF-8 JSON, sorted keys, compact separators,
unescaped Unicode, finite JSON values, and duplicate-key rejection. Ed25519 signs:

```text
b"coreline.trust-registry-release.v1\x00" + canonical(payload)
```

This differs from snapshot, evidence seal, anchor-receipt, and expected-tip domains,
preventing cross-protocol signature reuse.

## Chain and concurrency

Generations begin at one and are contiguous. Every successor authenticates the
previous release ID and full-envelope digest. Keys cannot disappear or change
identity. A new key enters ACTIVE at its introduction generation. Allowed transitions
are ACTIVE→RETIRED, ACTIVE→REVOKED, and RETIRED→REVOKED. RETIRED or REVOKED can
never return to ACTIVE in the same registry.

Creation holds both an in-process mutex and POSIX advisory file lock, verifies the
entire chain, and publishes with exclusive atomic creation. Equivalent concurrent
requests converge on the same release. Conflicting successors cannot both occupy a
generation through Coreline. Filesystem advisory-lock guarantees still depend on
the underlying filesystem.

## Expected registry tip

`CORELINE_TRUST_EXPECTED_TIP` identifies a separately administered directory. Each
release can publish a separately domain-signed fixed-generation tip record binding
registry identity, generation, release ID/digest, and root identity. Tip history is
append-only; there is no mutable head.

Relations are `MATCH`, `LOCAL_AHEAD_OF_EXPECTED`, `LOCAL_BEHIND_EXPECTED`,
`LOCAL_MISSING`, `DIVERGED`, `LOCAL_INVALID`, `NOT_PRESENT`, and `NOT_CONFIGURED`.
Behind/diverged/invalid expected-tip results fail registry health whenever present.
`--require-expected-tip` additionally requires an available exact match. Thus an
attacker restoring authentic Release 19 after Release 21 revoked key X is detected
while the external tip still remembers Release 21.

A filesystem tip directory on the same host is not necessarily an independent
security domain. Deletion of the newest release and newest tip by an attacker
controlling both locations remains undetectable. The fixed record format can be
adapted to GCS conditional-create objects without changing release semantics; v1
does not silently reuse incident anchor credentials or create recursive trust.

## Key lifecycle and artifact verification

- **ACTIVE**: cryptographically verifies existing artifacts and authorizes new
  signatures through Coreline creation APIs (`TRUSTED_ACTIVE`).
- **RETIRED**: cryptographically verifies historical artifacts but creation APIs
  reject the private key (`SIGNED_BY_RETIRED_KEY`).
- **REVOKED**: signatures can remain mathematically correct, but trusted verification
  fails and reports `SIGNED_BY_REVOKED_KEY`. Revocation preserves the public key,
  boundary generation, and reason.
- **UNKNOWN**: no matching purpose/scope/key exists (`UNKNOWN_KEY`).
- A bad signature remains `INVALID_SIGNATURE`, distinct from key authorization.

Snapshot verification resolves each historical snapshot key through the newest
valid registry, allowing an A→B rotation while verifying the existing chain. New
snapshots require the ACTIVE `SNAPSHOT_SIGNER/default` key. Anchor ledgers resolve
each receipt by key ID, so old receipts survive anchor rotation while only the
ACTIVE key for that anchor scope can append.

Snapshot v1 and anchor-receipt v1 predate registry releases and do not embed a
registry generation. Coreline can prove their signature and current key
qualification, and its authoritative creation APIs enforce current ACTIVE status.
The artifact alone cannot prove which release was current at its claimed creation
time. External snapshot/receipt anchoring limits backdating opportunities but does
not remove this format limitation. A future artifact schema may bind release ID
directly; v1 does not rewrite historical artifacts.

## Rotation, revocation, and sealing

Rotation publishes one release that retires A and introduces B ACTIVE for the same
purpose/scope. There is never more than one ACTIVE key per slot. Sealing uses the
same SnapshotStore and AnchorManager authorization checks: retired or revoked keys
cannot produce the final snapshot or required anchor receipt. Existing sealing and
checkpoint ordering remain unchanged.

Revocation is a security qualification, not deletion or retirement. Any snapshot or
receipt chain containing a now-revoked signer fails trusted verification while
retaining enough data for forensic analysis.

## Bootstrap, migration, and recovery

Bootstrap is explicit: an operator generates a root outside Coreline home, pins its
public key independently, and publishes R1. Existing installations remain in legacy
pin mode while no signed-registry root exists. Once a root exists, the signed
registry is authoritative and all legacy snapshot and configured anchor keys that
must remain trusted must be explicitly imported in authenticated releases. Coreline
does not silently convert mutable pin files.

Loss or compromise of the registry root cannot be repaired with cryptographic
continuity unless an already-authorized recovery authority exists; v1 defines none.
Recovery therefore creates a new registry/root using `--trust-reset-from` plus
`--acknowledge-broken-continuity`. R1 is marked `TRUST_RESET` and records that
continuity is not claimed. Exclusive root-pin creation prevents this command from
silently overwriting an existing trust root. Preserve the old bundle and expected
tip for audit, then distribute the new pin through an independently governed path.

## Portable bundle and import

An exported bundle contains registry identity, root key ID/public key, and the
complete signed release chain. It contains no private keys or credentials. Import
first requires the bundled root to match the independently pinned local root, then verifies every
signature, identity, generation, transition, and predecessor against the already
pinned local root before publication. It accepts an identical prefix plus newer
successors. Older bundles and any conflict with local history are rejected. The
public root may accompany an audit package for portability, but import never trusts
a root supplied only by the bundle.

## Operations

```bash
coreline trust init --registry-id org-main --private-key /secure/registry-root.key \
  --actor security --expected-tip /independent/coreline-registry-tips
coreline trust key add --public-key snapshot.verify.json \
  --purpose SNAPSHOT_SIGNER --scope default --identity snapshot-2026 \
  --root-key /secure/registry-root.key --actor security
coreline trust key rotate --old-key-id SHA256:... --public-key snapshot-next.verify.json \
  --identity snapshot-2027 --reason "scheduled rotation" \
  --root-key /secure/registry-root.key --actor security
coreline trust key revoke --key-id SHA256:... --reason "suspected compromise" \
  --root-key /secure/registry-root.key --actor security
coreline trust status --require-expected-tip
coreline trust export --output trust-bundle.json
```

`verify` and `doctor` include registry chain health. Legacy installations with no
root report `NOT_PRESENT` and remain compatible. A present malformed, rolled-back,
or cryptographically invalid registry fails trusted verification. Expected-tip
provider unavailability is distinct from invalid signed data; required freshness is
never reported VALID when unknown.
