# Independent snapshot anchors and expected-tip policy v1

## Problem and threat model

Authenticated snapshots prove that locally available checkpoint content was signed.
They cannot alone reveal deletion of a valid tail. If local history once held
`S1 → S2 → S3`, an attacker controlling the incident directory can delete `S3`
and restore state for `S2`; the remaining local chain is internally consistent.

An anchor retains a signed acknowledgement of `S3` in another configured storage
domain. Coreline then reports `LOCAL_BEHIND_EXPECTED`: expected `S3`, observed `S2`.
V1 also detects local chain substitution/divergence, missing local snapshots,
removed intermediate receipts, receipt modification/substitution, cross-incident
reuse, unknown anchor keys, malformed/conflicting receipts, and stale local receipt
caches while the external ledger remains available.

V1 does not protect against compromise of both domains, the anchor or snapshot
private keys, a malicious authorized anchor operator, a compromised signing host,
destruction of all independent receipts, filesystem denial of service, or anchor
unavailability. `acknowledged_at` is signed anchor metadata, not independently
trusted time. This is not consensus, legal nonrepudiation, or transactional storage.

## Trust domains

```text
                 LOCAL INCIDENT DOMAIN

Incident state -> signed Snapshot S3 -> S1 -> S2 -> S3
                                             |
                                identifiers and digests only
================================ TRUST BOUNDARY ================================
                                             |
                                             v
                                 Filesystem anchor adapter
                                             |
                                  signed Receipt R3
                                             |
                            R1 -> R2 -> R3 / expected S3
```

Incident records remain authoritative. Snapshots are authenticated checkpoints.
Receipts acknowledge checkpoints; they never authorize or mutate evidence,
Subjects, Observations, Claims, Actions, Decisions, lifecycle, audit, or snapshots.
The CLI and reports call core APIs and contain no independent verification rules.

The filesystem reference can be placed outside the Coreline home and works offline,
but another path on one host is not necessarily an independent security domain.
Deployments must enforce separation with permissions, host boundaries, protected
storage, or a future remote/WORM adapter appropriate to their threat model.

## Provider contract and request

`SnapshotAnchor` is the minimal provider protocol: `anchor(request)`,
`get_expected_tip(incident_id)`, and `verify_ledger(incident_id)`. The reference
`FilesystemAnchor` is an adapter. Core semantics do not depend on cloud, HTTP,
databases, Redis, or vendor APIs.

The canonical request contains exactly:

```text
schema_version = 1
incident_id
snapshot_id
snapshot_digest                  # SHA-256 of complete signed snapshot envelope
state_digest                     # authenticated incident-state digest
snapshot_signer_key_id
snapshot_sequence
previous_snapshot_id | null
previous_snapshot_digest | null
```

No investigation text, metadata, artifacts, PII, credentials, or keys cross the
boundary. The request is derived only after the full local snapshot chain and
selected snapshot verify under the independently pinned snapshot key.

## Receipt schema and authentication

The receipt envelope is `{payload, signature}`. Its payload contains every request
field plus:

```text
domain = "coreline.snapshot-anchor-receipt.v1"
receipt_schema_version = 1
anchor_id
anchor_type = "filesystem-v1"
receipt_id = "ANC-" + SHA256(canonical payload without receipt_id)
anchor_sequence
acknowledged_at
anchor_key_id
authentication_algorithm = "ed25519"
previous_receipt_id | null
previous_receipt_digest | null
```

Canonicalization is Snapshot v1 canonical UTF-8 JSON: sorted keys, compact
separators, unescaped Unicode, no NaN/infinity, duplicate-key rejection. The
signature is Ed25519 over:

```text
b"coreline.snapshot-anchor-receipt.v1\x00" + canonical(payload)
```

The domain differs from Snapshot v1, preventing cross-protocol signature reuse.
The signed anchor identity, incident, snapshot/state/envelope digests, sequences,
predecessors, receipt identity, and receipt predecessor prevent field movement.

Receipts contain no verification key. Trust comes from `<home>/trust/anchors.json`
or `CORELINE_ANCHOR_REGISTRY`. The v1 registry defines a default enabled anchor,
filesystem root, Ed25519 public key/fingerprint, provider type, and policy. An
explicit CLI registry overrides the environment/default. Private anchor keys and
provider credentials are never stored in incidents or reports. The registry is a
local pin; protect or distribute it independently for independent trust.

## Two monotonic histories

V1 deliberately requires sequential anchoring. Snapshot sequence N can be anchored
only after N-1, and its predecessor ID/digest must match the previous receipt's
acknowledged snapshot. Duplicate identical requests return the existing receipt;
rollback, skipped snapshots, and forks are rejected.

```text
Snapshots: S1 --------> S2 --------> S3
             \            \            \
Receipts:     R1 --------> R2 --------> R3
```

Each receipt also signs the previous receipt ID and complete-envelope digest.
Ledger verification checks signatures, filenames, contiguous anchor/snapshot
sequences, both histories, and both predecessor digests. Files use atomic,
no-overwrite publication under a per-incident advisory lock. The lock coordinates
processes sharing a POSIX filesystem; it is not a cross-host lock guarantee.
Receipt-ledger verification is O(n).
Each append revalidates existing history before extending it, so constructing n
receipts is O(n²) total in the reference implementation. This deliberate check
avoids trusting a mutable head index; 100 receipts remain inexpensive in the v1
benchmark. A future independently authenticated index/checkpoint can optimize this
without weakening historical validation.

The provider stores ledgers under a SHA-256 of incident ID, never an untrusted path
component. Anchor IDs are restricted. Fixed filenames, regular bounded files,
`O_NOFOLLOW`, symlink-chain rejection, strict JSON, and exclusive publication
prevent traversal and replacement through normal APIs. A party controlling the
anchor filesystem can still delete a tail; the reference provider relies on that
storage domain's controls and does not claim WORM behavior.

## Expected tip and policy

`ExpectedTip` is represented by the latest authenticated external receipt:
incident/anchor identity, snapshot ID/digest/state digest, receipt ID, sequences,
and acknowledgement metadata. Coreline distinguishes:

| Relation | Meaning | Default integrity effect |
| --- | --- | --- |
| `MATCH` | Local tip equals independently retrieved tip | Satisfied |
| `LOCAL_AHEAD_OF_EXPECTED` | Local valid descendants are not anchored yet | Valid for OPTIONAL; unsatisfied for REQUIRED |
| `LOCAL_BEHIND_EXPECTED` | External anchor remembers a later checkpoint | Failure; likely deletion/rollback |
| `DIVERGED` | Expected snapshot is absent at same/lower local sequence | Failure |
| `LOCAL_SNAPSHOTS_MISSING` | Anchor expects a checkpoint, local chain is empty | Failure |
| `UNANCHORED` | No cached or external receipt exists | Informational for OPTIONAL |

Policies are deterministic:

- `OPTIONAL`: absence is informational; valid local-ahead state is allowed. Any
  existing invalid receipt, invalid external ledger, behind/missing/diverged state
  fails verification.
- `REQUIRED`: the external expected tip must be checked online, equal the local
  tip, authenticate under the pin, and match the local snapshot. Unavailability is
  incomplete verification and fails policy; there is no fallback. Because sealing
  creates a new final snapshot, sealing also requires the anchor signing key and
  anchors that final checkpoint.
- `REQUIRED_FOR_SEAL`: behaves like OPTIONAL before sealing. Sealing preflights
  both signing authorities, writes sealed state/audit, creates the final snapshot,
  anchors it, and confirms `MATCH`. A post-snapshot provider/cache failure leaves
  sealed state plus a final snapshot; retry `anchor snapshot` idempotently. There
  is no audit-after-anchor cycle. Once sealed, the policy behaves like REQUIRED.

## Offline and online verification

A local cached receipt plus pinned anchor public key can prove offline that the
configured anchor signed that receipt and that it matches a locally available
snapshot. It cannot prove that the receipt is still the anchor's newest retained
tip. Results expose `receipt_authentic`, `receipt_matches_snapshot`,
`expected_tip_checked`, `expected_tip_available`, `expected_tip_relation`, and
`anchor_policy_satisfied` separately. `OFFLINE_RECEIPT_VERIFIED` explicitly means
freshness was not checked.

Provider-backed verification validates the complete independent ledger and compares
its newest receipt to local history. Provider unavailability is distinct from
invalid data. OPTIONAL can remain locally valid with an authentic cached receipt;
REQUIRED cannot complete. An invalid reachable ledger always fails, including under
OPTIONAL. A stale cache is reported while the newer external tip controls relation.
If an authentic cache remembers a higher receipt sequence than a reachable external
ledger—or the same sequence with another receipt—the external expected tip has
regressed/conflicted and every policy fails. A missing reachable external tip also
fails when cache proves that anchor previously acknowledged a checkpoint.

Local receipt caches live under `incident/anchors/<anchor-id>/`. They are verification
artifacts excluded from snapshot authoritative-state inventory. If external commit
succeeds and caching fails, retry returns the identical receipt and safely fills the
cache. Verification and reporting are read-only.

## Operator workflow and recovery

```bash
coreline anchor init --anchor-id vault-a --root /independent/anchor \
  --private-key /secure/anchor.key --policy OPTIONAL
coreline snapshot create INC-EXAMPLE --signing-key /secure/snapshot.key
coreline anchor snapshot INC-EXAMPLE SNP-... --signing-key /secure/anchor.key
coreline anchor verify-tip INC-EXAMPLE
coreline anchor status INC-EXAMPLE --offline
coreline verify --id INC-EXAMPLE
```

Anchor snapshots in order. `anchor list/show/verify/expected-tip/status` provide
cached inspection, offline authentication, and online freshness. Failed receipt or
tip verification exits nonzero. `LOCAL_AHEAD_OF_EXPECTED` exits successfully under
OPTIONAL because it is normal between anchors. `LOCAL_BEHIND_EXPECTED`, missing,
diverged, invalid, or unsatisfied required policy exits nonzero.

For required final anchoring:

```bash
coreline lifecycle seal --id INC-EXAMPLE \
  --snapshot-key /secure/snapshot.key --anchor-key /secure/anchor.key
```

If external acknowledgement succeeded but cache publication failed, run `anchor
snapshot` again. If anchoring failed after final snapshot creation, anchor that same
final ID. Never delete/rewrite history to make verification pass. Key/config init
uses separate exclusive writes; interruption can leave a private key without its
registry. Inspect paths and recover deliberately rather than overwriting.

## Reporting, performance, and future providers

PIR/live integrity reports show policy, anchor/receipt/snapshot IDs, receipt
authentication, expected-tip relation/check status, and policy satisfaction without
signatures, keys, roots, secrets, or content. Legacy incidents without registry or
receipts remain OPTIONAL/UNANCHORED and valid.

Run `python -m scripts.benchmark_anchors --receipts 100`. The measured local run
created 100 receipts in 3.60 s (36.0 ms mean), verified individual receipts in
0.265 ms mean, retrieved/validated the expected tip in 0.066 s, and verified the
full ledger in 0.063 s. These figures are illustrative, not an SLA. The script measures receipt
creation, standalone authentication, expected-tip lookup, and full O(n) ledger
verification separately from snapshot creation.

Future adapters can retain the same request/receipt semantics with S3/GCS/Azure
retention controls, an organizational evidence vault, transparency service,
timestamp service, or enterprise signing service. Their capabilities differ:
retention, independent time, public auditability, and organizational identity must
be declared and evaluated separately. V1 implements no network/cloud provider and
does not pretend these systems offer equivalent guarantees.
