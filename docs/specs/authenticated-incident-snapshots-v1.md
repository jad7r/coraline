# Authenticated incident snapshots v1

## Threat model

A snapshot authenticates a semantic inventory of an incident at a checkpoint,
not a backup and not a trusted timestamp. An independently pinned Ed25519 public
key authenticates the inventory. Changing, deleting, or substituting captured
records, audit entries, manifest/custody data, incident identity, checkpoint
identity, or chain links is detectable relative to that checkpoint. A signature
cannot prove wall-clock time: `created_at` is the signer's assertion.

Private snapshot keys are never persisted inside an incident or its store.
Snapshot files contain a key fingerprint, never a self-authorizing public key.
The public pin is supplied explicitly or loaded from
`CORELINE_SNAPSHOT_VERIFY_KEY`, defaulting to `<home>/trust/snapshot.verify.json`.
For independent trust, keep the public pin outside the attacker's writable
storage domain. The default is a local development convenience. Existing
per-incident manifest keys are not migrated or used as snapshot keys.

Not protected: signing-key compromise, malicious authorized signers, host
compromise during creation, filesystem denial of service, or loss of every
checkpoint and external copy. A local authenticated snapshot chain improves
tamper evidence but cannot prove the latest local checkpoint was not deleted by
an attacker controlling the entire local storage domain. An independently retained
expected tip ID/digest detects deletion of that known checkpoint. No network
anchor or transactional incident journal is introduced.

## Canonical state

Authoritative sources are `state.json`, `manifest.json` (including custody),
`manifest.sig`, `signer.json`, `audit.jsonl`, and optional `subjects.json`,
`observations.json`, `claims.json`, `actions.json`, `decisions.json`. Record stores
include amendments. Subjects currently have no amendment store. State includes
lifecycle and sealing metadata. A fixed allowlist prevents caches, graph
projections, generated reports, keys, snapshots, locks, and temporary files from
becoming authoritative. Unknown files are not part of v1 state.

Each source gets a component inventory entry. Investigative records, amendments,
evidence identities, and audit entries also get logical inventory entries. Entries
contain type, logical ID, relative source, canonical byte size, and SHA-256.
Snapshots do not copy source content or absolute paths. Existing absolute path
values in manifests remain bound by their component digest, without disclosure.
Artifact bytes are not duplicated in inventories: identity is already recorded
in the evidence manifest. Creation still runs the existing full integrity check,
which hashes evidence bytes once; this cost is reported separately.

Canonical JSON uses UTF-8, sorted object keys, compact separators, unescaped
Unicode, and no NaN/infinity or duplicate keys. Record collections are sorted by
logical ID; audit and custody order remain significant. JSON whitespace/object
key order are insignificant, while array order is significant unless explicitly
normalized. An absent optional store differs from a present empty store.
The state digest covers the versioned, sorted inventory and incident identity.

## Snapshot and chain

The envelope contains `payload` and a base64 Ed25519 `signature`. The payload
includes domain/schema, incident ID, sequence, UTC timestamp, actor, audit head
and length, state digest, record count, inventory, key fingerprint, algorithm,
final flag, predecessor ID/digest, and snapshot ID. The ID is `SNP-` plus SHA-256
of canonical payload excluding the ID. The signature covers a domain prefix and
the entire canonical payload, including ID. The snapshot digest is SHA-256 of
the canonical complete envelope. This is portable without repository paths.

Files are named by ID. Sequence and signed predecessor links determine order;
filesystem enumeration cannot. Duplicate sequences, forks, missing predecessors,
incorrect filenames, and replacement files fail chain verification. The format
already carries all material needed by a future external receipt: incident ID,
snapshot ID, full-envelope digest, sequence, and key fingerprint. No speculative
anchor provider interface is needed for v1.

## Checkpoint boundary, publication, sealing

Creation holds the existing writer lock, reloads state, checks base integrity,
checks the existing snapshot chain, inventories state, signs, and atomically
publishes one immutable file. It appends no audit event and changes no authoritative
file. The signed actor/timestamp/sequence provide the checkpoint's own history;
the snapshot covers the audit prefix that existed immediately before publication.
Publication never overwrites a snapshot and temporary files are not chain members.

Snapshots are historical: later legitimate state can differ without invalidating
their signatures. `compare-current` explicitly fails on differences. General
verification reports that distinction. A shortened or changed captured audit
prefix is inconsistent with the latest available checkpoint and fails health.

Legacy incidents without snapshots retain their sealing behavior. When snapshots
exist, sealing requires an external snapshot signing key. Snapshot-backed sealing
sets a final-snapshot requirement in state, performs the existing SEALED transition
and audit append, then captures that final state under the same lock. A crash or
signing failure leaves a visible missing-final-checkpoint failure, not a false
success. Retrying final snapshot creation can complete the checkpoint without
rewriting sealed state. No group-transaction guarantee is claimed.

Standalone snapshots of legacy SEALED incidents are allowed, marked final, and
do not mutate sealed state. Once a final snapshot exists, another snapshot cannot
replace it. Final-state comparison is mandatory for snapshot health. Deletion of
all snapshots and the local requirement marker together requires an external pin
to detect; this is the whole-storage rollback limitation above.

## Verification outputs

Structure, pinned-key trust, signature, chain, captured-record comparison, and
exact current-state comparison are separate results. Historical signature
verification never depends on current files or private keys. General verification
accepts legacy `NOT_PRESENT`, fails malformed chains, audit-prefix inconsistency,
and missing/mismatched required final checkpoints, and reports ordinary live
`CURRENT_STATE_DIFFERS`. A sealed final mismatch always fails.

Verification is read-only. Snapshot and inventory paths are fixed/validated;
symlinks are rejected, duplicate JSON keys fail parsing, and no snapshot-supplied
path or public key is used as authority. Active host/filesystem races beyond
cooperative writer locking remain outside the v1 host-compromise boundary.

## Inventory and wire format details

All sources have one component entry whose type and ID are the source kind:

| Source | Component kind | Additional logical entries |
| --- | --- | --- |
| `state.json` | `state` | None; metadata, lifecycle, final requirement included |
| `manifest.json` | `manifest` | `evidence` (`sha256:zero-based-index`), `custody-event` (one-based index) |
| `manifest.sig` | `manifest-signature` | None; digest/size cover decoded signature bytes |
| `signer.json` | `manifest-signer` | None; binds existing manifest public signer information |
| `audit.jsonl` | `audit` | `audit-entry` (one-based index) |
| `subjects.json` | `subjects` | `subject` (`subject_id`) |
| `observations.json` | `observations` | `observation`, `observation-amendment` |
| `claims.json` | `claims` | `claim`, `claim-amendment` |
| `actions.json` | `actions` | `action`, `action-amendment` |
| `decisions.json` | `decisions` | `decision`, `decision-amendment` |

Investigative records use their existing IDs, amendments their `amendment_id`.
Known collections are sorted by ID; manifest evidence items by canonical bytes.
The audit component is the canonical JSON array of parsed JSONL events in order.
Other component digests cover the entire parsed object, including unknown fields.
Each inventory entry has exactly `type`, `id`, `source`, `size`, `sha256`.
`size` is canonical UTF-8 byte length, **not** original on-disk file length.
Records are sorted lexicographically by `(source, type, id)` using Unicode code
point order, independent of locale. Missing required sources prevent creation.

The canonical serializer is precisely Python JSON with `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, encoded as UTF-8
without a BOM. No Unicode normalization is applied. V1 is this defined encoding,
not a claim of RFC 8785 conformance. Persisted JSON is parsed with duplicate-key
and nonfinite-number rejection. Payload/inventory numbers are integers. Source
values use the shared Python JSON representation; JSON numeric types remain
distinct (for example, `1` and `1.0`).

Given canonical encoding `C` and SHA-256 lowercase hex `H`:

```text
incident_state_digest = H(C({"schema_version": 1, "incident_id": ID, "records": sorted_inventory}))
snapshot_id = "SNP-" + H(C(payload_without_snapshot_id))
signature = base64(Ed25519.sign(b"coreline.incident-snapshot.v1\x00" + C(payload)))
snapshot_digest = H(C({"payload": payload, "signature": signature}))
```

The payload has exactly these fields (no extensions in schema v1):

```text
domain = "coreline.incident-snapshot.v1"
schema_version = 1
snapshot_id, incident_id, sequence (starts at 1)
created_at (canonical UTC ISO-8601 ending Z), created_by
previous_snapshot_id, previous_snapshot_digest (both null for sequence 1)
audit_head_hash, audit_length
incident_state_digest, record_count, records
signing_key_id = "SHA256:" + SHA256(raw_public_key).hexdigest()
signature_algorithm = "ed25519"
final (boolean)
```

Content-derived IDs bind the entire checkpoint assertion rather than just current
state. Two checkpoints with identical state still have different IDs because
sequence/predecessor differ. The envelope digest also binds the signature.
V1 supports one independently pinned signing key per chain; key rotation and
revocation policy are not implemented. Snapshot key trust is separate from the
existing manifest signer registry and never silently inherits its incident key.

Each source/snapshot file is limited to 64 MiB. Regular files only; symlinks in
paths are rejected. Snapshot files are published mode 0600, public pins 0644,
private seeds 0600. Keys are generated/loaded with existing Ed25519 primitives.
Core APIs accept in-memory key objects; callers are responsible for their custody.
The file-loading CLI rejects private paths anywhere under the incident store.

## Operator workflow

Invoke the CLI as `python -m interfaces.cli.coreline` (abbreviated `coreline` below).
All commands support `--home`; incident defaults to the active incident for
create/list/verify-chain/report. Show/verify/compare-current require the incident ID.

```bash
coreline snapshot keygen --private-key /secure/coreline-snapshot.key \
  --public-key /independent-trust/coreline-snapshot.verify.json
export CORELINE_SNAPSHOT_VERIFY_KEY=/independent-trust/coreline-snapshot.verify.json

coreline snapshot create INC-EXAMPLE --signing-key /secure/coreline-snapshot.key
coreline snapshot list INC-EXAMPLE
coreline snapshot show INC-EXAMPLE SNP-<digest>
coreline snapshot verify INC-EXAMPLE SNP-<digest>
coreline snapshot verify-chain INC-EXAMPLE --expected-tip SNP-<independently-retained-tip>
coreline snapshot compare-current INC-EXAMPLE SNP-<digest>
coreline verify --id INC-EXAMPLE
coreline snapshot report INC-EXAMPLE
```

Replace illustrative IDs and paths. Alternatively pass `--verify-key` to snapshot
commands, `--snapshot-verify-key` to general `verify`/`lifecycle seal`. Explicit keys
take precedence over the environment pin, which takes precedence over the default.
Use the environment pin for `doctor` and normal lifecycle gates. Pins inside the
incident are rejected. Neither a key in a snapshot nor a substituted local pin
constitutes independent trust. Preserve the public pin/fingerprint out of band.

Successful verification exits 0; failed/untrusted/malformed verification exits 1.
`compare-current` exits 1 even for a legitimate new state. CLI usage errors exit 2.
`show` only displays untrusted envelope data; it is **not** a validity assertion.
`verify` checks one document, `verify-chain` all locally published documents, and
`compare-current` compares current semantic records against one authenticated
document. `records_match` means all captured entries still match; added entries
can leave it true while `current_state_matches` is false.

General `verify` (including `--trusted`) and `doctor` include snapshot health.
`NOT_PRESENT` preserves legacy compatibility. Valid history plus legitimate live
changes yields `CURRENT_STATE_DIFFERS`, with overall integrity still valid if
the core checks and captured audit prefix pass. `CHAIN_BROKEN`, unreadable sources,
changed/truncated audit prefix, missing required final snapshot, or changed final
state fail the aggregate verdict. Snapshot comparison does not reread evidence
blobs; general verification checks their bytes against the authenticated identities.

To seal an incident with snapshot history, first close it using normal gates, then:

```bash
coreline lifecycle seal --id INC-EXAMPLE --snapshot-key /secure/coreline-snapshot.key
coreline snapshot report INC-EXAMPLE
```

The final snapshot covers **post-seal** state and its audit event. A failed final
publication does not undo sealing. `verify` then fails with
`FINAL_SNAPSHOT_MISSING`; rerun `snapshot create` with the trusted signing key to
complete final publication. Investigate integrity failures before recovery; never
delete or rewrite a chain to make verification pass. A crash after publication
but before the caller receives success can leave a valid checkpoint: inspect
list/verification before retrying. Key generation also uses two separate file
publications; a failure can leave a private key without its public pin. Do not
overwrite it blindly; recover public material from that key through trusted key
management, or explicitly choose new unused paths.

PIRs include checkpoint status as of report generation. Because reports precede
the final seal, they do not pretend to contain a subsequently created final ID.
The read-only `snapshot report` command renders the current/final attestation
without changing a sealed incident or rewriting its PIR.

## Portable verification without Coreline

Copy the JSON snapshot envelope and independently authenticated public pin.
No packaging/export subsystem is necessary. This minimal Python/PyNaCl example
verifies the signed payload without importing Coreline (it does not verify chain
completeness or current files):

```python
import base64, hashlib, json
from nacl.signing import VerifyKey

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def reject_constant(value):
    raise ValueError("nonfinite number")

def read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique, parse_constant=reject_constant)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

document = read("snapshot.json")
pin = read("independently-pinned-public-key.json")
payload = document["payload"]
public = base64.b64decode(pin["verify_key"], validate=True)
assert payload["domain"] == "coreline.incident-snapshot.v1"
assert payload["schema_version"] == 1
assert payload["signing_key_id"] == "SHA256:" + hashlib.sha256(public).hexdigest()
unsigned_id = {k: v for k, v in payload.items() if k != "snapshot_id"}
assert payload["snapshot_id"] == "SNP-" + hashlib.sha256(canonical(unsigned_id)).hexdigest()
VerifyKey(public).verify(b"coreline.incident-snapshot.v1\x00" + canonical(payload),
                         base64.b64decode(document["signature"], validate=True))
```

Compare incident/checkpoint identity and tip digest with independently retained
expected values; signature authenticity alone does not establish that a supplied
checkpoint is the one requested or the newest. Do not fetch trust from the same
untrusted bundle. Core's `verify_document` additionally validates the full schema,
inventory consistency, expected incident ID and expected snapshot ID.

## Performance and residual trust limits

Run `python -m scripts.benchmark_snapshots --records 200 --evidence 20` for a
disposable synthetic incident created through real core APIs. The measured local
run had 200 observations, 200 claims, 200 actions, 20 small evidence artifacts,
1,289 inventory entries and three checkpoints: inventory 0.074 s, existing base
verification 0.138 s, snapshot creation 0.437 s, three-checkpoint health 0.180 s.
The full snapshot was 194,858 bytes. These are illustrative local measurements,
not an SLA. Full evidence verification scales with artifact bytes; inventory and
chain verification scale with metadata/history. No artifact bytes are copied into
snapshots. No new dependency was needed for tests or implementation.

Authenticated snapshots now bind metadata and audit prefixes to signing authority.
They do not prevent direct disk writes, independently anchor the newest audit or
snapshot head, provide an independently trusted timestamp, or make multi-file
updates transactional. Read-only verification can observe an in-progress writer
and fail transiently. Whole-storage rollback remains undetectable without external
retained material. A protected public pin establishes signer identity; a separately
retained latest checkpoint ID/digest establishes which checkpoint must still exist.
Neither substitutes for the other. Future anchoring should record the existing
envelope digest and return independently verifiable durable receipts.
