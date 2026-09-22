# GCS snapshot anchor adapter v1

## Purpose and trust boundary

The GCS adapter moves authenticated snapshot receipt history out of the incident
storage domain. If local storage is rolled back from `S3` to `S2` while GCS still
retains the receipt for `S3`, expected-tip verification reports
`LOCAL_BEHIND_EXPECTED`. GCS receipts acknowledge checkpoint identifiers and
digests only. Evidence and investigative content never cross this interface, and
the provider cannot mutate incident state.

This adapter implements the provider-neutral contract in
`independent-snapshot-anchors-v1.md`; it does not change Snapshot v1 or the receipt
schema except that the authenticated provider type is `gcs-v1`.

```text
incident + snapshots                 independently administered GCS bucket
--------------------                 -------------------------------------
S1 -> S2 -> S3  -- digests only -->  00000000000000000001.json (R1)
                                      00000000000000000002.json (R2)
                                      00000000000000000003.json (R3)
                                                   expected tip = S3
```

## Authentication and object layout

The trusted anchor registry independently pins `anchor_id`, provider type, bucket,
prefix, Ed25519 verification key/fingerprint, and policy. Receipt-supplied material
cannot change that pin. The anchor private signing key remains outside Coreline
home and GCS. Production GCS access uses ambient Application Default Credentials,
normally Workload Identity Federation; there is no service-account key-file API.

Objects use this form:

```text
<prefix>/<anchor-id>/ledger/<sha256(incident-id)>/<20-digit-sequence>.json
```

Raw incident IDs never become object path components. Bucket, prefix, and anchor ID
are validated before use. Listing accepts only the exact fixed-width receipt names;
gaps, duplicates, unexpected objects, malformed UTF-8/JSON, duplicate JSON keys,
oversized objects, invalid signatures, and broken receipt/snapshot links invalidate
the reachable ledger.

Each upload uses the GCS create-only precondition `if_generation_match=0`. Two
writers racing for sequence N therefore cannot publish different receipts at that
sequence. The loser reads the winner and succeeds only when its complete anchor
request is identical; a conflicting request fails. Duplicate retries are
idempotent. No mutable expected-tip object exists. GCS object listing is strongly
consistent, and Coreline derives the tip only after validating the full contiguous
signed receipt ledger.

## Capabilities and deployment requirements

The adapter declares:

| Capability | v1 value |
| --- | --- |
| Conditional create | yes |
| Durable read/list | yes |
| Retention managed externally | yes |
| Retention verified by Coreline | no |
| Independently trusted time | no |

Coreline cannot establish a bucket's WORM posture from this application boundary.
Operators must configure and independently audit bucket retention/retention lock,
uniform bucket access, IAM, organization policy, audit logs, and lifecycle rules.
The runtime identity needs only the object operations required to create, list, and
read receipt objects in the configured prefix. It must not receive delete or
overwrite authority. The application signing authority and cloud identity should
be independently controlled where the threat model requires it.

Protect and distribute `trust/anchors.json` independently of both incident storage
and the receipt bucket. It contains public trust pins, not secrets, but replacing it
can redirect verification to an attacker key and storage location. A deployment can
ship it through a signed configuration release, read-only host image, configuration
management system, or separately governed integrity store. Coreline deliberately
does not turn the untrusted bucket into a registry distribution channel.

## Failure and verification semantics

Upload succeeds before the local receipt cache is written. If cache publication
fails, retrying the same operation retrieves the already accepted receipt and fills
the cache. If upload fails, no local receipt is fabricated. Cloud exception text,
bucket URIs, and provider response bodies are not returned through trusted status
or CLI errors.

An authenticated cached receipt supports offline authenticity checking but not
freshness. Online expected-tip checking lists, reads, authenticates, and validates
the independent ledger. A cloud transport/list/read failure is `ANCHOR UNAVAILABLE`;
reachable malformed or cryptographically invalid data is an invalid ledger. Required
policy never downgrades on either condition. Optional policy may tolerate genuine
unavailability according to the base protocol, but it never accepts reachable
corruption or a locally observed rollback.

## Security limits

The adapter cannot protect against compromise of the GCS project and its retention
controls, compromise of the anchor or snapshot signing keys, replacement of an
unprotected trusted registry, malicious authorized anchoring, compromised signing
hosts, destruction of all independent material, or denial of service. Receipt
`acknowledged_at` remains signed metadata rather than trusted time. GCS retention is
not legal nonrepudiation, consensus, backup synchronization, or proof of real-world
time. Full-ledger expected-tip verification is O(n); append also validates existing
history and therefore building n receipts is O(n²) total in v1.
