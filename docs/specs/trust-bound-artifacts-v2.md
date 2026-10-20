# Trust-bound incident artifacts v2

## Purpose

Snapshot v1 and anchor-receipt v1 identify their signing keys but do not identify
the signed trust-registry release that authorized those keys. V2 binds every new
artifact to the exact authenticated release used at creation time. This proves
issuance authorization when the referenced release chain is available, while the
newest trusted release still controls present-day revocation.

This format does not prove that the referenced release was globally newest at the
claimed wall-clock time. That requires an independently retained registry expected
tip. It also does not rewrite or weaken existing v1 history.

## Security properties

A trusted v2 artifact proves all of the following:

1. Its artifact signature is valid for its declared signer and v2 domain.
2. Its registry binding names an exact root-authenticated release envelope.
3. The signer was `ACTIVE` for the required purpose and scope in that release.
4. The referenced release belongs to the locally pinned registry and valid release
   chain; a release supplied only by the artifact is never trusted.
5. The signer is not `REVOKED` in the newest trusted release used for verification.
6. Artifact and registry history did not move backwards within the same artifact
   chain after v2 adoption.

The expected-tip policy remains responsible for detecting deletion of newer
registry releases. Artifact creation fails closed if an installed registry is
invalid, unavailable, or does not have exactly one active key for the required
slot.

## Registry binding

Both v2 payloads add the same object:

```json
{
  "registry_binding": {
    "registry_id": "org-main",
    "generation": 7,
    "release_id": "TRR-...",
    "release_digest": "<sha256 of the complete release envelope>",
    "root_key_id": "SHA256:..."
  }
}
```

The fields are exact and closed: unknown or missing members fail structural
verification. `release_digest` uses the existing trust-registry `release_digest()`
algorithm. The binding is part of the artifact payload, ID, and signature.

Verification resolves the binding only through a caller-authenticated
`TrustRegistryStore` or an imported bundle already matched to the pinned root. It
must find the named generation and require registry identity, root identity,
release ID, and full-envelope digest to match.

## Snapshot v2

- Domain: `coreline.incident-snapshot.v2`
- `schema_version`: `2`
- Existing `SNP-<sha256>` identifiers and canonical JSON rules remain unchanged.
- The v1 payload is retained and gains only `registry_binding`.
- The signing key must be `ACTIVE` for `SNAPSHOT_SIGNER/default` in the bound
  release.

Snapshot chains may transition once from v1 to v2. A v2 snapshot may name a v1 or
v2 predecessor using the existing predecessor ID and digest fields. After the first
v2 snapshot, a v1 successor is a downgrade and invalid. Successive v2 snapshots
must bind the same registry/root identity and a nondecreasing registry generation.

Legacy-pin workspaces with no registry continue producing v1 snapshots. Once a
valid registry root is installed, authoritative creation produces v2 only; there is
no command-line downgrade switch.

## Anchor receipt v2

- Domain: `coreline.snapshot-anchor-receipt.v2`
- `receipt_schema_version`: `2`
- Existing `ANC-<sha256>` identifiers and canonical JSON rules remain unchanged.
- The v1 payload is retained and gains `registry_binding` for the anchor signer.
- The anchor key must be `ACTIVE` for `ANCHOR_SIGNER/<anchor_id>` in the bound
  release.

The signed snapshot ID and full snapshot-envelope digest already bind the receipt
to the snapshot's registry assertion, so the snapshot registry fields are not
duplicated into the receipt. Receipt ledgers use the same one-way v1-to-v2 upgrade
rule and nondecreasing-generation rule as snapshot chains.

Filesystem and GCS providers must emit identical v2 payload semantics. Provider
type remains signed and no incident content or registry release body is sent to an
anchor.

## Verification results

Trusted verification reports signature validity separately from authorization:

- `ISSUANCE_AUTHORIZED`: signer was active in the exactly bound release.
- `REGISTRY_BINDING_MISSING`: v2 binding is absent or malformed.
- `REGISTRY_RELEASE_UNKNOWN`: the authenticated local chain lacks the release.
- `REGISTRY_BINDING_MISMATCH`: identity, generation, ID, digest, or root differs.
- `SIGNER_NOT_ACTIVE_AT_ISSUANCE`: key was absent, retired, or revoked in that release.
- `SIGNED_BY_REVOKED_KEY`: newest trusted release currently revokes the key.
- `REGISTRY_GENERATION_ROLLBACK`: a later artifact binds an earlier generation.
- `ARTIFACT_SCHEMA_DOWNGRADE`: v1 follows v2 in one artifact chain.

Cryptographic verification without a registry may still report a valid signature,
but it must not report issuance authorization or trusted status.

## Compatibility and rollout

- Existing v1 snapshots and receipts remain byte-for-byte valid and readable.
- Mixed chains verify during migration subject to the one-way upgrade rule.
- Legacy pin mode preserves current v1 behavior until registry bootstrap.
- Registry mode requires v2 for all newly created snapshots and receipts.
- General `verify`, `doctor`, sealing, offline anchor status, reports, and bundle
  portability must expose binding failures in their aggregate verdicts.
- No private key, registry release body, mutable trust lookup, or trusted timestamp
  is embedded in an artifact.

## Non-goals

- Re-signing historical artifacts
- Proving global registry freshness without an independent expected tip
- Root-key rotation or recovery beyond the existing explicit trust reset
- Certificate, transparency-log, consensus, or trusted-time semantics
- Changing incident-record authority, snapshot inventory, or anchor retention claims

