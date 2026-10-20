# Coreline

Coreline is a local-first incident response platform. The deterministic `core/` package is
the system of record; CLI, GUI, and future AI-assisted workflows are interfaces over that
core.

The current usable path is the operator CLI:

```bash
python -m interfaces.cli.coreline declare --title "DB Exfiltration Alert" --severity SEV1
python -m interfaces.cli.coreline evidence add --file alert.log --note "SIEM alert"
python -m interfaces.cli.coreline subject create \
  --type HOST --value prod-db --display-name "Production database"
python -m interfaces.cli.coreline observe add \
  --text "CloudTrail shows database access from unusual source IP" \
  --evidence <sha256-or-prefix> --subject-id SUB-ABC123DEF456
python -m interfaces.cli.coreline observe correct OBS-ABC123DEF456 \
  --text "Source IP was 10.0.0.6" --reason "Analyst typo"
python -m interfaces.cli.coreline observe retract OBS-ABC123DEF456 \
  --reason "Duplicate observation"
python -m interfaces.cli.coreline claim add \
  --text "Production database was accessed from an unusual source IP" \
  --observation OBS-ABC123DEF456 --status SUPPORTED --subject-id SUB-ABC123DEF456
python -m interfaces.cli.coreline claim correct CLM-ABC123DEF456 \
  --text "Production database was accessed from 203.0.113.10" \
  --reason "Add confirmed source IP"
python -m interfaces.cli.coreline claim status CLM-ABC123DEF456 \
  --status REFUTED --reason "Follow-up review disproved access"
python -m interfaces.cli.coreline claim withdraw CLM-ABC123DEF456 \
  --reason "Superseded by final analysis"
python -m interfaces.cli.coreline action create \
  --type credential-revocation \
  --description "Revoked exposed deployment credential" \
  --claim CLM-ABC123DEF456 --status COMPLETED --subject-id SUB-ABC123DEF456
python -m interfaces.cli.coreline action status ACT-ABC123DEF456 \
  --status COMPLETED --reason "IAM confirmed revocation"
python -m interfaces.cli.coreline action outcome ACT-ABC123DEF456 \
  --outcome "Credential revoked and sessions invalidated"
python -m interfaces.cli.coreline action cancel ACT-ABC123DEF456 \
  --reason "Superseded by containment playbook"
python -m interfaces.cli.coreline decision create \
  --type authorize-recovery \
  --statement "Authorize staged recovery" \
  --rationale "Containment completed and evidence reviewed" \
  --claim CLM-ABC123DEF456 --action ACT-ABC123DEF456
python -m interfaces.cli.coreline decision approve DEC-ABC123DEF456 \
  --approved-by director@example.com --reason "Recovery authorized"
python -m interfaces.cli.coreline graph show
python -m interfaces.cli.coreline graph verify
python -m interfaces.cli.coreline graph trace DEC-ABC123DEF456 --direction upstream
python -m interfaces.cli.coreline lifecycle contain --note "Blocked egress"
python -m interfaces.cli.coreline lifecycle eradicate --note "Credential rotated"
python -m interfaces.cli.coreline lifecycle recover --note "Database access validated"
python -m interfaces.cli.coreline lifecycle resolve --note "Customer impact ended"
python -m interfaces.cli.coreline timeline show
python -m interfaces.cli.coreline status
python -m interfaces.cli.coreline verify
python -m interfaces.cli.coreline report
python -m interfaces.cli.coreline close
python -m interfaces.cli.coreline lifecycle seal
```

## Current Shape

| Area | Status |
| --- | --- |
| `core/incident` | Incident workspace, lifecycle metadata, hash-linked audit log, PIR generation |
| `core/evidence` | SHA-256 evidence records, canonical manifests, custody chains, signing/sealing |
| `core/storage` | Write-only storage abstraction with local and GCS-oriented backends |
| `interfaces/cli` | Primary local operator console |
| `interfaces/gui` | Streamlit visual console over the same core |
| `services/` | Revived service experiments and integration surfaces |

Coreline deliberately keeps AI out of the trust path. LLMs may draft, summarize, or guide,
but incident state, evidence integrity, audit verification, and reports are produced by
deterministic Python.

## Setup

From this repo root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-services.txt
.venv/bin/pip install -r requirements.txt
```

The CLI stores incidents under `coreline-incidents/` by default. Override that with
`CORELINE_HOME` or `--home`.

```bash
export CORELINE_HOME=/tmp/coreline-demo
export CORELINE_ACTOR="$(whoami)"
```

## CLI Commands

```bash
.venv/bin/python -m interfaces.cli.coreline --help
.venv/bin/python -m interfaces.cli.coreline doctor
.venv/bin/python -m interfaces.cli.coreline list
.venv/bin/python -m interfaces.cli.coreline use INC-YYYYMMDD-ABC123
.venv/bin/python -m interfaces.cli.coreline subject create \
  --type HOST --value prod-db --display-name "Production database"
.venv/bin/python -m interfaces.cli.coreline subject list
.venv/bin/python -m interfaces.cli.coreline subject show SUB-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline observe add \
  --text "CloudTrail shows database access from unusual source IP" \
  --evidence <sha256-or-prefix> --subject-id SUB-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline observe list
.venv/bin/python -m interfaces.cli.coreline observe show OBS-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline observe correct OBS-ABC123DEF456 \
  --text "Source IP was 10.0.0.6" --reason "Analyst typo"
.venv/bin/python -m interfaces.cli.coreline observe retract OBS-ABC123DEF456 \
  --reason "Duplicate observation"
.venv/bin/python -m interfaces.cli.coreline claim add \
  --text "Production database was accessed from an unusual source IP" \
  --observation OBS-ABC123DEF456 --status SUPPORTED --subject-id SUB-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline claim list
.venv/bin/python -m interfaces.cli.coreline claim show CLM-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline claim correct CLM-ABC123DEF456 \
  --text "Production database was accessed from 203.0.113.10" \
  --reason "Add confirmed source IP"
.venv/bin/python -m interfaces.cli.coreline claim status CLM-ABC123DEF456 \
  --status REFUTED --reason "Follow-up review disproved access"
.venv/bin/python -m interfaces.cli.coreline claim withdraw CLM-ABC123DEF456 \
  --reason "Superseded by final analysis"
.venv/bin/python -m interfaces.cli.coreline action create \
  --type credential-revocation \
  --description "Revoked exposed deployment credential" \
  --claim CLM-ABC123DEF456 --status COMPLETED --subject-id SUB-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline action list
.venv/bin/python -m interfaces.cli.coreline action show ACT-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline action amend ACT-ABC123DEF456 \
  --description "Revoked exposed deployment credential in production IAM"
.venv/bin/python -m interfaces.cli.coreline action status ACT-ABC123DEF456 \
  --status COMPLETED --reason "IAM confirmed revocation"
.venv/bin/python -m interfaces.cli.coreline action outcome ACT-ABC123DEF456 \
  --outcome "Credential revoked and sessions invalidated"
.venv/bin/python -m interfaces.cli.coreline action cancel ACT-ABC123DEF456 \
  --reason "Superseded by containment playbook"
.venv/bin/python -m interfaces.cli.coreline decision create \
  --type authorize-recovery \
  --statement "Authorize staged recovery" \
  --rationale "Containment completed and evidence reviewed" \
  --claim CLM-ABC123DEF456 --action ACT-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline decision list
.venv/bin/python -m interfaces.cli.coreline decision show DEC-ABC123DEF456
.venv/bin/python -m interfaces.cli.coreline decision amend DEC-ABC123DEF456 \
  --statement "Authorize staged recovery for prod-db"
.venv/bin/python -m interfaces.cli.coreline decision rationale DEC-ABC123DEF456 \
  --rationale "Containment and integrity gates were reviewed"
.venv/bin/python -m interfaces.cli.coreline decision approve DEC-ABC123DEF456 \
  --approved-by director@example.com --reason "Recovery authorized"
.venv/bin/python -m interfaces.cli.coreline decision reject DEC-ABC123DEF456 \
  --reason "Legal review pending"
.venv/bin/python -m interfaces.cli.coreline decision supersede DEC-ABC123DEF456 \
  --by DEC-DEF456ABC123 --reason "New decision replaces earlier approach"
.venv/bin/python -m interfaces.cli.coreline decision withdraw DEC-ABC123DEF456 \
  --reason "Decision no longer applies"
.venv/bin/python -m interfaces.cli.coreline graph show
.venv/bin/python -m interfaces.cli.coreline graph show --format json
.venv/bin/python -m interfaces.cli.coreline graph verify
.venv/bin/python -m interfaces.cli.coreline graph trace DEC-ABC123DEF456 --direction upstream
.venv/bin/python -m interfaces.cli.coreline graph trace <sha256> --direction downstream --format json
.venv/bin/python -m interfaces.cli.coreline lifecycle contain --note "Blocked egress"
.venv/bin/python -m interfaces.cli.coreline lifecycle eradicate --note "Credential rotated"
.venv/bin/python -m interfaces.cli.coreline lifecycle recover --note "Database access validated"
.venv/bin/python -m interfaces.cli.coreline lifecycle resolve --note "Customer impact ended"
.venv/bin/python -m interfaces.cli.coreline verify
.venv/bin/python -m interfaces.cli.coreline close
.venv/bin/python -m interfaces.cli.coreline lifecycle seal
```

`doctor` checks the local incident store and verifies the active incident's manifest
signature, custody chain, audit chain, and stored local evidence artifacts. `verify`
prints the same integrity checks for one incident or all incidents. `close` generates the
final PIR, marks the incident closed, and locks evidence intake. Closure requires all
pre-closure quality gates to pass; administrative or false-positive closure requires an
explicit audited override:

```bash
.venv/bin/python -m interfaces.cli.coreline close --force --reason "False positive; no artifact available"
```

The incident lifecycle is forward-only:

```text
OPEN -> INVESTIGATING -> CONTAINED -> ERADICATING -> RECOVERING -> RESOLVED -> CLOSED -> SEALED
```

`RESOLVED` locks evidence intake, `CLOSED` locks case mutation after the final PIR, and
`SEALED` is the final read-only archival state.

Subjects are immutable incident-local identities for users, hosts, IP addresses,
credentials, services, files, malware, workloads, and other entities under investigation.
They are not a CMDB, asset inventory, identity provider, or threat-intelligence store.
Subject creation is audited and verified; existing records may still carry legacy display
subject text, while new records can reference stable `SUB-*` IDs.

Observations are immutable investigative records. They may reference zero or more evidence
items by SHA-256 hash or unique hash prefix from the incident's authoritative manifest;
Coreline never copies evidence bytes into an observation and never treats filesystem paths
as evidence references. Observations may also reference stable incident Subjects.
Corrections and retractions are append-only amendments: the original observation remains
intact, and the amendment history is audited and included in the PIR.

Claims are immutable investigative assertions derived from observations. A claim must
reference at least one non-retracted observation from the same incident; claims cannot
reference raw evidence hashes or filesystem paths directly. Claims may reference stable
incident Subjects. Corrections, status changes, and withdrawals are append-only
amendments. Claim creation and amendments are audited, and verification fails if a claim
or amendment is missing, tampered, or points at a missing observation or Subject.

Actions are immutable responder activity records. An action may reference claims,
observations, evidence hashes, and stable Subjects from the same incident. Corrections,
status changes, outcome updates, and cancellations are append-only amendments. Action
creation and amendments are audited, verified, and included in the PIR.

Decisions are immutable human incident-response judgments: what an authorized person
decided and why. Decisions may reference Subjects, evidence, observations, claims, and
actions from the same incident. Corrections, rationale updates, approvals, rejections,
supersessions, and withdrawals are append-only amendments. AI identities are rejected as
decision makers or approvers because AI is outside Coreline's authoritative trust path.
Decision creation and amendments are audited, verified, and included in the PIR.

The Case Graph is a deterministic projection, not another source of truth. It can be
deleted and rebuilt from authoritative incident state. Graph nodes represent Evidence,
Subjects, Observations, Claims, Actions, and Decisions. Graph edges are created only from
explicit stored references such as evidence supporting an observation, an observation
supporting a claim, a claim justifying an action, an action informing a decision, or a
Subject being associated with one of those records. The PIR includes a textual Case
Relationships section derived from this projection.

Graph tracing answers provenance and impact questions without creating new state.
`upstream` walks toward supporting records, `downstream` walks toward dependent records,
and `both` returns the connected relationship subgraph. `--max-depth` limits the number
of relationship hops, and `--format json` provides deterministic machine-readable output.

Conceptually:

```text
Evidence = what was preserved
Observation = what an investigator observed
Claim = what the investigation asserts
Action = what responders did
Decision = what authorized humans decided and why
Subject = what those records concern
Case Graph = deterministic relationships among those records
```

Trusted signer registry workflow:

```bash
.venv/bin/python -m interfaces.cli.coreline registry init
.venv/bin/python -m interfaces.cli.coreline registry trust-active
.venv/bin/python -m interfaces.cli.coreline registry verify --min-sequence 2
.venv/bin/python -m interfaces.cli.coreline verify --trusted --min-sequence 2
# Check every incident using an explicitly pinned root public key:
.venv/bin/python -m interfaces.cli.coreline verify --all --trusted --root-verify /path/to/root.verify.json --min-sequence 2
```

By default this writes a demo local root key and signed registry under
`$CORELINE_HOME/trust/`. The root key is a local development convenience; production root
key custody should be handled outside the incident workspace.

`verify --trusted` checks the registry root seal and sequence floor, then requires
the incident manifest signature to verify against a trusted, non-revoked registry
key. It also runs the core custody, audit, local evidence storage, Subject,
Observation, Claim, Action, Decision, and Case Graph checks. The core owns the
aggregate verdict; any failed record check also fails CLI verification.
Any failed check exits with status 1; invalid option combinations exit with status 2.
Use `--id` to target one incident or `--all` for the store. Custom trust files can
be supplied with `--registry`, `--seal`, and `--root-verify`.
These options and `--min-sequence` require `--trusted`.
Without `--trusted`, verification checks local integrity and reports signer trust
as unchecked. The default sequence floor is zero; supply a known minimum sequence
for rollback protection. Keep the pinned public key outside the writable workspace
when independent trust is required. These local storage checks do not attest cloud
retention settings.

## Authenticated incident snapshots

Signed checkpoints bind incident metadata, evidence/custody manifests, audit
history, investigative records and amendments, and lifecycle/sealing state.
They reuse Ed25519 and require an independently pinned public key; snapshot private
keys must remain outside the incident store. Case Graphs and reports stay derived.

```bash
python -m interfaces.cli.coreline snapshot keygen --private-key /secure/snapshot.key
python -m interfaces.cli.coreline snapshot create --signing-key /secure/snapshot.key
python -m interfaces.cli.coreline snapshot list
python -m interfaces.cli.coreline snapshot verify-chain
```

The default public pin is `<home>/trust/snapshot.verify.json`; use
`CORELINE_SNAPSHOT_VERIFY_KEY` for an independently protected pin. Snapshot commands
also support `--verify-key`. Historical signature validity, chain validity, and
current-state equality are separate results. `snapshot compare-current INCIDENT
SNAPSHOT_ID` exits nonzero on any difference. General `verify` and `doctor` reject
broken snapshot history and captured audit-prefix rollback, while accepting normal
live evolution. Incidents without snapshots remain compatible.

Once snapshots exist, `lifecycle seal --snapshot-key /secure/snapshot.key` creates
a final checkpoint of the sealed state. `snapshot report` renders its current
attestation without modifying the sealed PIR. A local authenticated snapshot chain
improves tamper evidence but cannot prove the latest local checkpoint was not
deleted by an attacker controlling the entire local storage domain. Preserve a
tip outside that domain and use `snapshot verify-chain --expected-tip ID_OR_DIGEST`.

See the [snapshot specification and operator guide](docs/specs/authenticated-incident-snapshots-v1.md)
for canonical format, portable verification, sealing recovery, and limitations.

### Independent snapshot anchors

Anchors move checkpoint identifiers and digests into a separately configured,
signed receipt ledger. They let Coreline detect a local snapshot tail rollback when
the independent ledger still expects a newer checkpoint. Anchors receive no incident
content and never become incident-record authority.

```bash
python -m interfaces.cli.coreline anchor init --anchor-id vault-a \
  --root /independent/coreline-anchor --private-key /secure/anchor.key
python -m interfaces.cli.coreline anchor snapshot INC-EXAMPLE SNP-... \
  --signing-key /secure/anchor.key
python -m interfaces.cli.coreline anchor verify-tip INC-EXAMPLE
python -m interfaces.cli.coreline anchor status INC-EXAMPLE --offline
```

`OPTIONAL` permits unanchored/local-ahead snapshots while rejecting invalid existing
receipts and rollback. `REQUIRED` needs an online expected-tip match.
`REQUIRED_FOR_SEAL` requires `lifecycle seal` to receive both `--snapshot-key` and
`--anchor-key`. `LOCAL_AHEAD_OF_EXPECTED` is normal between anchors;
`LOCAL_BEHIND_EXPECTED`, `DIVERGED`, and `LOCAL_SNAPSHOTS_MISSING` fail verification.
Offline verification proves a pinned anchor signed a cached receipt, but cannot prove
it is still the anchor's newest receipt.

The filesystem adapter should reside outside the Coreline home, but a different path
on one host may not constitute an independent security domain. See the
[independent anchor specification](docs/specs/independent-snapshot-anchors-v1.md).

For a remote receipt ledger, Coreline also provides a GCS adapter:

```bash
python -m interfaces.cli.coreline anchor init-gcs --anchor-id vault-gcs \
  --bucket org-coreline-anchors --prefix production/coreline \
  --private-key /secure/anchor.key --policy REQUIRED
```

The adapter uses ambient ADC/Workload Identity and accepts no credential-file
option. It stores one create-only object per receipt sequence and reads the full
ledger to determine the expected tip; there is no mutable head object. Configure
bucket retention, retention lock, IAM, audit logging, and an independently protected
copy of `trust/anchors.json` outside Coreline. Coreline reports these retention
controls as externally managed and does not claim to verify them. See the
[GCS anchor deployment specification](docs/specs/gcs-snapshot-anchor-v1.md).

### Signed trust registry

Signed registry releases authenticate key authorization and preserve rotation and
revocation history. Existing workspaces remain on legacy public-key pins until an
operator explicitly bootstraps a registry and imports the keys that should remain
trusted.

```bash
python -m interfaces.cli.coreline trust init --registry-id org-main \
  --private-key /secure/registry-root.key --actor security \
  --expected-tip /independent/coreline-registry-tips
python -m interfaces.cli.coreline trust key add \
  --public-key ~/.coreline/trust/snapshot.verify.json \
  --purpose SNAPSHOT_SIGNER --scope default --identity snapshot-current \
  --root-key /secure/registry-root.key --actor security
python -m interfaces.cli.coreline trust status --require-expected-tip
```

ACTIVE keys may sign new material. RETIRED keys verify historical material but
cannot sign new snapshots or receipts. REVOKED keys remain recorded and their
signatures are reported as cryptographically meaningful but untrusted. Protect the
registry root pin and expected-tip history independently. See the
[signed trust-registry specification](docs/specs/signed-trust-registry-v1.md).

## Verification

Baseline test gate:

```bash
.venv/bin/python -m pytest core autonomous services lib interfaces/cli/tests interfaces/gui/tests -q
```

Current complete regression gate:

```text
710 passed, 1 skipped, 28 warnings, 6 subtests passed
```

The gate includes the signed trust-registry, snapshot, anchor, GCS, incident, CLI,
GUI, service, autonomous, and shared-library suites. The previously stalled
provider-failure regression now runs as part of the normal gate. See the
[signed trust-registry checkpoint](docs/status/2026-09-22-signed-trust-registry.md),
[anchor checkpoint assessment](docs/status/2026-09-20-independent-snapshot-anchors.md),
and [snapshot checkpoint assessment](docs/status/2026-09-20-authenticated-snapshots.md).
The earlier post-commit audit regression selection passed 127 tests. See the
[architecture and security audit](docs/status/2026-09-19-post-commit-audit.md)
for corrected defects and the limits of local incident integrity.

Scrub check for old project naming: search the working tree for the previous project name
while excluding `.git/`, `.venv/`, bytecode, and cache directories. The expected result is
no matches.

## Repository Layout

```text
core/                 deterministic platform and system of record
interfaces/           CLI and GUI front ends
services/             service integrations and experiments
lib/                  shared service support
autonomous/           autonomous workflow experiments
docs/                 ADRs, specs, and status notes
scripts/              standalone utilities
```

Service startup and environment examples: [services/README.md](services/README.md).

## Direction

Near-term work is CLI-first:

1. Keep the baseline green.
2. Make the local operator flow complete and boring.
3. Move shared behavior into `core/`, leaving interfaces thin.
4. Reconcile docs and service experiments around the deterministic platform boundary.
