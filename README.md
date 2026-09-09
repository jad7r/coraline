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
```

By default this writes a demo local root key and signed registry under
`$CORELINE_HOME/trust/`. The root key is a local development convenience; production root
key custody should be handled outside the incident workspace.

## Verification

Baseline test gate:

```bash
.venv/bin/python -m pytest core autonomous services lib interfaces/cli/tests interfaces/gui/tests -q
```

Current local baseline at this checkpoint:

```text
357 passed, 1 skipped, 17 warnings, 6 subtests passed
```

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

## Direction

Near-term work is CLI-first:

1. Keep the baseline green.
2. Make the local operator flow complete and boring.
3. Move shared behavior into `core/`, leaving interfaces thin.
4. Reconcile docs and service experiments around the deterministic platform boundary.
