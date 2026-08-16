# Coreline

Coreline is a local-first incident response platform. The deterministic `core/` package is
the system of record; CLI, GUI, and future AI-assisted workflows are interfaces over that
core.

The current usable path is the operator CLI:

```bash
python -m interfaces.cli.coreline declare --title "DB Exfiltration Alert" --severity SEV1
python -m interfaces.cli.coreline evidence add --file alert.log --note "SIEM alert"
python -m interfaces.cli.coreline timeline show
python -m interfaces.cli.coreline status
python -m interfaces.cli.coreline verify
python -m interfaces.cli.coreline report
python -m interfaces.cli.coreline close
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
.venv/bin/python -m interfaces.cli.coreline verify
.venv/bin/python -m interfaces.cli.coreline close
```

`doctor` checks the local incident store and verifies the active incident's manifest
signature, custody chain, audit chain, and stored local evidence artifacts. `verify`
prints the same integrity checks for one incident or all incidents. `close` generates the
final PIR, marks the incident closed, and locks evidence intake.

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
290 passed, 1 skipped, 17 warnings, 6 subtests passed
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
