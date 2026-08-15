# ADR-0002 — Coreline is an AI-Independent Incident Response Platform

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** Product owner (J. Dellinger) + Staff Architect review
- **Supersedes:** [ADR-0001](0001-target-architecture.md)
- **Context doc:** `ASSESSMENT.md`

## Context

ADR-0001 treated the Python toolkit as a *helper for Claude*. That inverts the intended
relationship. The long-term goal is **not** "Claude + local toolkit." It is an
**AI-independent incident response platform** in which Coreline is the system of record and
the deterministic execution engine, and any LLM is a **replaceable, advisory plugin**.

## Decision

### 1. Coreline is the system of record and the deterministic engine

Coreline **owns** — deterministically, with no AI in the trust path:

- **incident state** (the state machine)
- **evidence** (store + integrity)
- **playbooks** (engine + content)
- **audit log** (append-only, tamper-evident)
- **workflow** (the orchestration of a response)
- **policy** (guardrails)
- **quality gates** (pre-closure and in-flight validation)
- **connector framework** (Slack, Jira, Drive, Grafana, … behind one interface)

All state transitions, evidence records, and audit entries are written by the
deterministic core. **The AI never becomes the system of record.**

### 2. LLMs are replaceable plugins behind a narrow provider interface

A single AI-provider abstraction exposes reasoning capabilities — **reason, plan,
summarize, recommend** — and nothing else. Implementations are interchangeable:

- **Claude** (one implementation)
- **OpenAI** (another)
- **Gemini** (another)
- **Local model** (must be possible)

Provider output is **advisory**: it is captured as an AI-attributed artifact
(provider, model, timestamp, input hash, output) and only becomes an action or a state
change when a human or a deterministic policy accepts it. The audit log records this
provenance so AI contributions are fully traceable and unambiguously non-authoritative.

### 3. AI is not just provider-independent — it is optional

The platform must function with **no AI at all**: declaring incidents, tracking state,
hashing/preserving evidence, running quality gates, and producing deterministic reports
(`build_timeline.py`, `incident_report.py`) never require an LLM. AI only *adds*
reasoning, summarization, planning, and recommendations on top.

### 4. Interfaces are front-ends, not the product

The CLI (`coreline`), an optional desktop GUI, and the **Claude Desktop skill** are all
front-ends that drive the same core. The Claude skill is thereby demoted from "the
product" to *one interface that happens to use Claude as its LLM provider*. This resolves
the two-contradictory-architectures problem in `ASSESSMENT.md` §1.

### 5. Evidence integrity is a core platform capability (PyNaCl in scope; WordPress removed)

The **cryptographic evidence subsystem is platform-native and first-class**. **PyNaCl is
part of the Coreline evidence architecture** (from `secops-secure-enclave/enclave/`:
X25519 / XSalsa20-Poly1305 / SealedBox / Ed25519 signing) — reused, not deferred as a
concept. It sits alongside/above the baseline SHA-256 + WORM path.

The subsystem owns, and exposes as a reusable library:

- **encrypted evidence bundles** (seal/unseal, multi-recipient)
- **SHA-256 integrity hashing**
- **manifest generation**
- **chain-of-custody metadata**
- **key handling** (OS keychain today; pluggable)
- **local/offline operation first**, with **future API/UI access** as a clean consumer of
  the same library

Hard constraints:

- **The subsystem MUST NOT be coupled to WordPress, any CMS, publishing, or a portal.** It
  knows nothing about presentation. Presentation/API/UI are separate consumers layered on
  top, so the crypto core can be **independently audited and reused**.
- **WordPress is dead alpha code — remove it entirely** from the product architecture
  (`secops-secure-enclave/enclave_wp/` and the WordPress GUI/portal docs). It was only an
  example presentation layer.
- **Defer production *deployment*** of the crypto subsystem until after security review and
  testing (its own docs call for a third-party crypto audit). In scope to build and
  verify now; not trusted for real evidence until reviewed.

## Target shape (illustrative, not final)

```
interfaces/   cli (coreline) · gui (optional) · skill (Claude Desktop front-end) · [future: web/api]
      │  (all call the same core; no logic lives in a front-end)
      ▼
core/  (deterministic system of record — no AI in the trust path)
   state/ · evidence/ · integrity/(crypto, no presentation) · audit/ · workflow/
   policy/ · quality_gates/ · playbooks/ · connectors/(Slack·Jira·Drive·Grafana adapters)
      │  (calls out for judgment through one narrow contract)
      ▼
ai/    provider interface: reason() · plan() · summarize() · recommend()
       providers: claude · openai · gemini · local        (output = advisory, provenance-tagged)
```

## Consequences

**Positive**
- One coherent identity: a durable platform, not an app tied to one vendor.
- No vendor lock-in; AI is swappable and optional; the record survives any AI outage.
- Evidence integrity becomes a reusable, independently-auditable capability.
- Absorbs the genuinely valuable Gen-2/3 assets (state machine, evidence engine, quality
  gate, PIR, playbooks, connector/collector code) into a principled structure.

**Costs / trade-offs (explicit)**
- **This reintroduces credential management that v3 had eliminated.** AI-independence and
  headless operation are fundamentally incompatible with "no standing tokens": when Coreline
  is *not* running inside Claude Desktop, it cannot ride the operator's Claude OAuth
  connectors — it needs its own connector credentials and LLM API keys. Accepted as a
  necessary consequence of the platform goal; managed by a dedicated secrets layer
  (the Gen-2/3 `secrets_manager` dual-mode pattern is a starting point). The Claude
  Desktop skill remains a valid **zero-token** operating mode for teams that only need
  assisted mode.
- Larger surface than v3 → more to build, test, secure, and version.
- Revived Gen-2/3 code was never production-validated → re-verify, don't trust.
- Two+ operating modes (assisted-via-skill, headless-via-CLI) must stay behaviorally
  coherent against the one core.

## Non-goals (unchanged from the fossil-layer decision)

- The always-on microservice **mesh** (webhook daemons, Redis, Cloud Run) — not required
  by this architecture and stays archived.
- The **autonomous agent** — conflicts with human-in-the-loop; AI is advisory only.
- The **WordPress portal / CMS publishing** — deleted as dead alpha code, not merely
  deferred. The evidence subsystem must never depend on it.

## Follow-up

Supersedes the ADR-0001 roadmap. A revised phased plan (platform core → provider
abstraction → evidence integrity → connector framework → interfaces) will be recorded
before implementation begins.
