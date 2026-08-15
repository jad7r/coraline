# Coreline — Phase 1 Discovery & Architectural Assessment

**Author:** Staff Software Architect / Security Engineer (review pass)
**Date:** 2026-07-06
**Scope:** Full read of the Coreline repository at `/Users/jdellinger/Desktop/Coreline`, **including the `CORELINE_OLD_DESIGN/` snapshot** added mid-review (~38,000 LOC of prior-generation source + ~100 design/security/playbook docs).
**Status:** Assessment only. No code changed. No implementation begun.

> **Revision note.** This assessment was first written against the active tree alone,
> then substantially expanded after `CORELINE_OLD_DESIGN/` was added. The old design is not
> a footnote — it reframes the central finding. Much of what a thin reading of the
> active tree suggests is "missing" or "unbuilt" was in fact **built, matured, and
> deliberately removed.** Coreline's real story is **progressive amputation**, not immaturity.

---

## 0. Version Lineage (the single most important context)

Coreline has been through **five generations**. Each one threw away most of the prior one to
escape its operational or security weight. The current repo is a thin outer ring with
four older rings preserved beside it.

| Gen | Name | Form | Where it lives now | Held tokens? | Fate |
|---|---|---|---|---|---|
| **1** | v1 | npm package / web app | referenced only (README history) — **absent** | — | deleted |
| **2** | v2 "mesh" | GCP microservices: FastAPI + Redis + Cloud Run + Docker; autonomous brain; secure enclave; Terraform infra; GCP Secret Manager | `CORELINE_OLD_DESIGN/archive/{experimental,services,infra,secops-secure-enclave}` + a duplicate in `./archive/experimental` | Yes (Secret Manager) | archived for "operational tax" |
| **3** | "Coreline Lite" | local-first Python **CLI (`coreline.py`)** + `tools/` + `lib/` + `collectors/` + `brain/` + PySide6 GUI + Socket-mode Slack bot | `CORELINE_OLD_DESIGN/archive/` (`coreline.py`, `tools/`, `lib/`, …) | env-var / Keychain | superseded |
| **4** | Desktop GUI | single-file **Tkinter app** (`gui.py`): declare → Doc + Channel + WORM manifest | **active tree root** (`gui.py`,`auth.py`,`storage.py`) **and** `CORELINE_OLD_DESIGN/` root (byte-identical) | Yes (Slack bot token in Keychain) | **orphaned in active tree** |
| **5** | v3 skill | Claude Desktop **skill**: `SKILL.md` + templates + one offline script | **active tree root** (`SKILL.md`, `templates/`, `scripts/`) | **No — by design** | **current direction** |

Datestamps corroborate this: the enclave/playbooks/services are May–early-June 2026;
`gui.py`/`ARCHITECTURE.md` are 2026-06-26 12:49; the v3 docs
(`README`/`PROJECT_SUMMARY`/`SKILL`) are 2026-06-26 16:36–16:38 — **the same day, hours
later.** The v3 pivot happened on June 26 and left Gen 4 (the GUI) behind in the tree
without removing it.

**The trajectory, stated plainly:** a near-complete, security-reviewed IR *platform*
(Gen 2/3) was reduced to a minimal declare-only *app* (Gen 4), then to a *specification*
driven by Claude (Gen 5). Each step bought operational simplicity by discarding built,
working capability. The active tree is Gen 5 + an orphaned Gen 4, sitting on top of a
Gen 2/3 fossil bed.

---

## 1. Executive Summary

### What Coreline *is*
An internal incident-response orchestration tool for a 4-person security team:
standardize incident kickoff (channel, roles, doc, Jira), capture evidence, build a
defensible forensic timeline, draft the PIR — aligned to ISO 27001 A.16, NIST 800-61,
FedRAMP IR-4/5/8, PCI DSS. That mission is the **one stable thing across all five
generations.**

### What Coreline currently *ships* (active tree)
Two contradictory things, side by side:
- **v3 skill** (intended direction): `SKILL.md` prose + 3 templates + one excellent
  offline script. Orchestration exists as **instructions to Claude**, not executable code.
- **Desktop GUI** (orphaned Gen 4): a polished ~1,400-line Tkinter app that
  re-implements the exact things v3 says it removed — a Slack **bot token**,
  programmatic channel creation, GCS "WORM" writes, an installable app.

`ARCHITECTURE.md` documents the GUI as *the* architecture; `README.md`, edited hours
later the same day, says that model was the problem v3 exists to solve. **The repo does
not have one answer to "what is Coreline."**

### Current maturity
- **Active tree, v3 path:** early — specification + one production-grade script. **Zero
  tests, no version control, no CI** (`git` is absent).
- **Active tree, GUI path:** functional but off-strategy and carrying real defects (§5).
- **Old design (Gen 2/3):** *self-described* as near-complete and security-reviewed, but
  **never validated in production** — its own status docs say "code-complete, pending
  validation," test suites were partial ("11 passing, 15 pending"), and the persisted
  data files (`data/*.jsonl`) are **empty** (it never ran a real incident). Treat its
  many `*-COMPLETE.md` / `DEPLOYMENT_READY.md` claims as **aspirational self-reports.**

### Major strengths
1. **A genuinely valuable, mostly-built IR asset base** now visible in `CORELINE_OLD_DESIGN/`:
   a full `coreline.py` operator CLI, evidence hashing + WORM, a 6-state machine, **six
   detailed incident playbooks** (ransomware/phishing/BEC ~1,000–1,550 lines each; plus
   malware/data-breach/account-takeover), breach-notification matrices, comms templates,
   a PyNaCl **secure enclave** for encrypted evidence, and a **9-category threat model
   with ~35 guardrails.** This is real domain and security work.
2. **`build_timeline.py` is production-quality** (deterministic, stdlib-only, UTC-correct).
3. **The v3 security *thesis* is sound** — eliminating standing service tokens via
   operator OAuth connectors is the right call for a 4-person team and dissolves most of
   the secret-management surface.
4. **Secret hygiene in code is consistently good** — no hardcoded secrets in any
   generation; Keychain / Secret Manager used correctly; the encrypted `.env` is Fernet,
   not plaintext.

### Major weaknesses
1. **No single source of truth for what the product is** — two live architectures; four
   more docs describing three different ones.
2. **The stated direction (v3) is largely unbuilt** — prose, not software, unverified
   against live connectors.
3. **Severe capability regression** — evidence hashing, state tracking, quality gates,
   playbooks, PIR automation, threat model: all existed in Gen 2/3 and are **absent from
   the v3 path.**
4. **Evidence integrity is asserted but not enforced** in the active tree (§5): the GUI's
   "WORM" write verifies nothing and hashes nothing — even though Gen 3 *did* hash
   evidence (SHA-256) and Gen 2's enclave did authenticated encryption.
5. **A latent confidentiality bug** — the GUI creates **public** incident channels.
6. **No tests / no git / no CI** on the active code; ~38k LOC of prior work is unversioned
   and partly duplicated on disk.

---

## 2. Repository Inventory

### 2.1 Active tree — v3 skill + orphaned Gen-4 GUI (~1,900 LOC)

| Path | Type | What it does | Gen |
|---|---|---|---|
| `SKILL.md` | Skill def | Claude Desktop skill: kickoff/evidence/timeline/handoff/PIR as NL instructions + connector calls | 5 |
| `templates/{roles,incident-doc,jira-incident}.md` | Templates | Slack role msg, canvas living-doc, Jira field map | 5 |
| `scripts/build_timeline.py` | **Program** (248 LOC) | Deterministic forensic timeline (parse/dedupe/sort/gap-detect → MD+CSV). Stdlib only. | 5 |
| `README.md`,`PROJECT_SUMMARY.md`,`INSTALL.md` | Docs | v3 vision, track reconciliation, install/packaging | 5 |
| `gui.py` | **Program** (1,400 LOC) | Tkinter console: setup wizard; Declare → Google Doc + Slack channel + GCS WORM manifest; Settings | 4 |
| `auth.py` (152) · `storage.py` (65) · `reset_google_auth.py` (45) | Programs | Google desktop-OAuth → Keychain; config+Keychain secrets; token reset | 4 |
| `requirements.txt` · `ARCHITECTURE.md` | Config/Doc | GUI deps; 450-line architecture of the GUI presented as "the" Coreline | 4 |
| `.gitignore` | Config | Security-aware; **ignores `archive/`** | shared |
| `./archive/experimental/` | Dead code | Duplicate of five Gen-2 microservices (~7,700 LOC), quarantined + gitignored | 2 |

**No CLI, no tests, no `lib/`/`tools/`** in the active tree — despite docs referencing them.

### 2.2 `CORELINE_OLD_DESIGN/` — full Gen-2/3/4 snapshot (~38,000 LOC source + ~100 docs)

Its top level is a **byte-identical copy** of the Gen-4 Desktop GUI (`gui.py` etc.).
Everything else sits under `CORELINE_OLD_DESIGN/archive/`:

| Cluster | Path | What it is | Self-reported maturity |
|---|---|---|---|
| **Coreline Lite CLI** | `archive/coreline.py` (572 LOC) + `lib/` + `collectors/` | `git`-style operator CLI: declare · use · state · roles · evidence · timeline · handoff · quality · close · report · ioc · metrics. Current-incident pointer, 6-state machine, hint system, offline-capable. | Core **production-ready** |
| **State machine** | `archive/tools/incident_state.py` | DECLARED→INVESTIGATING→CONTAINED→ERADICATED→RECOVERED→CLOSED (+ESCALATED/reopen), append-only JSONL, validated transitions | Production-ready |
| **Evidence bot** | `archive/tools/evidence_bot{,_enhanced}.py` | Slack 📌 capture → **SHA-256 hash** → upload to **GCS WORM** bucket → append metadata; enhanced adds Claude classification + quality grade | Ready / prototype |
| **Quality gate** | `archive/tools/pre_closure_check{,_enhanced}.py` | Pre-closure validation: evidence completeness, timeline gaps, playbook coverage, PIR presence, legal state path; AI variant enforces min Grade-B | Production-ready |
| **PIR generation** | `archive/coreline-brain.py` + `brain/` | Jira + Slack + timeline + gaps → Claude → Markdown PIR; 📌 timeline extraction; PII redaction | Ready (needs creds) |
| **Timeline / IOC / metrics / dashboard** | `archive/tools/{timeline_builder,ioc_tracker,metrics_*,dashboard*}.py` | Timeline assembly; cross-incident IOC extraction+correlation; MTTR/velocity/IC metrics; static HTML dashboard | Ready → prototype |
| **Playbooks** | `archive/playbooks/` | **6 full incident playbooks** (P1: ransomware/phishing/bec; P2: malware/data-breach/account-takeover) + SIRP v2, breach-notification matrix, comms templates, contact list, evidence-collection guide, IR training | **High-value, largely complete** |
| **Secure enclave** | `archive/secops-secure-enclave/` (~5k LOC) | PyNaCl client-side encryption (X25519 + XSalsa20-Poly1305, SealedBox DEKs, **Ed25519-signed** recipient directory); PySide6 GUI; **WordPress portal** publishing of encrypted evidence | **Beta** (needs security audit) |
| **Slack bot (Gen 3)** | `archive/services/coreline-slack-bot/` | Socket-mode slack-bolt bot: `/coreline status|timeline|handoff|ask|transition|evidence|playbook|ioc|metrics`; channel-prefix authz | Prototype |
| **Secrets (shared)** | `archive/services/shared/secrets_manager.py` (~600 LOC) | Dual-mode: GCP Secret Manager (prod) / Fernet `.env.encrypted` + Keychain (dev); fail-fast; audit logging | Ready |
| **v2 microservices** | `archive/experimental/{jira-webhook-listener,slack-orchestrator,coreline-brain-service,grafana-webhook,brain-autonomous}` | Event-driven mesh: HMAC/replay-verified Jira webhook → Redis → auto channel + auto PIR; autonomous agent (stub) | Mixed: listener **complete**, rest prototype/abandoned |
| **Infra** | `archive/infra/` | Terraform: Cloud Run ×3 + Memorystore Redis + VPC + WORM buckets + Secret Manager + monitoring; ~$150–300/mo prod | IaC-ready, undeployed |
| **Security docs** | `archive/SECURITY_THREAT_MODEL.md` (+FIXES, CHECKLIST, WIZ_EXCEPTION) | 9-threat model, ~35 guardrails; 6 remediated findings (CVEs, GCS public-access-prevention, VPC) | Substantial |
| **Design/history** | `archive/docs/`, `EXECUTIVE_SUMMARY.md`, `MATURITY-ROADMAP.md`, `compliance-mapping.md`, `status/summary-2026-05-*.md` | Vision, 4-track model, sprint history, compliance mapping | Extensive |
| **`.env.encrypted`** | `CORELINE_OLD_DESIGN/.env.encrypted` | 376-byte Fernet blob (not plaintext). Present on disk; should be Keychain-migrated. | — |

### 2.3 Tests / CI / VCS
- **Tests:** only in `CORELINE_OLD_DESIGN/archive/{experimental/jira-webhook-listener/tests, tests, secops-secure-enclave/tests}` — and self-reported as partial. **Active tree: none.**
- **CI/CD:** none present.
- **Version control:** **none** (`git` absent). ~40k LOC total across generations is unversioned; Gen-2 code is duplicated in two `archive/` trees.

---

## 3. Architecture

Documented in depth for the two live paths; the old generations are summarized in §2.2.

### 3.1 v3 skill (intended current)
```
Operators → Claude Desktop + Coreline skill
   ├─ operator OAuth connectors → Slack · Jira/Confluence · Google Drive
   │     (channel setup · ticket · canvas · 📌 evidence · Drive preservation)
   └─ frozen events.jsonl → build_timeline.py (offline, stdlib) → timeline.md/.csv
```
- **Auth:** none held by Coreline; the operator's OAuth session inside Claude is the sole authenticator. Strongest part of the whole project — no Coreline-held credential to steal.
- **Storage:** Slack/Jira/Drive; "WORM" delegated to an admin-set Google Vault hold **by documentation only** — nothing in the skill pins or verifies it.
- **Trust boundaries:** operator ↔ Claude ↔ Anthropic (ZDR is an open procurement item) and Claude ↔ SaaS via operator OAuth. `build_timeline.py` is a hard local boundary (no network, no tokens).

### 3.2 Desktop GUI (Gen 4, orphaned but present)
```
gui.py → auth.py (Google OAuth → Keychain) + storage.py (config + Keychain: slack_bot_token)
       → IncidentServices → Drive (create Doc, full auth/drive) · Docs · GCS (WORM upload) · Slack (create channel, bot token)
```
Reintroduces the standing Slack bot token and the deploy-an-app model that v3 eliminated.

### 3.3 Technical debt & architectural risks (highlighted)
1. **[CRITICAL] Architectural non-determinism.** Two live architectures; the repo cannot state which is the product. Root cause of most other debt.
2. **[CRITICAL] `ARCHITECTURE.md` documents the rejected Gen-4 model as current**, never mentioning v3 — actively misleads onboarding and security review.
3. **[HIGH] Capability regression is undocumented.** Nothing in the active tree tells you that state tracking, evidence hashing, quality gates, playbooks, and PIR automation already exist one directory over. A reader of the active tree would rebuild what's already written.
4. **[HIGH] The skill ZIP bundles the whole tree.** `INSTALL.md`'s `cp -R Coreline /tmp/coreline-pkg/coreline` ships `gui.py`, `auth.py` (OAuth scopes + `EMBEDDED_CLIENT_CONFIG`), and `requirements.txt` **inside the uploaded skill.** No skill manifest limits contents.
5. **[HIGH] Connector-contract drift.** `SKILL.md` hardcodes tool names (`slack_create_canvas`, `createJiraIssue`, …) with no preflight that they exist; a rename breaks a flow at 3am.
6. **[MEDIUM] ~40k LOC unversioned + partially duplicated on disk** (two `archive/experimental` copies), all gitignored.
7. **[MEDIUM] Reproducibility ≠ integrity.** `build_timeline.py` reproduces output from a *hand-assembled, unsigned* `events.jsonl`; "defensible" overstates what's enforced.

---

## 4. Feature Inventory & Classification

Classification: **Production Ready · Partially Implemented · Prototype · Broken · Dead Code** (Dead Code here means *not wired into any live path* — several items are high-quality and **salvageable**, flagged ♻.)

### 4.1 Active tree
| Feature | Impl | Completeness | Known issues | Class |
|---|---|---|---|---|
| Forensic timeline | `scripts/build_timeline.py` | High | any all-digit `ts`→epoch; input unsigned | **Production Ready** |
| Kickoff orchestration | `SKILL.md` + templates | Spec only | not executable; connector names unverified | **Prototype** |
| Evidence capture (📌) | `SKILL.md` | Spec only | Drive not WORM; no hashing/manifest | **Prototype** |
| Handoff / PIR | `SKILL.md` | Spec only | redaction is instruction, not control | **Prototype** |
| Templates | `templates/*.md` | High | static, fine | **Production Ready** |
| GUI setup/auth/storage | `gui.py`/`auth.py`/`storage.py` | High | off-strategy; solid code | **Partially Implemented** |
| GUI: Google Doc | `create_doc` | High | needs full `auth/drive` | **Partially Implemented** |
| GUI: Slack channel | `create_channel` | Medium | **`is_private=False` → PUBLIC channel (gui.py:410)** | **Broken** (security) |
| GUI: WORM manifest | `write_manifest` | Medium | **no retention check, no hashing** → false WORM (gui.py:427) | **Broken as-designed** |

### 4.2 `CORELINE_OLD_DESIGN/` (all Dead Code relative to the active tree; ♻ = salvageable)
| Feature | Impl | Self-reported | Reviewer note | Class |
|---|---|---|---|---|
| Operator CLI | `coreline.py` | Production-ready | Genuinely well-designed UX; offline-first | **Dead Code ♻ (high value)** |
| Incident state machine | `tools/incident_state.py` | Production-ready | Exactly the state tracking v3 lacks | **Dead Code ♻** |
| Evidence hashing + WORM | `tools/evidence_bot*.py` | Ready | **SHA-256 + GCS WORM** — the integrity v3 is missing | **Dead Code ♻ (high value)** |
| Pre-closure quality gate | `tools/pre_closure_check*.py` | Production-ready | playbook mapping is a stub | **Dead Code ♻** |
| PIR generation | `coreline-brain.py` + `brain/` | Ready (needs creds) | untested against live creds | **Dead Code ♻** |
| Incident playbooks (6) | `playbooks/` | Complete (P1), P2 present | **Highest-value asset; architecture-agnostic** | **Dead Code ♻ (high value)** |
| Secure enclave (crypto) | `secops-secure-enclave/` | Beta | real PyNaCl crypto; needs 3rd-party audit; no decrypt audit log | **Dead Code ♻** |
| Slack `/coreline` bot | `services/coreline-slack-bot/` | Prototype | Socket-mode; rich commands | **Dead Code** |
| Secrets manager | `services/shared/secrets_manager.py` | Ready | dual-mode, fail-fast, audited | **Dead Code ♻** |
| IOC / metrics / dashboard | `tools/*` | Prototype | correlation/calc "in development" | **Dead Code** |
| Grafana IRM sync | `lib/grafana_irm.py` | Prototype | stubs | **Dead Code** |
| v2 Jira webhook listener | `experimental/jira-webhook-listener` | Complete + tests | HMAC + replay + schema; sound | **Dead Code ♻** |
| v2 slack-orchestrator / brain-service | `experimental/*` | Prototype | depend on absent modules | **Dead Code** |
| v2 grafana-webhook | `experimental/grafana-webhook` | Abandoned | fail-open secret, missing lib | **Dead Code** |
| v2 autonomous brain | `experimental/brain-autonomous` | Abandoned | mostly `# TODO`; conflicts with human-in-loop | **Dead Code** |
| GCP infra (Terraform) | `infra/` | IaC-ready | never deployed | **Dead Code** |

---

## 5. Security Review

### Authentication
- **v3:** none held by Coreline (operator OAuth in Claude). Best-in-project.
- **GUI (Gen 4):** operator Google OAuth **plus a standing Slack bot token** in Keychain — the surface v3 set out to remove.
- **Gen 2/3:** GCP Secret Manager (prod) + Fernet `.env.encrypted`/Keychain (dev), fail-fast, secrets never logged — a mature model, now dormant.

### Authorization
- **GUI:** full **`auth/drive`** (auth.py:32–36) — read/write all of the operator's Drive; defensible only if the GUI is retained. GCS `validate_bucket` checks IAM create/get but **not retention lock.**
- **Gen 3:** least-privilege `channels:manage`+`chat:write`; enclave enforces per-recipient cryptographic authorization (fail-closed).

### Secrets management
- **Good across every generation:** no hardcoded secrets (grep-verified in active tree); Keychain/Secret Manager; `.env.encrypted` is Fernet, gitignored. v3's no-secrets posture is the strongest.

### Audit logging
- **Active tree: none** (neither GUI nor skill emits audit events).
- **Gen 2/3 had it:** structlog JSON to Cloud Logging; the threat model specifies PII scrubbing + 7-year retention (SIEM consolidation was the one acknowledged open item). Notably, **the secure enclave has *no* decrypt audit log** — a real gap it documents.

### Evidence integrity — the most overstated claim in the active tree, and a clear regression
1. **GUI "WORM" is unverified WORM.** `write_manifest` (gui.py:427) does a plain `upload_from_string`; nothing checks the bucket has a retention policy/lock. The operator is told *"WORM manifest written"* regardless. **False assurance.**
2. **Nothing is hashed or signed in the active tree.** The manifest (gui.py:1159) stores links + metadata, not content hashes — a pointer file, not a tamper-evident record.
3. **This is a regression, not an absence.** Gen 3's `evidence_bot.py` **SHA-256-hashed** every item and wrote to a real WORM bucket; Gen 2's enclave did authenticated encryption with MAC-verified tamper detection and Ed25519-signed directories. The integrity engineering existed and was dropped.
4. **v3's own evidence path is explicitly non-immutable** (Drive, not WORM — disclosed in `SKILL.md`). So the flagship "immutable evidence" value prop is currently met in **neither** live path, despite being solved in Gen 2/3.
5. **Timeline reproducibility is real but narrow** — deterministic ordering of an unsigned, Claude-assembled input; not authenticity or completeness.

### Attack surface
- **v3:** minimal Coreline-owned surface; real risks are prompt-injection via hostile Slack/Jira content steering an action, and the Anthropic ZDR boundary (procurement).
- **GUI:** pasted Slack bot token (theft → workspace-wide bot actions), full Drive scope, **public-channel leak.**
- **Gen 2/3 (if revived):** the mesh's HMAC/replay/schema controls were solid; the autonomous brain conflicts with the human-in-loop principle.

### Security concerns — ranked
- **[CRITICAL]** GUI "WORM" write: no retention verification, no hashing → false evidence-integrity assurance (gui.py:363–372, 427–439).
- **[CRITICAL]** GUI creates **public** incident channels (`is_private=False`, gui.py:410).
- **[HIGH]** Off-strategy standing Slack bot token in the active tree contradicts the v3 model.
- **[HIGH]** Capability regression: hashing/state/quality-gates/threat-model built in Gen 2/3, absent from v3 path.
- **[MEDIUM]** No audit logging in either live path; enclave lacks decrypt logging.
- **[MEDIUM]** Skill ZIP ships auth code + OAuth scopes to every operator account.
- **[MEDIUM]** ~40k LOC (incl. security-sensitive code) unversioned; `.env.encrypted` on disk.
- **[LOW]** Over-broad `auth/drive`; no Anthropic ZDR confirmation.

---

## 6. Missing Pieces — reframed as *dropped* pieces

With the old design visible, the honest finding is that Coreline's gaps are mostly **losses,
not absences.** Almost every "missing" capability was built in Gen 2/3.

| Capability the vision calls for | Status in active tree | Reality |
|---|---|---|
| Incident state tracking (DECLARED→CLOSED) | absent | **built** (`tools/incident_state.py`) |
| Evidence hashing / integrity | absent | **built** (SHA-256 + WORM in `evidence_bot.py`; enclave AEAD) |
| Immutable/WORM archival | doc-only / false in GUI | **built** (Gen-3 GCS WORM; Gen-2 enclave) |
| Pre-closure quality gate | absent | **built** (`pre_closure_check*.py`) |
| PIR automation | prose | **built** (`coreline-brain.py`) |
| Incident playbooks | absent | **built** (6 detailed playbooks + supporting docs) |
| IOC correlation / metrics | absent | **built** (prototype) |
| Threat model / compliance mapping | absent | **built** (9-threat model; ISO/NIST/FedRAMP/PCI mapping) |
| Audit logging / SIEM | absent | **specified + partially built** (structlog); consolidation open |
| Operator CLI (offline 3am path) | absent | **built** (`coreline.py`) |

**Genuinely still-open (never resolved in any generation):**
- **A decision on which architecture is the product** (Milestone 0).
- **End-to-end verification of the v3 skill** against live connectors.
- **SIEM consolidation** (acknowledged open item since Gen 2).
- **Anthropic enterprise/ZDR confirmation** before handling a real incident.
- **Tests / CI / version control** on whatever becomes the product.

**Abandoned-and-should-stay-abandoned:** the autonomous brain agent (conflicts with
human-in-the-loop) and the always-on microservice mesh (the operational tax that drove
every simplification).

**Opportunities to simplify:** pick one architecture and delete the rest from the active
tree; **preserve the playbooks and the evidence-hashing logic regardless of choice**
(they're architecture-agnostic, high-value, low-controversy); collapse the four
overlapping docs into one coherent set; put everything under git.

---

## 7. Technical Debt (prioritized)

### CRITICAL
- **C1. Architectural incoherence** — two live architectures; docs disagree with code and each other. Nothing can be planned or trusted until "what is Coreline" has one answer.
- **C2. False WORM/evidence-integrity assurance** (GUI) — an untrue integrity claim in a security tool is worse than none; it will fail an audit and could taint real evidence. *Aggravated by the fact that correct hashing/WORM code already exists in Gen 3.*
- **C3. Public incident channels** (gui.py:410) — leaks incident existence/content; trivial to fix, high impact if the GUI ships.

### HIGH
- **H1. Stated direction (v3) is unbuilt** — prose, unverified against connectors.
- **H2. `ARCHITECTURE.md` documents the deprecated Gen-4 model as current** — misleads.
- **H3. No version control on ~40k LOC** — no history/attribution/rollback/review gate; unacceptable for a security tool. Gen-2 code is duplicated on disk.
- **H4. Undocumented regression** — the active tree gives no signal that a richer, built platform exists in `CORELINE_OLD_DESIGN/`; invites rebuilding solved problems.
- **H5. Skill packaging leaks GUI + auth code** into every uploaded skill.

### MEDIUM
- **M1. No audit logging / SIEM** in either live path (enclave lacks decrypt logging).
- **M2. No tests / CI** on active code.
- **M3. No connector-contract preflight** for the skill.
- **M4. Over-broad `auth/drive`** (only if GUI retained).
- **M5. `.env.encrypted` on disk**; dual old/new secret models coexist in the fossil layer.

### LOW
- **L1. macOS-only Keychain** (portability). **L2.** GCS placeholder project / no requester-pays. **L3.** Best-effort operator email. **L4.** `parse_ts` all-digit→epoch edge case. **L5.** ~2.8MB of bundled `.venv`/caches inside `CORELINE_OLD_DESIGN/` polluting the tree.

---

## 8. Proposed Roadmap

**Everything is gated on one decision.** No feature code until Milestone 0 lands. Each
milestone is scoped to a few hours. The presence of `CORELINE_OLD_DESIGN/` changes the
economics: several milestones are now **salvage**, not greenfield.

### Milestone 0 — Decide the architecture (½ day, no code) — *requires your approval*
Produce a one-page ADR choosing the product-of-record. The evidence favors **v3 (skill)
as the product**, but with a deliberate decision on **which Gen-2/3 assets to
re-adopt** — because the pivot discarded working, valuable capability. Explicitly decide
the fate of: the Gen-4 GUI, the `coreline.py` CLI, evidence hashing/WORM, the state machine,
and the playbooks. *Blocks all else.*

### Milestone 1 — Make the repo tell the truth (2–3 hrs)
- `git init`; commit; establish review expectations.
- Consolidate the fossil layers (one `legacy/`, de-duplicate the two `archive/experimental` copies, strip the bundled `.venv`/caches).
- Rewrite/retire `ARCHITECTURE.md` to describe only the chosen architecture; fix dangling references; add a short "prior generations & why superseded" note pointing at `legacy/`.

### Milestone 2 — Contain the security defects (2–4 hrs)
- If GUI retained: `is_private=True` (C3); make `write_manifest` **verify bucket retention lock** and refuse/warn otherwise; stop labeling non-WORM writes as WORM (C2).
- If GUI dropped: remove `gui.py`/`auth.py`/`storage.py`/`reset_google_auth.py`/`requirements.txt` from the active tree; add a skill packaging manifest so the ZIP ships only `SKILL.md`/`templates/`/`scripts/`.

### Milestone 3 — Salvage the two highest-value, architecture-agnostic assets (3–4 hrs)
- **Playbooks:** lift `CORELINE_OLD_DESIGN/archive/playbooks/` into the product (as skill references or repo docs). Highest value, lowest risk, useful under any architecture.
- **Evidence integrity:** port Gen-3's SHA-256 hashing (and, if WORM is required, the WORM-write + retention-verify path) into whichever evidence flow is chosen — directly closing C2 with code that already exists.

### Milestone 4 — Prove one v3 flow end-to-end (3–4 hrs)
- Add a connector preflight to `SKILL.md` (verify required tools; fail loud).
- Tabletop the **Kickoff** flow against live connectors; correct `SKILL.md` tool names/outputs to match reality.

### Milestone 5 — Timeline hardening + first tests + integrity manifest (3–4 hrs)
- Extend `build_timeline.py` to emit a signed/append-only manifest hashing `events.jsonl` and each evidence item (honest chain of custody).
- Add a `tests/` suite for `build_timeline.py` (parse edge cases, dedupe, gaps, all-digit-`ts`); wire minimal CI.

### Milestone 6 — Re-adopt state tracking (optional, 3–4 hrs)
- If the product benefits, port Gen-3's `incident_state.py` state machine + `pre_closure_check` quality gate (the offline, defensible spine v3 currently lacks).

### Milestone 7 — Close compliance decisions (2–3 hrs, mostly non-code)
- SIEM in/out (ADR); confirm Anthropic enterprise/ZDR tier; wire + **verify** the Google Vault retention hold if WORM-grade retention is required.

### Milestone 8 — Remaining flows to parity (3–4 hrs each)
- Bring Evidence, Handoff, PIR to the "tabletop-verified against live connectors" bar, one at a time — reusing Gen-3's PIR assembler where it fits.

---

*End of assessment. No implementation performed. Awaiting approval of Milestone 0 (the
architecture decision, now including which prior-generation assets to re-adopt) before
any code is written.*
