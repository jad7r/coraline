# Architecture, security, and regression audit of 9f9d463

## Verdict

`9f9d463` alone was **not a safe verification checkpoint**: real record corruption
could return CLI success, Jira did not honor its newly documented credential,
and brain readiness could approve a configuration that could not initialize.
The corrective changes make a coherent **local development checkpoint**. This is
not a production security certification or a claim of resistance to an attacker
who controls the entire writable incident store and local signing keys.

The initial audit and temporary failure reproductions preceded code changes.
All testing used temporary incidents and synthetic credentials. No external
messages, live provider requests, or production deployments were performed.

## Commit forensics: all 20 files

| Changed file | Purpose |
| --- | --- |
| `README.md` | Trusted verification usage and baseline |
| `core/incident/workspace.py` | Core detached-signature verification against a registry |
| `docs/status/2026-09-18-session-summary.md` | CLI handoff |
| `docs/status/2026-09-19-session-summary.md` | Documentation/secret-resolution handoff |
| `interfaces/README.md` | CLI trust workflow |
| `interfaces/cli/coreline.py` | Options, registry loading, result formatting |
| `interfaces/cli/tests/test_cli.py` | Trust workflow, revocation, tampering, exit codes |
| `services/README.md` | Shared service configuration documentation |
| `services/brain_service/.env.template` | Brain environment example |
| `services/brain_service/README.md` | Replace stale operational/compliance claims |
| `services/brain_service/_lib_shim.py` | Remove duplicate credential resolver |
| `services/brain_service/main.py` | Wire shared secret getters |
| `services/brain_service/routes/health.py` | Shared credential lookup in readiness |
| `services/brain_service/tests/test_brain_service.py` | Isolate missing-credential test |
| `services/jira_webhook_listener/.env.template` | Jira environment example |
| `services/jira_webhook_listener/README.md` | Replace stale operational instructions |
| `services/shared/secrets.py` | Prefix/alias/keychain precedence |
| `services/shared/tests/test_secrets.py` | Resolver and readiness tests |
| `services/slack_orchestrator/.env.template` | Exportable prefixed environment example |
| `services/slack_orchestrator/README.md` | Replace stale operational instructions |

The **1,650 deleted lines** reconcile exactly:

- **1,508 documentation lines:** brain README 414, Jira README 529, Slack README
  563, root README 1, interfaces README 1. Removed old deployment recipes,
  unsupported compliance/performance claims, stale paths, duplicated settings,
  and claims of live collection that the placeholder collectors did not implement.
- **16 Slack template lines:** comments/formatting and replacement configuration.
- **124 implementation lines:** brain shim 87, brain startup 10, brain readiness
  14, shared secrets 13. These consolidate or replace secret lookup logic.
- **2 test lines:** replaced with an isolated missing-credential context.

No endpoint, collector implementation, incident record type, lifecycle operation,
Dockerfile, or complete test file was deleted. No unrelated product feature was
hidden in the diff. The older operational guidance remains in Git history;
container deployment still needs independent verification. The important
functional omission was **Jira's separate loader remaining active**, not deletion
of a required implementation. The original readiness test changes bypassed real
startup, allowing that omission and the provider defect to escape detection.

## Findings and corrections

| Severity | Finding | Outcome |
| --- | --- | --- |
| HIGH | CLI aggregate checked only signature/custody/audit/storage; failed Subject/Observation/Claim/Action/Decision/Graph checks did not fail `verify` or `doctor` | Core now supplies `ok`; interfaces use it and show record failures |
| HIGH | Missing/empty audit passed, stored entry hashes were discarded, final-entry changes could be missed; malformed audit raised unexpectedly | Require nonempty workspace audit, verify sequence and stored hashes, reject malformed data, return a failed verdict |
| HIGH | Redis URL passwords and raw dependency exceptions could enter service logs; Jira readiness returned raw exceptions | Mask URL settings/serialization, suppress input values in settings errors, log exception types, return stable HTTP errors |
| HIGH | Grafana accepted requests with an unset webhook secret (pre-existing) | Blank/missing secret rejects authentication |
| MEDIUM | Jira's actual startup still used its private unprefixed resolver | Compatibility module delegates to shared authority; original Jira keychain namespace preserved |
| MEDIUM | Brain reported ready with missing SDK and could silently choose a fake after configured-provider failure | Initialize once at startup, inject the same provider, fail configured initialization, check loaded provider in readiness |
| MEDIUM | Whitespace credentials and non-string keychain responses counted as available | Reject blank/non-string candidates without coercing or logging values |
| MEDIUM | Invalid incident state crashed CLI; `--all` skipped a named incident with deleted state | Controlled `WorkspaceError`; discover `INC-*` directories even without state |
| MEDIUM | Subscribers logged malformed payloads/validation inputs; configured Jira URL credentials entered draft packets | Remove raw payload logging and remove URL userinfo/query/fragment from packets |
| LOW | Docs claimed Jira used shared resolution and readiness represented provider availability; baseline notes were stale | Corrected docs and linked this audit |
| INFORMATIONAL | Removed README production/compliance claims had no supporting active implementation | Cleanup was intentional; no deployment certification inferred |

The CLI aggregation, audit weaknesses, raw error logging, and Grafana fail-open
behavior predated this commit; the new trusted command inherited those risks.
The Jira documentation/configuration mismatch and insufficient readiness claim
are directly relevant to the checkpoint being reviewed.

## Credential authority and precedence

For Jira, Slack, and brain FastAPI services the authority is
`services/shared/secrets.py`. For each credential, order is deterministic:

1. `CORELINE_<name>` environment value.
2. Other supported prefixed aliases, then unprefixed aliases.
3. `Coreline` keychain, lowercase account name.
4. `secops-secure-enclave` keychain, environment-style names in the same order.
5. For Jira webhook only, historical `coreline-jira-webhook-listener` /
   `jira-webhook-secret`.

Anthropic's exact environment order is `CORELINE_ANTHROPIC_API_KEY`,
`CORELINE_CLAUDE_API_KEY`, `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY`.
Its `Coreline` accounts are `anthropic_api_key`, then `claude_api_key`.
Other service names are `SLACK_BOT_TOKEN`, `JIRA_WEBHOOK_SECRET`, `JIRA_API_TOKEN`,
and `JIRA_EMAIL`, each prefixed first and unprefixed second. No credential default
is hardcoded. Empty/whitespace-only values and non-string keychain responses are
absent; keychain failure falls through. Nonblank values retain their exact bytes.

Pydantic dotenv files supply settings, not exported secrets. Templates must be
exported as documented; strict dotenv unknown-key validation remains enabled.
`hide_input_in_errors` prevents validation text from quoting credential values.
Redis connections unwrap `SecretStr` only when constructing the client.

Other credential domains are explicitly separate, not competing incident truth:

- Grafana: `WEBHOOK_SECRET` from environment; no keychain or CORELINE alias.
- VirusTotal/MISP: `lib/_secrets.py` retains its tested explicit argument, then
  `coreline-secrets` keychain, then legacy environment contract. This audit does
  not silently reverse that intentional public API.
- Desktop OAuth: `CORELINE_GOOGLE_CLIENT_JSON`, administrator config, or embedded
  client config; refresh token in `Coreline` keychain.
- Incident signing: local incident Ed25519 seed/public metadata; registry root
  keys are separate from service API credentials. Enclave adapter key custody is
  also separate. The service resolver does not select core signing keys.

## Provider/readiness behavior

Brain's HTTP startup resolves required credentials and constructs Claude's SDK
client before creating the orchestrator. The exact provider is injected into the
orchestrator. Missing credentials, SDK, blank model, and constructor failure
fail startup. Direct library use can still select the fake when no credential is
configured, or explicitly inject a provider; there is no new offline HTTP mode
or additional provider selector.

Brain `/ready` pings Redis and checks the initialized provider held by the
orchestrator. It does not contact Anthropic or prove key validity, model access,
upstream reachability, or output quality. Changing environment/keychain values
requires restart to replace the loaded provider. Jira readiness checks Redis and
initialized webhook components. Slack readiness performs both Redis ping and
Slack `auth_test`, so its upstream connectivity semantics are intentionally stronger.

## CLI and incident trust path

`verify --trusted` loads a pinned root public key and calls core's
`load_signed_registry`: parse/validate registry, authenticate its canonical hash
and domain-separated root seal, then enforce the supplied sequence floor.
`IncidentWorkspace.verify_signer` fingerprints the local signer, finds a trusted
non-revoked registry entry, validates its key consistency, and verifies the raw
detached signature over manifest bytes. No CLI cryptographic algorithm is added.

`IncidentWorkspace.verify` verifies manifest signature, custody, local artifact
hashes, audit, all investigative records, and deterministic graph projection.
The CLI uses core's aggregate and combines it with signer trust. Failure is exit
1; invalid options are exit 2; successful verification is exit 0. An empty `--all`
store returns 0 with “no incidents”, never a verified-incident claim.

Verification reads state, signer public metadata, manifest/signature, audit,
record stores, evidence receipts/artifacts, registry/seal, and root public key.
It does not read private keys, reseal, update CURRENT, rewrite records, or acquire
a mutation lock that creates files. Byte/mtime snapshots prove repeated trusted
verification, sealed verification, and corrupt-state checks are read-only.

Services import no `IncidentWorkspace` mutators. Their writes are Redis mappings,
advisory draft files, and integration event logs. A failing provider leaves the
core incident tree byte-identical. Evidence, immutable investigative records,
append-only amendments, human decision checks, lifecycle gates, and sealing
remain in core. Existing lifecycle and tampering tests remain green.

## Residual limits / next milestone

**HIGH under an adversarial-local-storage threat model, pre-existing:** state and
audit history are not independently authenticated as a complete incident snapshot.
A party controlling the whole directory can rewrite mutable metadata and recompute
an unanchored audit chain or restore an old valid snapshot. Checking stored hashes
improves corruption detection; it does not solve deliberate whole-store rewriting.
The local signing seed and default root key are also in writable local storage.
Externally pin the root and supply a known sequence floor for independent signer
trust and registry rollback protection. Default floor zero offers none.

**MEDIUM, pre-existing:** mutation locks serialize writers, but multi-file writes
are not crash-atomic, and verification is not an atomic read snapshot against a
concurrent writer. No transaction journal was added. New verification/secret paths
add no authoritative writes. Services still need deployment isolation and their
own least-privilege filesystem permissions; configuration is trusted operator input.

**LOW / scope limit:** no blanket “no secret can ever escape” claim is justified
for arbitrary user-authored evidence, legacy desktop/experimental exception
surfaces, third-party SDK debug logging, or a malicious provider. The corrected
service credential/error boundaries have synthetic canary regression coverage;
incident content intentionally remains reportable. A pattern scan is not a formal
proof that every possible credential format is absent.

**Single best next milestone:** design and implement an authenticated incident
snapshot covering state, records, and audit head, with explicit rollback and
crash-consistency guarantees. This is more valuable than adding service features
or presenting trusted-signer verification as whole-incident authenticity.

## Validation and test quality

- Final focused audit selection: **127 passed**, 17 warnings.
- Complete documented active-project suite: **506 passed, 1 skipped, 28 warnings,
  6 subtests passed**, 32.84 seconds.
- The additional warnings exercise existing Pydantic/Redis deprecations through
  real startup paths. The optional GCS smoke test remains skipped; no cloud test ran.
- `compileall` for active Python packages, `pip check`, shell syntax for the three
  templates, and `git diff --check` passed.
- No tracked lint/type/security CI configuration, Makefile, or build gate exists.
  Archived prototypes are excluded from the documented active-project suite.
- Tracked-file inspection found no `.env`, private-key/runtime database/cache/
  incident-artifact paths and no matches for the scanned private-key/token formats.
  Contents were not printed.

Tests cover the full environment/keychain precedence matrix, malformed candidates,
Jira's real startup and old keychain, brain startup and provider-constructor/SDK/
Redis failures, initialized-provider readiness, secret canaries in output/settings/
HTTP errors/drafts, subscriber rejection, Grafana authentication, core record
corruption, missing/malformed audit/state, explicit CLI exits, sealed deterministic
verification, and filesystem isolation. Old mocks that bypassed startup were
replaced with actual lifespan tests using fake dependencies. Keychain/environment
fixtures are restored between tests and never require developer credentials.

The thread-backed provider regression exposed a sandbox event-loop notification
restriction; it passed outside the sandbox. Final focused and full suites ran
outside that restriction with synthetic dependencies and no live API calls.
