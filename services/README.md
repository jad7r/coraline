# Service integrations

The operator CLI and deterministic `core/` remain the system of record. These
services are integration experiments; brain-service output is advisory and does
not replace the core-generated PIR or evidence verification.

| Service | Default port | Role |
| --- | --- | --- |
| [Jira listener](jira_webhook_listener/README.md) | 8080 | Validate webhooks and publish incident events |
| [Slack orchestrator](slack_orchestrator/README.md) | 8081 | Create and track incident channels |
| [Brain service](brain_service/README.md) | 8082 | Produce advisory PIR drafts using collector placeholders |

## Configuration boundary

All three Settings classes use `CORELINE_` for application settings. Shared
settings include `CORELINE_ENVIRONMENT` (default `prod`), `CORELINE_REDIS_URL`
(default `redis://localhost:6379/0`), `CORELINE_INCIDENT_CHANNEL_NAME`
(default `coreline:incident:created`), `CORELINE_LOG_LEVEL` (default `INFO`),
`CORELINE_HOST` (default `0.0.0.0`), and `CORELINE_PORT` (service-specific).
Use separate processes and environment files so ports and service settings do
not leak between services. List values should be quoted JSON arrays.

All three services use `shared/secrets.py` for secrets. Nonempty values resolve
in this order: prefixed environment names, unprefixed environment names, the
`Coreline` keychain, then the legacy `secops-secure-enclave` keychain.

| Credential | Environment names, in priority order | `Coreline` keychain key |
| --- | --- | --- |
| Jira webhook | `CORELINE_JIRA_WEBHOOK_SECRET`, `JIRA_WEBHOOK_SECRET` | `jira_webhook_secret` |
| Slack bot | `CORELINE_SLACK_BOT_TOKEN`, `SLACK_BOT_TOKEN` | `slack_bot_token` |
| Anthropic | `CORELINE_ANTHROPIC_API_KEY`, `CORELINE_CLAUDE_API_KEY`, `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY` | `anthropic_api_key`, then `claude_api_key` |
| Jira API token | `CORELINE_JIRA_API_TOKEN`, `JIRA_API_TOKEN` | `jira_api_token` |
| Jira email | `CORELINE_JIRA_EMAIL`, `JIRA_EMAIL` | `jira_email` |

The legacy `secops-secure-enclave` namespace accepts the environment-style names
in the same order shown above. Existing unprefixed environment variables and
keychain entries remain supported. Jira additionally falls back to its original
`coreline-jira-webhook-listener` service and `jira-webhook-secret` account after
the other keychains. Empty or whitespace-only values and non-string keychain
responses are absent; meaningful whitespace in a nonblank secret is preserved.
Such absent values fall through to the next source;
an unavailable keychain is treated as absent. Required missing secrets fail startup.
Brain startup uses this resolver and initializes the provider once. Readiness
checks the provider actually held by the orchestrator, not freshly read credentials
that might differ from the running configuration. Restart after credential rotation.
Redis URLs are represented as masked `SecretStr` values in settings and diagnostics;
only connection construction unwraps them.

This contract applies to the three FastAPI services above. The separate Grafana
experiment reads `WEBHOOK_SECRET` directly and rejects webhooks when it is blank.
The VirusTotal/MISP clients in `lib/` intentionally retain their documented
explicit-argument, `coreline-secrets` keychain, then legacy-environment precedence.
Google OAuth and incident signing keys have separate custody mechanisms; service
API credentials never select a core incident signer.

## Local startup

Run from the repository root, with dependencies installed in `.venv`:

```bash
.venv/bin/python -m pip install -r requirements-services.txt
```

Start Redis separately. Copy the desired service's `.env.template` to a local
file, fill in credentials, then export that file in the service's own shell.
For example:

```bash
cp services/slack_orchestrator/.env.template /tmp/coreline-slack.env
# Edit /tmp/coreline-slack.env before continuing.
set -a
. /tmp/coreline-slack.env
set +a
.venv/bin/python -m services.slack_orchestrator.main
```

Source only your own trusted environment files. Keep real credentials out of Git.
The templates are shell-compatible and contain no real credentials. Exporting
values is necessary because Pydantic's dotenv loading does not export secrets
into the process environment. Jira and brain Settings look for `.env` in the
working directory; Slack Settings looks beside its `config.py`. These Settings
also reject unknown dotenv keys, so a mixed settings-and-secrets file should be
exported as above rather than copied to an automatically loaded `.env` path.

The module launch commands honor `CORELINE_HOST` and `CORELINE_PORT`. When using
`uvicorn` directly, supply its host and port explicitly; `CORELINE_PORT` does not
configure the Uvicorn command line.

## Validation

```bash
.venv/bin/python -m pytest services -q
```

Tests use fakes and do not establish live Slack/Jira connectivity or production
readiness. See each service's `config.py` for the full settings definition.
