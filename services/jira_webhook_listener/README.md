# Jira webhook listener

Validates Jira webhooks with HMAC and replay checks, then publishes incident
events to Redis for downstream integrations. It does not create authoritative
core incident records. See [shared setup and secret resolution](../README.md).

From the repository root, export a filled-in copy of [.env.template](.env.template)
using the shared setup instructions, then run:

```bash
.venv/bin/python -m services.jira_webhook_listener.main
```

The default port is `8080`. `CORELINE_JIRA_WEBHOOK_SECRET` (or legacy `JIRA_WEBHOOK_SECRET`) is required at startup and is
resolved from the environment or the `Coreline` OS keychain. Google Secret
Manager is not implemented by the current shared resolver.

Endpoints: `POST /webhook`, `GET /health`, and `GET /ready`.
Readiness checks Redis and the loaded webhook secret.

| Setting | Default | Purpose |
| --- | --- | --- |
| `CORELINE_MAX_WEBHOOK_AGE_SECONDS` | `300` | Replay age window |
| `CORELINE_WEBHOOK_ID_TTL_SECONDS` | `86400` | Redis deduplication TTL |
| `CORELINE_MAX_REQUEST_BODY_SIZE` | `1048576` | Request size limit in bytes |
| `CORELINE_ENABLE_SWAGGER` | `false` | API docs; prohibited in production |

See [config.py](config.py) for all settings and [TESTING.md](TESTING.md) for the
webhook test harness. Run offline unit coverage from the repository root:

```bash
.venv/bin/python -m pytest services/jira_webhook_listener/tests -q
```
