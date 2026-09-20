# Slack orchestrator

Consumes incident events from Redis, creates Slack response channels, and tracks
incident-to-channel mappings in Redis. See [shared setup and secret
resolution](../README.md). This integration does not replace the core incident
workspace or evidence store.

Export a filled-in copy of [.env.template](.env.template) using the shared setup
instructions, then launch from the repository root:

```bash
.venv/bin/python -m services.slack_orchestrator.main
```

The default port is `8081`. Startup requires `CORELINE_SLACK_BOT_TOKEN` (or legacy `SLACK_BOT_TOKEN`) from the environment
or the `Coreline` keychain's `slack_bot_token` entry, plus reachable Redis.
Prefixed environment values take precedence over legacy names and keychain entries.

| Setting | Default | Purpose |
| --- | --- | --- |
| `CORELINE_RESPONSE_TEAM_USER_IDS` | `[]` | Users invited to response channels; JSON array or CSV |
| `CORELINE_CHANNEL_TRACKING_TTL_SECONDS` | `7776000` | Mapping lifetime, 90 days |
| `CORELINE_ENABLE_SWAGGER` | `false` | API docs; prohibited in production |

`GET /health` provides liveness and `GET /ready` checks dependencies.
See [config.py](config.py) for all settings. Run offline tests from the repo root:

```bash
.venv/bin/python -m pytest services/slack_orchestrator/tests -q
```
