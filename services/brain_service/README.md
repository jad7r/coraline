# Brain service

Produces advisory PIR drafts from Redis incident events or `POST /pir/generate`.
The deterministic core remains authoritative; these drafts are not the final
core PIR and do not establish compliance. See [shared configuration and secret
resolution](../README.md).

## Current implementation

`_lib_shim.py` contains a placeholder Jira collector and data assembler. They
return synthetic incident metadata and a Slack channel note, not live Jira data
or Slack message history. `CORELINE_FAKE_JIRA_STATUS` controls the placeholder
status (default `Resolved`). Providing credentials does not enable real collection.

`PIRProvider` is the replaceable advisory generation interface. Direct provider
usage can select `FakePIRProvider` without an API key, and tests inject fakes.
The running HTTP service nevertheless requires Anthropic, Slack, Jira token,
and Jira email credentials at startup, plus Redis and an installed `anthropic`
SDK. Startup constructs the provider without making an upstream API request.
A configured provider that cannot initialize fails startup; it never silently
substitutes a fake provider. It does not currently offer
a credential-free offline server mode.

## Run locally

Export a filled-in copy of [.env.template](.env.template) using the shared setup
instructions, then run from the repository root:

```bash
.venv/bin/python -m pip install anthropic
.venv/bin/python -m services.brain_service.main
```

The default port is `8082`. The output directory must be an absolute writable
path. The template uses `/tmp/coreline-pirs`; the code default is `/output/pirs`.

| Setting | Default | Purpose |
| --- | --- | --- |
| `CORELINE_PIR_COMPLETED_CHANNEL` | `coreline:pir:completed` | Completion events |
| `CORELINE_GENERATE_PIR_ON_STATUS` | `["Resolved","Closed"]` | Status filter (currently placeholder metadata) |
| `CORELINE_SKIP_PIR_IF_EXISTS` | `true` | Skip existing drafts |
| `CORELINE_CLAUDE_MODEL` | `claude-sonnet-4-5` | Configured provider model string |
| `CORELINE_CLAUDE_MAX_TOKENS` | `16000` | Generation limit |
| `CORELINE_CLAUDE_TEMPERATURE` | `0.3` | Generation temperature |
| `CORELINE_SLACK_MESSAGE_LIMIT` | `1000` | Passed to the placeholder assembler |

See [config.py](config.py) for all settings. `GET /health` is a liveness check.
`GET /ready` pings Redis and checks that the orchestrator holds an initialized
provider. The `credentials` compatibility field and `provider` field refer to
that loaded configuration. It does not validate credentials or model availability
against upstream APIs. Restart to pick up changed environment/keychain credentials. `POST /pir/generate` accepts an `IncidentEvent` and returns
`incident_id`, `generated`, `pir_path`, and `preview`.

## Validation

```bash
.venv/bin/python -m pytest services/brain_service/tests -q
```

Tests use `fakeredis` and an injected fake provider. Live collection and offline HTTP startup remain integration follow-ups.
