# Coreline-Brain Service

**Automated Post-Incident Review Generation Service**

Event-driven microservice that listens for security incident notifications via Redis Pub/Sub and automatically generates compliance-ready Post-Incident Reviews (PIRs) using an LLM provider.

> **Revived under [ADR-0003](/docs/adr/0003-revive-archived-services.md).** Lives at
> `services/brain_service/` and imports as the package `services.brain_service.*` from
> the repo root.
>
> **AI provider boundary (ADR-0002 §2).** PIR generation runs behind a narrow,
> replaceable `PIRProvider` interface (`_lib_shim.py`). The LLM is *advisory* — its
> output is captured with provenance (provider, model, timestamp) and is never the
> system of record. With **no** API key configured (offline / CI) a deterministic
> `FakePIRProvider` is selected automatically, so the service imports, boots, health-
> checks, and produces a PIR-shaped document with no network and no live LLM. Tests
> inject the fake provider and use `fakeredis`.
>
> **Vendored shims.** The archived build imported `services.shared`, `brain.*`, and
> `collectors.jira_incident`, none of which exist in the active tree yet. `_lib_shim.py`
> vendors minimal offline stand-ins for these (marked `# TODO(ADR-0003 integration)`)
> so the unit is independently mergeable and testable. Swap them for the real modules
> when those land.
>
> **Secrets.** LLM API keys and tokens are read from the environment or the OS keychain
> (`keyring`); nothing is hardcoded.

---

## Overview

Coreline-Brain Service is the automated PIR generation component of the Coreline (Automated Response & Evidence System) platform. It integrates with:

- **Jira**: Fetches incident metadata and resolution details
- **Slack**: Collects incident response logs and evidence markers (📌)
- **Claude AI**: Synthesizes evidence into structured PIR documents
- **Redis Pub/Sub**: Receives incident events and publishes completion notifications

### Key Features

- ✅ **Event-Driven**: Automatically triggered when incidents are resolved
- ✅ **Evidence Synthesis**: Combines Jira metadata + Slack logs into comprehensive PIRs
- ✅ **Claude AI Powered**: Uses Claude Sonnet 4.5 with Coreline-Brain persona prompt
- ✅ **Compliance Ready**: Generates PIRs meeting ISO 27001 and FedRAMP requirements
- ✅ **Audit Logging**: Structured JSON logs for SIEM integration
- ✅ **Health Checks**: Kubernetes/Cloud Run compatible readiness probes

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Coreline-Brain Service                     │
└──────────────────────────────────────────────────────────┘
                          ↓
    ┌─────────────────────────────────────────────┐
    │   Redis Pub/Sub: coreline:incident:created     │
    └─────────────────────────────────────────────┘
                          ↓
    ┌─────────────────────────────────────────────┐
    │        PIR Subscriber (Background Task)     │
    │  - Filters for Resolved/Closed incidents    │
    │  - Validates incident event schema          │
    └─────────────────────────────────────────────┘
                          ↓
    ┌─────────────────────────────────────────────┐
    │           PIR Orchestrator                  │
    │  1. Fetch Jira incident metadata            │
    │  2. Lookup Slack channel from Redis         │
    │  3. Collect Slack messages + 📌 markers     │
    │  4. Assemble data packet                    │
    │  5. Generate PIR using Claude AI            │
    │  6. Save PIR to filesystem                  │
    │  7. Publish completion event to Redis       │
    └─────────────────────────────────────────────┘
                          ↓
    ┌─────────────────────────────────────────────┐
    │      Redis Pub/Sub: coreline:pir:completed     │
    └─────────────────────────────────────────────┘
```

---

## Prerequisites

### Required Secrets

The service requires the following credentials (loaded via Coreline secrets manager):

1. **Anthropic API Key** (`ANTHROPIC_API_KEY`)
   - Obtain from: https://console.anthropic.com
   - Permissions: Access to Claude Sonnet 4.5 model

2. **Jira API Token** (`JIRA_API_TOKEN`, `JIRA_EMAIL`)
   - Obtain from: https://id.atlassian.com/manage-profile/security/api-tokens
   - Permissions: Read access to Security Incident issues

3. **Slack Bot Token** (`SLACK_BOT_TOKEN`)
   - Obtain from: Slack App configuration
   - Required scopes: `channels:history`, `channels:read`, `users:read`, `reactions:read`

### External Dependencies

- **Redis**: Pub/Sub messaging (channel tracking and event distribution)
- **Jira**: Incident metadata source
- **Slack**: Incident response logs and evidence markers

---

## Configuration

### Environment Variables

All configuration uses the `CORELINE_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `CORELINE_ENVIRONMENT` | `prod` | Deployment environment (dev/staging/prod) |
| `CORELINE_PORT` | `8082` | HTTP server port |
| `CORELINE_REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `CORELINE_INCIDENT_CHANNEL_NAME` | `coreline:incident:created` | Redis Pub/Sub input channel |
| `CORELINE_PIR_COMPLETED_CHANNEL` | `coreline:pir:completed` | Redis Pub/Sub output channel |
| `CORELINE_CLAUDE_MODEL` | `claude-sonnet-4-5` | Claude model for generation |
| `CORELINE_CLAUDE_MAX_TOKENS` | `16000` | Max tokens for Claude response |
| `CORELINE_PIR_OUTPUT_DIR` | `/output/pirs` | Directory for generated PIRs |
| `CORELINE_GENERATE_PIR_ON_STATUS` | `["Resolved","Closed"]` | Jira statuses triggering PIR |
| `CORELINE_SKIP_PIR_IF_EXISTS` | `true` | Skip if PIR file already exists |
| `CORELINE_SLACK_MESSAGE_LIMIT` | `1000` | Max Slack messages to fetch |
| `CORELINE_JIRA_SERVER` | `https://pantheon.atlassian.net` | Jira server URL |
| `CORELINE_LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `CORELINE_LOG_JSON` | `true` | Use JSON logging for Cloud Logging |

### Configuration File

Create `.env` file:

```bash
# Service Configuration
CORELINE_ENVIRONMENT=dev
CORELINE_PORT=8082

# Redis
CORELINE_REDIS_URL=redis://localhost:6379/0

# Anthropic (from secrets manager)
CORELINE_ANTHROPIC_API_KEY=sk-ant-...

# Jira (from secrets manager)
CORELINE_JIRA_SERVER=https://pantheon.atlassian.net
CORELINE_JIRA_EMAIL=your-email@example.com
CORELINE_JIRA_API_TOKEN=your-jira-token

# Slack (from secrets manager)
CORELINE_SLACK_BOT_TOKEN=xoxb-...

# PIR Generation
CORELINE_CLAUDE_MODEL=claude-sonnet-4-5
CORELINE_PIR_OUTPUT_DIR=/output/pirs
```

---

## Quick Start

### 1. Install Dependencies

```bash
# From the repo root, into an isolated venv:
pip install -r services/brain_service/requirements.txt
```

### 2. Start Redis (Local Development)

```bash
docker run -d --name coreline-redis -p 6379:6379 redis:7-alpine
```

### 3. Configure Secrets

```bash
# Option 1: Environment variables
export CORELINE_ANTHROPIC_API_KEY=sk-ant-...
export CORELINE_JIRA_API_TOKEN=...
export CORELINE_JIRA_EMAIL=...
export CORELINE_SLACK_BOT_TOKEN=...

# Option 2: .env file
cp .env.template .env
# Edit .env with your credentials
```

### 4. Start Service

```bash
# From the repo root (imports resolve as services.brain_service.*):
uvicorn services.brain_service.main:app --host 0.0.0.0 --port 8082
```

Service will start on http://localhost:8082

### 5. Verify Health

```bash
# Liveness check
curl http://localhost:8082/health

# Readiness check (verifies Redis + credentials)
curl http://localhost:8082/ready
```

---

## Docker Deployment

### Build Image

```bash
# From repository root
docker build -f services/coreline-brain-service/Dockerfile -t coreline-brain-service:latest .
```

### Run Container

```bash
docker run -d \
  --name coreline-brain-service \
  -p 8082:8082 \
  -e CORELINE_REDIS_URL=redis://host.docker.internal:6379 \
  -e CORELINE_ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e CORELINE_JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e CORELINE_JIRA_EMAIL=$JIRA_EMAIL \
  -e CORELINE_SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN \
  -v /output/pirs:/output/pirs \
  coreline-brain-service:latest
```

### Check Logs

```bash
# Follow logs
docker logs -f coreline-brain-service

# Search for PIR generation events
docker logs coreline-brain-service | grep PIR_GENERATED
```

---

## Usage

### Automated PIR Generation

Once running, the service automatically:

1. **Listens** for incident events on Redis channel `coreline:incident:created`
2. **Filters** for incidents with status "Resolved" or "Closed"
3. **Generates** PIR using Claude AI
4. **Saves** to `/output/pirs/{INCIDENT_ID}-{TIMESTAMP}.md`
5. **Publishes** completion event to `coreline:pir:completed`

### Manual Testing

Trigger PIR generation manually by publishing a test event to Redis:

```bash
# Using redis-cli
redis-cli PUBLISH coreline:incident:created '{
  "incident_id": "INC-TEST-001",
  "summary": "Test incident for PIR generation",
  "priority": "P2",
  "severity": "Medium",
  "detection_time": "2026-05-26T10:00:00Z",
  "webhook_event": "jira:issue_updated",
  "jira_url": "https://pantheon.atlassian.net/browse/INC-TEST-001"
}'
```

Then check if PIR was generated:

```bash
ls /output/pirs/INC-TEST-001-*.md
```

---

## Monitoring & Observability

### Health Endpoints

- **`GET /health`**: Liveness probe (returns 200 if service is running)
- **`GET /ready`**: Readiness probe (checks Redis connectivity and credentials)
- **`POST /pir/generate`**: Synchronous PIR entrypoint. Body is an `IncidentEvent`
  (same schema as the Pub/Sub path). Drives one orchestration run and returns
  `{incident_id, generated, pir_path, preview}`. Complements the event-driven path.

### Structured Logs

All logs are JSON-formatted for SIEM integration:

```json
{
  "event": "pir_orchestrator.generation_started",
  "incident_id": "INC-42",
  "channel_id": "C01234567",
  "model": "claude-sonnet-4-5",
  "timestamp": "2026-05-26T10:30:00Z",
  "msg": "Starting PIR generation"
}
```

### Key Log Events

- `service.started` - Service initialization complete
- `pir_subscriber.incident_received` - Incident event received from Redis
- `pir_orchestrator.generation_started` - PIR generation initiated
- `pir_orchestrator.pir_saved` - PIR successfully generated and saved
- `pir_orchestrator.published_completion` - Completion event published to Redis

---

## Troubleshooting

### Service Won't Start

**Symptom**: Service exits immediately with `service.startup_failed`

**Check**:
1. Redis connectivity: `redis-cli PING` (should return `PONG`)
2. Required secrets loaded: Check logs for `service.secrets_loaded`
3. Port availability: `lsof -i :8082` (should be empty)

### PIR Generation Skipped

**Symptom**: Logs show `pir_orchestrator.skipped_status`

**Reason**: Incident status is not in `CORELINE_GENERATE_PIR_ON_STATUS` list

**Fix**: 
- Verify incident is marked as "Resolved" or "Closed" in Jira
- Or update `CORELINE_GENERATE_PIR_ON_STATUS` to include desired statuses

### No Slack Channel Found

**Symptom**: Logs show `pir_orchestrator.no_channel`

**Reason**: Slack channel not tracked in Redis (incident may predate slack-orchestrator)

**Impact**: PIR will be generated from Jira data only (no Slack logs)

**Workaround**: PIR is still valid but may lack Slack evidence

### Claude API Errors

**Symptom**: `pir_orchestrator.generation_failed` with Anthropic API error

**Common Causes**:
- Invalid API key: Check `CORELINE_ANTHROPIC_API_KEY`
- Rate limits: Claude API throttling (wait and retry)
- Token limits: Incident logs too large (reduce `CORELINE_SLACK_MESSAGE_LIMIT`)

---

## Development

### Run Tests

Offline — no live LLM, no network, `fakeredis` + `FakePIRProvider`:

```bash
# From the repo root:
pytest services/brain_service/tests/
```

### Enable Debug Logging

```bash
export CORELINE_LOG_LEVEL=DEBUG
python main.py
```

### Enable Swagger UI

```bash
export CORELINE_ENABLE_SWAGGER=true
python main.py
# Visit http://localhost:8082/docs
```

---

## Security Considerations

1. **Non-Root User**: Container runs as UID 10001 (FedRAMP compliance)
2. **Secret Management**: Credentials loaded via Coreline secrets manager (not hardcoded)
3. **Audit Logging**: All PIR generation events logged for compliance
4. **PII Redaction**: Slack logs automatically scrubbed for emails, SSNs, API keys
5. **Prompt Injection Defense**: Claude system prompt treats incident data as untrusted

---

## Performance

### Typical Metrics

- **PIR Generation Time**: 15-30 seconds (depends on Slack log volume)
- **Resource Usage**: ~200MB memory, <5% CPU (idle)
- **Throughput**: 2-4 PIRs per minute (Claude API rate limit dependent)

---

## Related Documentation

- [Coreline-BRAIN-USAGE.md](/docs/Coreline-BRAIN-USAGE.md) - CLI usage guide
- [Coreline-BRAIN-Anthropic.md](/docs/Coreline-BRAIN-Anthropic.md) - Claude API setup
- [claude-pir-system-prompt.md](/prompts/claude-pir-system-prompt.md) - Coreline-Brain persona
- [SECURITY_THREAT_MODEL.md](/SECURITY_THREAT_MODEL.md) - Security guardrails

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/pantheon-systems/coreline/issues
- Security Contact: security@example.com

---

**Version**: 1.0.0  
**Last Updated**: 2026-05-26  
**Maintained by**: Coreline Security Operations
