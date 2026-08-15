# Coreline Slack Orchestrator

**Status**: ✅ Ready for Testing  
**Version**: 1.0.0  
**Last Updated**: 2026-05-21

Automated Slack incident channel creation from Jira security incident webhooks.

---

## Overview

The Slack Orchestrator is the second component of the Coreline-Comm workflow. It receives incident notifications from the Jira webhook listener via Redis Pub/Sub and automatically creates private Slack incident response channels.

**Workflow Position**:
```
Jira Incident → [jira-webhook-listener] → Redis Pub/Sub → [slack-orchestrator] → Slack Channel
```

**What It Does**:
1. Subscribes to Redis Pub/Sub channel `coreline:incident:created`
2. Receives incident notifications from jira-webhook-listener
3. Creates private Slack channel with naming convention: `sec-ops-inc-{year}-{number}`
4. Invites configured response team members
5. Posts initial incident summary with rich formatting (Block Kit)
6. Sets channel topic/description with incident metadata
7. Prevents duplicate channels using Redis tracking
8. Emits audit events to SIEM via Cloud Logging

---

## Quick Start

### Prerequisites

# > Revived per ADR-0003. Now lives at `services/slack_orchestrator/` in the
# > active tree and imports as the package `services.slack_orchestrator`
# > (secrets come from `services.shared`). Run all commands from the repo root.

```bash
# Install dependencies (isolated venv, from repo root)
python3 -m venv services/slack_orchestrator/.venv
services/slack_orchestrator/.venv/bin/pip install \
  -r services/slack_orchestrator/requirements.txt

# Install Redis (if not already running)
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# Docker (alternative)
docker run -d -p 6379:6379 --name redis redis:7-alpine
```

### Configuration

```bash
# Copy environment template
cp .env.template .env

# Edit .env with your settings
vim .env
```

**Required Environment Variables**:
```bash
CORELINE_ENVIRONMENT=dev
CORELINE_REDIS_URL=redis://localhost:6379/0
CORELINE_INCIDENT_CHANNEL_NAME=coreline:incident:created
CORELINE_RESPONSE_TEAM_USER_IDS='["U01234567", "U89ABCDEF"]'  # JSON array of Slack user IDs

# Slack bot token: read from SLACK_BOT_TOKEN env var, OR from the OS keychain
# (service "Coreline", key "slack_bot_token") via services.shared — never hardcoded.
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
```

### Run Service

```bash
# Development mode (run as a module from the repo root)
export CORELINE_ENVIRONMENT=dev
export CORELINE_REDIS_URL=redis://localhost:6379/0
export SLACK_BOT_TOKEN=xoxb-your-token
export CORELINE_RESPONSE_TEAM_USER_IDS='["U01234567"]'
services/slack_orchestrator/.venv/bin/python -m services.slack_orchestrator.main
# or: uvicorn services.slack_orchestrator.main:app --port 8081

# Production mode (via Docker — build from the REPO ROOT so `services` is importable)
docker build -f services/slack_orchestrator/Dockerfile -t coreline-slack-orchestrator:latest .
docker run -d \
  --name coreline-slack-orchestrator \
  -p 8081:8081 \
  -e CORELINE_ENVIRONMENT=prod \
  -e CORELINE_REDIS_URL=redis://host.docker.internal:6379/0 \
  -e CORELINE_RESPONSE_TEAM_USER_IDS='["U01234567"]' \
  coreline-slack-orchestrator:latest
```

**Health Checks**:
```bash
# Liveness probe (is service running?)
curl http://localhost:8081/health

# Readiness probe (can service handle requests?)
curl http://localhost:8081/ready
```

---

## Architecture

### Data Flow

```
┌──────────────────────────────────────────────────────────┐
│ 1. Jira → Webhook (Security Incident Created)           │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 2. jira-webhook-listener                                 │
│    - Validate HMAC, schema, replay                       │
│    - PUBLISH to Redis: "coreline:incident:created"           │
└────────────────────┬─────────────────────────────────────┘
                     │ Redis Pub/Sub
                     │ Message: IncidentEvent JSON
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 3. slack-orchestrator (Subscriber)                       │
│    - Receive IncidentEvent                               │
│    - Check duplicate (Redis tracking)                    │
│    - Create private Slack channel                        │
│    - Invite response team                                │
│    - Post incident summary                               │
│    - Emit audit event                                    │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 4. Slack Workspace                                       │
│    Channel: #sec-ops-inc-2026-042                        │
│    - Response team invited                               │
│    - Summary pinned                                      │
│    - Topic: "🚨 Critical | INC-42 | IC: Josh"            │
└──────────────────────────────────────────────────────────┘
```

### Component Diagram

```
services/slack-orchestrator/
├── main.py                          # FastAPI app + lifespan manager
├── config.py                        # Pydantic Settings (CORELINE_ prefix)
│
├── handlers/
│   ├── slack_channel_creator.py    # Core channel creation logic
│   ├── incident_subscriber.py      # Redis Pub/Sub subscriber
│   └── audit_logger.py              # SIEM audit event emission
│
├── models/
│   ├── incident_event.py            # IncidentEvent Pydantic model
│   └── audit.py                     # Audit event models
│
├── utils/
│   ├── channel_naming.py            # Channel name generation
│   └── duplicate_tracker.py         # Redis-based duplicate prevention
│
└── routes/
    └── health.py                    # /health and /ready endpoints
```

---

## Channel Naming Convention

**Pattern**: `sec-ops-inc-{year}-{number}`

**Examples**:
- `INC-42` → `sec-ops-inc-2026-042`
- `INC-2026-001` → `sec-ops-inc-2026-001`
- `INCIDENT-123` → `sec-ops-inc-2026-123`

**Edge Cases**:
- **Name collision** (rare): Append timestamp suffix → `sec-ops-inc-2026-042-0521-1430`
- **Large numbers**: INC-999999 → `sec-ops-inc-2026-999999` (no truncation)
- **Year boundary**: Incident on 2025-12-31 uses `sec-ops-inc-2025-...`

---

## Incident Event Schema

**Redis Channel**: `coreline:incident:created`  
**Publisher**: jira-webhook-listener  
**Consumer**: slack-orchestrator

**JSON Format**:
```json
{
  "incident_id": "INC-42",
  "summary": "Suspected ransomware on PROD-FILE-01",
  "priority": "P1",
  "severity": "Critical",
  "incident_commander": "Josh Dellinger",
  "detection_time": "2026-05-21T14:32:00.123Z",
  "affected_systems": ["PROD-FILE-01", "PROD-BACKUP-02"],
  "webhook_event": "jira:issue_created",
  "jira_url": "https://pantheon.atlassian.net/browse/INC-42"
}
```

---

## Duplicate Prevention

**Purpose**: Prevent creating duplicate channels if Jira sends multiple webhook events (issue_created + issue_updated)

**Redis Key Pattern**:
```
Key: coreline:slack:channel:INC-42
Value: C01234567  (Slack channel ID)
TTL: 90 days
```

**Behavior**:
- Before creating channel: Check Redis for existing channel ID
- If exists: Log and return existing channel ID (skip creation)
- After creating: Store channel ID in Redis with 90-day TTL

---

## Slack Bot Permissions

Required Slack app scopes:
- `channels:write` - Create channels
- `channels:read` - List channels
- `chat:write` - Post messages
- `pins:write` - Pin messages
- `groups:write` - Create private channels
- `groups:read` - List private channels

**To configure**:
1. Go to https://api.slack.com/apps
2. Select your Slack app
3. Navigate to **OAuth & Permissions**
4. Add **Bot Token Scopes**
5. Reinstall app to workspace

---

## Response Team Configuration

**Option 1: Static User IDs** (Current Implementation)

Find Slack user IDs:
1. Click user's profile in Slack
2. Click **More** → **Copy member ID**
3. Add to environment variable:

```bash
CORELINE_RESPONSE_TEAM_USER_IDs='["U01234567", "U89ABCDEF", "U0FEDCBA"]'
```

**Option 2: Slack User Group** (Future Enhancement)

Query Slack API for user group members dynamically:
```python
response = slack_client.usergroups_users_list(usergroup="S01234567")
user_ids = response['users']
```

---

## Error Handling

### Slack API Rate Limits
- **Strategy**: Exponential backoff with retry (max 3 attempts)
- **Behavior**: Retry with increasing delays (2s, 4s, 8s)
- **Failure**: Log error, emit failed audit event, raise exception

### Channel Name Collisions
- **Strategy**: Append timestamp suffix
- **Behavior**: Retry with `{channel_name}-MMDD-HHMM`
- **Example**: `sec-ops-inc-2026-042-0521-1430`

### User Invitation Failures
- **Strategy**: Non-fatal logging
- **Behavior**: Log error but don't fail channel creation
- **Rationale**: Team can manually join via Slack search

### Redis Connection Lost
- **Strategy**: Health check failure → auto-restart
- **Behavior**: `/ready` returns HTTP 503 → Cloud Run restarts service
- **Recovery**: Subscriber reconnects automatically on startup

### Invalid Incident Events
- **Strategy**: Log and skip
- **Behavior**: Validate with Pydantic, log validation errors, continue processing
- **Rationale**: Don't crash subscriber on malformed messages

---

## Monitoring & Observability

### Key Metrics (Cloud Logging)

**Channel Creation Rate**:
```
service=slack-orchestrator AND event_type=INCIDENT_CHANNEL_CREATED
```

**Duplicate Prevention**:
```
service=slack-orchestrator AND msg="Channel already exists"
```

**Slack API Errors**:
```
service=slack-orchestrator AND error_code=*
```

**Processing Latency** (slow channel creation):
```
service=slack-orchestrator AND duration_ms > 5000
```

### Audit Events

**INCIDENT_CHANNEL_CREATED** (Success):
```json
{
  "event_type": "INCIDENT_CHANNEL_CREATED",
  "service": "slack-orchestrator",
  "success": true,
  "incident_id": "INC-42",
  "resource": {
    "type": "slack_channel",
    "id": "C01234567",
    "name": "sec-ops-inc-2026-042"
  },
  "metadata": {
    "priority": "P1",
    "severity": "Critical",
    "team_members_invited": 5
  },
  "duration_ms": 1247
}
```

**INCIDENT_CHANNEL_CREATED** (Failure):
```json
{
  "event_type": "INCIDENT_CHANNEL_CREATED",
  "service": "slack-orchestrator",
  "success": false,
  "incident_id": "INC-42",
  "error_message": "Slack API error: rate_limited",
  "error_code": "SlackApiError",
  "duration_ms": 8245
}
```

---

## Testing

Unit tests run fully offline — no live Redis or Slack. Redis is replaced with
`fakeredis` and the Slack `WebClient` with an in-test stub. Run from the repo
root:

```bash
PYTHONPATH=. services/slack_orchestrator/.venv/bin/python \
  -m pytest services/slack_orchestrator/tests \
  -c services/slack_orchestrator/pytest.ini
```

Coverage: `/health` + `/ready` routes, channel-name generation, the
Redis-backed duplicate tracker, and the full `SlackChannelCreator` flow
(create → topic/purpose → invite → post/pin → dedupe).

**Manual Redis smoke test** (requires a live Redis):
```bash
# Publish test incident event to Redis
python3 << 'EOF'
import redis
import json
from datetime import datetime

r = redis.Redis(host='localhost', port=6379)

incident = {
    "incident_id": "INC-TEST-001",
    "summary": "Test incident for validation",
    "priority": "P1",
    "severity": "Critical",
    "detection_time": datetime.utcnow().isoformat() + "Z",
    "webhook_event": "jira:issue_created",
    "jira_url": "https://jira.example.com/INC-TEST-001"
}

r.publish("coreline:incident:created", json.dumps(incident))
print("✅ Test incident published to Redis")
EOF

# Check Slack Orchestrator logs for channel creation
# Check Slack workspace for new channel: #sec-ops-inc-2026-test-001
```

---

## Deployment

### Cloud Run Configuration

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: coreline-slack-orchestrator
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"    # Keep warm for Pub/Sub
        autoscaling.knative.dev/maxScale: "10"
    spec:
      containerConcurrency: 80
      containers:
      - image: gcr.com/PROJECT_ID/coreline-slack-orchestrator:latest
        env:
        - name: CORELINE_ENVIRONMENT
          value: "prod"
        - name: CORELINE_REDIS_URL
          value: "redis://memorystore-ip:6379/0"
        - name: CORELINE_INCIDENT_CHANNEL_NAME
          value: "coreline:incident:created"
        - name: CORELINE_RESPONSE_TEAM_USER_IDS
          value: '["U01234567", "U89ABCDEF"]'
        - name: CORELINE_LOG_LEVEL
          value: "INFO"
        resources:
          limits:
            cpu: "1000m"
            memory: "512Mi"
```

### Build and Deploy

```bash
# Build Docker image
docker build -t gcr.com/PROJECT_ID/coreline-slack-orchestrator:latest .

# Push to Google Container Registry
docker push gcr.com/PROJECT_ID/coreline-slack-orchestrator:latest

# Deploy to Cloud Run
gcloud run deploy coreline-slack-orchestrator \
  --image gcr.com/PROJECT_ID/coreline-slack-orchestrator:latest \
  --platform managed \
  --region us-central1 \
  --min-instances 1 \
  --max-instances 10 \
  --memory 512Mi \
  --cpu 1 \
  --set-env-vars "CORELINE_ENVIRONMENT=prod" \
  --set-env-vars "CORELINE_REDIS_URL=redis://memorystore-ip:6379/0" \
  --set-env-vars "CORELINE_RESPONSE_TEAM_USER_IDS=[\"U01234567\"]"
```

---

## Troubleshooting

### Service won't start (exit code 1)

**Symptoms**: Service exits immediately after startup

**Possible Causes**:
1. **Missing secrets**: Check `SLACK_BOT_TOKEN` environment variable or SecretsManager
2. **Redis unavailable**: Verify `CORELINE_REDIS_URL` and Redis connectivity
3. **Slack auth failed**: Check bot token validity with `curl -H "Authorization: Bearer $SLACK_BOT_TOKEN" https://slack.com/api/auth.test`

**Fix**:
```bash
# Check logs
docker logs coreline-slack-orchestrator

# Look for:
# - "service.secret_load_failed"
# - "service.redis_connection_failed"
# - "service.slack_auth_failed"
```

### Channels not being created

**Symptoms**: Incidents logged but no Slack channels created

**Possible Causes**:
1. **Subscriber not started**: Check for "service.subscriber_stopped" in logs
2. **Redis Pub/Sub misconfiguration**: Verify channel name matches webhook listener
3. **Duplicate prevention**: Check if channel already exists in Redis

**Debug**:
```bash
# Check subscriber status in logs
docker logs coreline-slack-orchestrator | grep "incident_subscriber"

# Check Redis for existing channels
redis-cli
> KEYS coreline:slack:channel:*
> GET coreline:slack:channel:INC-42

# Manually publish test event
r.publish("coreline:incident:created", '{"incident_id":"INC-TEST",...}')
```

### Team members not invited

**Symptoms**: Channel created but team not invited

**Possible Causes**:
1. **Invalid user IDs**: Check user IDs match Slack member IDs
2. **Bot permissions**: Verify `groups:write` scope
3. **User already in channel**: Check error code `already_in_channel`

**Fix**:
```bash
# Verify user IDs
curl -H "Authorization: Bearer $SLACK_BOT_TOKEN" \
  https://slack.com/api/users.info?user=U01234567

# Check bot scopes
curl -H "Authorization: Bearer $SLACK_BOT_TOKEN" \
  https://slack.com/api/auth.test
```

---

## Security Considerations

**Secrets Management**:
- Slack bot token stored in Google Secret Manager (production)
- Never commit tokens to version control
- Rotate tokens quarterly or after exposure

**Channel Privacy**:
- All incident channels created as private (not public)
- Only invited team members can access
- Channel names don't contain sensitive information

**Audit Logging**:
- All channel creations logged to SIEM
- Failures logged with sanitized error messages
- No sensitive data (tokens, user emails) in logs

**Non-Root Execution**:
- Docker container runs as UID 10001 (FedRAMP compliance)
- No elevated privileges required

---

## Support

**Issues**: #security-engineering (Slack)  
**Documentation**: `README.md`, `TESTING.md`  
**Deployment**: Cloud Run service `coreline-slack-orchestrator`

---

**Maintained by**: Coreline Security Operations  
**Last Updated**: 2026-05-21
