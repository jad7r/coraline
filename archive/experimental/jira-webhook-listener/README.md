# Coreline Jira Webhook Listener

**Status**: ✅ MVP Complete  
**Version**: 1.0.0  
**Last Updated**: 2026-05-23

Receives and validates Jira security incident webhooks, implementing security guardrails before triggering downstream incident response automation.

---

## Overview

The Jira Webhook Listener is the first component in the Coreline incident response workflow:

```
Jira (Security Incident Created)
  ↓
Jira Webhook Listener (THIS SERVICE)
  ├─ HMAC Verification (G2.1)
  ├─ Replay Prevention (G2.2)
  ├─ Schema Validation (G2.3)
  └─ Audit Logging → SIEM
  ↓
[Future: Slack Orchestrator]
```

**Security Guardrails Implemented**:
- **G2.1**: HMAC-SHA256 signature verification
- **G2.2**: Replay attack prevention (timestamp + Redis tracking)
- **G2.3**: Pydantic schema validation with sanitization

---

## Quick Start

### Prerequisites

**Required**:
- Python 3.11+
- Redis 7.x
- Pydantic v2.x (v2.12.5+)

**Note**: This service uses **Pydantic v2** with `pydantic-settings` for configuration. The migration from Pydantic v1 includes:
- `BaseSettings` imported from `pydantic_settings` (not `pydantic`)
- Field validators use `pattern=` instead of `regex=`
- Compatible with both local development and containerized deployments

### 1. Install Dependencies

```bash
cd services/jira-webhook-listener
pip install -r requirements.txt
```

**Key dependencies**:
- `fastapi==0.110.0` - Web framework
- `uvicorn==0.27.1` - ASGI server
- `pydantic==2.12.5` - Data validation (v2.x required)
- `pydantic-settings==2.5.2` - Configuration management
- `redis[hiredis]==5.0.1` - Replay prevention
- `google-cloud-secret-manager==2.18.2` - Secrets management
- `cryptography==42.0.5` - Encryption utilities

### 2. Configure Environment

```bash
# Set environment variables
export CORELINE_ENVIRONMENT=dev
export CORELINE_REDIS_URL=redis://localhost:6379/0
```

**Required Secrets** (from Google Secret Manager or local .env):
- `JIRA_WEBHOOK_SECRET` - HMAC secret for signature verification

### 3. Run Service

```bash
# Development mode (auto-reload)
python main.py

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8080
```

### 4. Verify Service is Running

```bash
# Health check
curl http://localhost:8080/health

# Readiness probe
curl http://localhost:8080/ready
```

---

## API Endpoints

### POST /webhook

Receives Jira security incident webhooks.

**Request Headers**:
```
X-Hub-Signature: sha256=<hmac_signature>
Content-Type: application/json
```

**Request Body**:
```json
{
  "webhookEvent": "jira:issue_created",
  "timestamp": "2026-05-20T14:32:00Z",
  "webhookEventId": "unique-webhook-id",
  "issue": {
    "key": "INC-42",
    "fields": {
      "issuetype": {"name": "Security Incident"},
      "priority": {"name": "P1"},
      "summary": "Suspicious login attempts detected",
      "status": {"name": "Open"}
    }
  }
}
```

**Responses**:
- `200 OK` - Webhook processed successfully
- `400 Bad Request` - Invalid schema or stale webhook
- `401 Unauthorized` - HMAC verification failed
- `409 Conflict` - Duplicate webhook detected
- `500 Internal Server Error` - Unexpected error

### GET /health

Basic health check (returns 200 if service is alive).

### GET /ready

Readiness probe (checks Redis connectivity and component initialization).

---

## Architecture

### Components

```
services/jira-webhook-listener/
├── security/
│   ├── hmac_verifier.py        # HMAC-SHA256 signature verification
│   └── replay_prevention.py    # Timestamp + Redis duplicate tracking
├── models/
│   ├── webhook.py              # Pydantic models for Jira webhooks
│   └── audit.py                # Audit event schemas
├── handlers/
│   ├── webhook_handler.py      # Core processing logic
│   └── audit_logger.py         # SIEM event emitter
├── routes/
│   ├── webhooks.py             # FastAPI webhook endpoint
│   └── health.py               # Health check endpoints
├── config.py                   # Environment configuration
└── main.py                     # FastAPI application
```

### Processing Flow

```
1. Receive POST /webhook
   ↓
2. Verify HMAC signature (constant-time comparison)
   ├─ FAIL → HTTP 401 + audit log → reject
   └─ PASS → continue
   ↓
3. Validate JSON schema (Pydantic)
   ├─ FAIL → HTTP 400 + audit log → reject
   └─ PASS → continue
   ↓
4. Check timestamp freshness (max 5 minutes old)
   ├─ FAIL → HTTP 400 + audit log → reject
   └─ PASS → continue
   ↓
5. Check Redis for duplicate webhook ID
   ├─ FAIL → HTTP 409 + audit log → reject
   └─ PASS → continue
   ↓
6. Mark webhook ID as processed in Redis (24h TTL)
   ↓
7. Emit JIRA_WEBHOOK_RECEIVED audit event → Cloud Logging → Chronicle
   ↓
8. Return HTTP 200 OK
```

**Performance Target**: <500ms end-to-end (p95)

---

## Configuration

### Environment Variables

All configuration via environment variables with `CORELINE_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `CORELINE_ENVIRONMENT` | `prod` | Deployment environment (dev, staging, prod) |
| `CORELINE_REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `CORELINE_MAX_WEBHOOK_AGE_SECONDS` | `300` | Maximum webhook age (5 minutes) |
| `CORELINE_WEBHOOK_ID_TTL_SECONDS` | `86400` | Webhook ID TTL in Redis (24 hours) |
| `CORELINE_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `CORELINE_PORT` | `8080` | HTTP server port |
| `CORELINE_ENABLE_SWAGGER` | `false` | Enable Swagger UI (dev only) |

### Secrets Management

Secrets loaded from Google Secret Manager:

**Production**:
```python
# Automatic in GCP environment
secrets = initialize_secrets(environment="prod", fail_fast=True)
webhook_secret = secrets.get_jira_webhook_secret()
```

**Local Development**:
```bash
# Create .env.encrypted file (see services/shared/secrets_manager.py)
# Or use environment variable fallback
export JIRA_WEBHOOK_SECRET=your-test-secret
```

---

## Security

### HMAC Signature Verification (G2.1)

**Algorithm**: HMAC-SHA256  
**Header**: `X-Hub-Signature: sha256=<hex_signature>`  
**Secret**: Stored in Google Secret Manager (`coreline-{env}-jira-webhook-secret`)

**Implementation**:
- Constant-time comparison (`hmac.compare_digest()`) prevents timing attacks
- Never logs signature values or secrets
- Rejects webhooks with missing/invalid signatures immediately

### Replay Attack Prevention (G2.2)

**Two-layer protection**:
1. **Timestamp validation**: Rejects webhooks older than 5 minutes
2. **Redis tracking**: Stores processed webhook IDs with 24-hour TTL

**Fail-open strategy**: If Redis is unavailable, accepts webhook but logs warning  
**Rationale**: Availability > strict replay prevention for incident response

### Schema Validation (G2.3)

**Security features**:
- Strict regex validation on issue keys (`^[A-Z]+-\d+$`)
- Path traversal prevention (rejects keys with `../`, `/`, `\`)
- Field length limits (prevents DoS via large payloads)
- Text field sanitization (strips control characters, normalizes Unicode)

---

## Monitoring & Observability

### Audit Events

All operations emit structured audit events to Cloud Logging → Chronicle SIEM:

**Event Types**:
- `JIRA_WEBHOOK_RECEIVED` - Successful webhook processing
- `JIRA_WEBHOOK_AUTH_FAILURE` - HMAC verification failed
- `JIRA_WEBHOOK_REPLAYED` - Duplicate webhook detected
- `JIRA_WEBHOOK_VALIDATION_ERROR` - Schema validation failed
- `SERVICE_STARTED` / `SERVICE_STOPPED` - Lifecycle events

**Event Schema**:
```json
{
  "event_id": "uuid",
  "event_type": "JIRA_WEBHOOK_RECEIVED",
  "timestamp": "2026-05-20T14:32:00Z",
  "service": "jira-webhook-listener",
  "environment": "prod",
  "success": true,
  "incident_id": "INC-42",
  "duration_ms": 245,
  "metadata": {
    "priority": "P1",
    "severity": "Critical"
  }
}
```

### Metrics

**Key metrics** (to be added in Phase 2):
- Webhook processing latency (p50, p95, p99)
- HMAC verification failure rate
- Replay attack detection rate
- Redis connection errors
- Endpoint availability (uptime)

---

## Deployment

### Docker

**Build from monorepo root** (Coreline/):

```bash
# Navigate to monorepo root
cd /path/to/Coreline

# Build image (must be run from Coreline/ directory)
docker build -f services/jira-webhook-listener/Dockerfile \
  -t coreline-jira-webhook-listener:latest .

# Verify build
docker images coreline-jira-webhook-listener:latest
# Expected: ~413MB image, created seconds ago
```

**Run container**:

```bash
# Start Redis (if not already running)
docker run -d --name coreline-redis -p 6379:6379 redis:7-alpine

# Run webhook listener
docker run -d --name coreline-webhook-listener \
  -p 8080:8080 \
  -e CORELINE_ENVIRONMENT=prod \
  -e CORELINE_REDIS_URL=redis://host.docker.internal:6379/0 \
  -e JIRA_WEBHOOK_SECRET=your-secret-here \
  coreline-jira-webhook-listener:latest

# Verify service is running
docker logs coreline-webhook-listener
curl http://localhost:8080/health
```

**Docker image details**:
- **Base image**: `python:3.11-slim`
- **Size**: ~413MB
- **User**: `coreline` (UID 10001, GID 10001) - non-privileged
- **Working directory**: `/app`
- **Entry point**: `uvicorn main:app --host 0.0.0.0 --port 8080 --workers 1`
- **Shared libraries**: Includes `services/shared/` for secrets management

**Important**: The Dockerfile uses paths relative to the Coreline/ monorepo root. Building from the service directory will fail.

### Cloud Run

```bash
# Deploy to Cloud Run
gcloud run deploy coreline-jira-webhook-listener \
  --image gcr.com/PROJECT_ID/coreline-webhook-listener:latest \
  --platform managed \
  --region us-central1 \
  --set-env-vars CORELINE_ENVIRONMENT=prod \
  --set-env-vars CORELINE_REDIS_URL=redis://memorystore-ip:6379/0 \
  --min-instances 1 \
  --max-instances 10 \
  --memory 512Mi \
  --cpu 1
```

---

## Testing

### Quick Validation (No Dependencies)

Pure Python logic validation without external dependencies:

```bash
cd services/jira-webhook-listener
python3 tests/quick_validation.py
```

**Validates**:
- ✅ HMAC signature verification logic
- ✅ Timestamp freshness calculation
- ✅ Webhook payload structure
- ✅ Mock webhook generator
- ✅ Constant-time comparison (timing attack resistance)

**Expected output**: All security guardrails validated (G2.1, G2.2, G2.3)

### Mock Webhook Sender

Comprehensive integration testing with real webhooks:

```bash
# Start the service first
python main.py

# In another terminal, run mock tests
cd services/jira-webhook-listener
python3 tests/mock_jira_webhook_sender.py --run-tests
```

**Test scenarios**:
1. ✅ Valid P1 Security Incident
2. ❌ Invalid HMAC signature (should reject with 401)
3. ❌ Missing HMAC signature (should reject with 401)
4. ❌ Stale timestamp - 10 minutes old (should reject with 400)
5. ❌ Duplicate webhook ID (should reject with 409)
6. ✅ Multiple distinct webhooks (should accept all)

**Custom webhook**:
```bash
python3 tests/mock_jira_webhook_sender.py \
  --incident-id "INC-123" \
  --summary "Custom security incident" \
  --priority "P1" \
  --severity "Critical"
```

### Unit Tests

```bash
pytest tests/test_hmac_verifier.py
pytest tests/test_replay_prevention.py
pytest tests/test_webhook_handler.py
```

### Integration Tests

```bash
# Requires Redis
docker run -d -p 6379:6379 redis:7-alpine

pytest tests/test_routes.py
```

### Manual Testing

```bash
# Generate valid HMAC signature
python -c "
import hmac, hashlib, json
secret = 'test-secret'
payload = json.dumps({'webhookEvent': 'jira:issue_created', 'timestamp': '2026-05-20T14:32:00Z', 'issue': {'key': 'INC-42', 'fields': {'issuetype': {'name': 'Security Incident'}, 'priority': {'name': 'P1'}, 'summary': 'Test', 'status': {'name': 'Open'}, 'created': '2026-05-20T14:32:00Z', 'updated': '2026-05-20T14:32:00Z'}}})
sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
print(f'X-Hub-Signature: sha256={sig}')
print(f'Payload: {payload}')
"

# Send test webhook
curl -X POST http://localhost:8080/webhook \
  -H "X-Hub-Signature: sha256=<signature>" \
  -H "Content-Type: application/json" \
  -d '<payload>'
```

---

## Troubleshooting

### Service won't start

**Error**: `Cannot start service without webhook secret`  
**Fix**: Ensure `JIRA_WEBHOOK_SECRET` is set in Google Secret Manager or environment

**Error**: `Cannot start service without Redis`  
**Fix**: Verify Redis is running and `CORELINE_REDIS_URL` is correct

### Webhooks rejected with HTTP 401

**Cause**: HMAC verification failure  
**Check**:
- Webhook secret matches what Jira is configured with
- Signature header format is `sha256=<hex>`
- Payload hasn't been modified in transit

### Webhooks rejected with HTTP 409

**Cause**: Duplicate webhook ID detected  
**Expected**: This is replay prevention working correctly  
**Action**: Check Jira for duplicate webhook configurations

### Redis connection errors

**Symptom**: Service accepts webhooks but logs Redis errors  
**Impact**: Replay prevention degraded (fail-open)  
**Fix**: Restore Redis connectivity

### Docker build failures

**Error**: `"/jira-webhook-listener": not found` during COPY  
**Cause**: Building from wrong directory or incorrect COPY paths  
**Fix**: 
```bash
# Build from Coreline/ root, not service directory
cd /path/to/Coreline  
docker build -f services/jira-webhook-listener/Dockerfile -t coreline-jira-webhook-listener:latest .
```

**Error**: `cannot import name 'CorelineConfig' from 'config'`  
**Cause**: Wrong class name - Pydantic v2 uses `Settings`  
**Fix**: Import `Settings` class:
```python
from config import Settings
settings = Settings()
```

**Error**: `BaseSettings not found in pydantic`  
**Cause**: Pydantic v2 moved BaseSettings to separate package  
**Fix**: Ensure `pydantic-settings==2.5.2` is installed:
```bash
pip install pydantic-settings==2.5.2
```

---

## Next Steps

### Phase 2 Enhancements

- [ ] Message queue integration (Redis Pub/Sub for slack-orchestrator)
- [ ] Prometheus metrics endpoint
- [ ] Grafana dashboard
- [ ] Load testing and performance validation
- [ ] Advanced rate limiting (per-IP sliding window)

---

## Support

**Issues**: #security-engineering (Slack)  
**Documentation**: `/docs/Coreline-BRAIN-USAGE.md`  
**Compliance**: ISO 27001 A.16.1.4, FedRAMP IR-4

---

**Maintained by**: Coreline Security Operations
