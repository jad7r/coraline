# Coreline Jira Webhook Listener - Testing Guide

**Status**: ✅ Fully Testable Without Production Jira  
**Version**: 1.0.0  
**Last Updated**: 2026-05-20

This guide shows how to test the webhook listener using the mock Jira webhook sender, without requiring access to a real Jira instance.

---

## Quick Start: End-to-End Test

### Prerequisites

```bash
# Install dependencies
cd services/jira-webhook-listener
pip install -r requirements.txt

# Install Redis (if not already installed)
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# Docker (alternative)
docker run -d -p 6379:6379 --name redis redis:7-alpine
```

### Run Complete Test Suite

```bash
# Terminal 1: Start webhook listener
export CORELINE_ENVIRONMENT=dev
export CORELINE_REDIS_URL=redis://localhost:6379/0
export JIRA_WEBHOOK_SECRET=test-webhook-secret
python main.py

# Terminal 2: Run security test suite
python tests/mock_jira_webhook_sender.py --run-tests
```

**Expected Output**:
```
================================================================================
Coreline Jira Webhook Listener - Security Test Suite
================================================================================

Test 1: Valid P1 Security Incident
--------------------------------------------------------------------------------
Status Code: 200
Response: {
  "status": "success",
  "message": "Webhook processed successfully",
  "duration_ms": 45,
  "incident_id": "INC-2026-001"
}
✅ Expected: 200, Got: 200

Test 2: Invalid HMAC Signature (Security Test)
--------------------------------------------------------------------------------
Status Code: 401
Response: {
  "status": "error",
  "message": "Authentication failed: HMAC signature verification failed",
  "duration_ms": 12
}
✅ Expected: 401, Got: 401

Test 3: Missing HMAC Signature (Security Test)
--------------------------------------------------------------------------------
Status Code: 401
✅ Expected: 401, Got: 401

Test 4: Stale Timestamp - Replay Attack Prevention
--------------------------------------------------------------------------------
Status Code: 400
✅ Expected: 400, Got: 400

Test 5: Duplicate Webhook ID - Replay Detection
--------------------------------------------------------------------------------
First send - Status: 200 (should be 200)
Duplicate send - Status: 409
✅ Expected: 409, Got: 409

Test 6: Non-Security Incident (Should Accept but Ignore)
--------------------------------------------------------------------------------
Status Code: 200
Response: {
  "status": "success",
  "message": "Webhook accepted (not a Security Incident, no action taken)",
  ...
}
✅ Expected: 200, Got: 200

Test 7: Path Traversal Attack Prevention
--------------------------------------------------------------------------------
Status Code: 400
✅ Expected: 400, Got: 400

================================================================================
Test Suite Complete
================================================================================
```

---

## Docker Testing

### Build Docker Image

```bash
# From services/jira-webhook-listener directory
docker build -t coreline-webhook-listener:latest .
```

**Build output should show**:
```
[+] Building 45.2s (15/15) FINISHED
 => [builder 1/4] WORKDIR /build
 => [builder 2/4] RUN apt-get update && apt-get install...
 => [builder 3/4] COPY requirements.txt .
 => [builder 4/4] RUN pip install --no-cache-dir --user...
 => [runner 1/6] WORKDIR /app
 => [runner 2/6] RUN apt-get update && apt-get install...
 => [runner 3/6] RUN groupadd -g 10001 coreline...
 => [runner 4/6] COPY --from=builder /root/.local...
 => [runner 5/6] COPY --chown=coreline:coreline . .
 => exporting to image
 => => naming to docker.com/library/coreline-webhook-listener:latest
```

### Run Container

```bash
# Start Redis (if using Docker for Redis)
docker run -d --name redis-test -p 6379:6379 redis:7-alpine

# Run webhook listener container
docker run -d \
  --name coreline-webhook-listener \
  -p 8080:8080 \
  -e CORELINE_ENVIRONMENT=dev \
  -e CORELINE_REDIS_URL=redis://host.docker.internal:6379/0 \
  -e JIRA_WEBHOOK_SECRET=test-webhook-secret \
  coreline-webhook-listener:latest

# Check logs
docker logs -f coreline-webhook-listener
```

### Test Containerized Service

```bash
# Health check
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Send test webhook
python tests/mock_jira_webhook_sender.py --run-tests
```

### Clean Up

```bash
docker stop coreline-webhook-listener redis-test
docker rm coreline-webhook-listener redis-test
```

---

## Manual Testing Scenarios

### Scenario 1: Valid Security Incident

```bash
python tests/mock_jira_webhook_sender.py
```

**Expected**:
- HTTP 200 response
- Audit event logged to console
- Webhook ID stored in Redis

**Verify in Redis**:
```bash
redis-cli
> KEYS webhook:processed:*
> GET webhook:processed:webhook-INC-2026-TEST-1716213120
> TTL webhook:processed:webhook-INC-2026-TEST-1716213120
```

### Scenario 2: HMAC Signature Tampering

Generate webhook with corrupted signature:

```python
# In Python REPL or script
from tests.mock_jira_webhook_sender import MockJiraWebhookSender

sender = MockJiraWebhookSender()
payload = sender._create_security_incident_payload(
    incident_id="INC-TEST",
    summary="Test with bad signature"
)
response = sender.send_webhook(payload, corrupt_signature=True)
print(f"Status: {response.status_code}")  # Should be 401
```

### Scenario 3: Replay Attack

Send same webhook twice:

```python
from tests.mock_jira_webhook_sender import MockJiraWebhookSender

sender = MockJiraWebhookSender()
payload = sender._create_security_incident_payload(
    incident_id="INC-REPLAY",
    summary="Test replay attack",
    webhook_id="duplicate-test-123"
)

# First send - should succeed
response1 = sender.send_webhook(payload)
print(f"First: {response1.status_code}")  # 200

# Second send - should be rejected
response2 = sender.send_webhook(payload)
print(f"Second: {response2.status_code}")  # 409
```

### Scenario 4: Stale Timestamp

```python
from tests.mock_jira_webhook_sender import MockJiraWebhookSender

sender = MockJiraWebhookSender()

# Webhook claims to be from 10 minutes ago
payload = sender._create_security_incident_payload(
    incident_id="INC-STALE",
    summary="Old webhook",
    timestamp_offset_seconds=-600  # 10 minutes in past
)

response = sender.send_webhook(payload)
print(f"Status: {response.status_code}")  # Should be 400
```

---

## Performance Testing

### Measure Webhook Processing Latency

```python
import time
from tests.mock_jira_webhook_sender import MockJiraWebhookSender

sender = MockJiraWebhookSender()

# Send 100 webhooks and measure average latency
latencies = []
for i in range(100):
    payload = sender._create_security_incident_payload(
        incident_id=f"INC-PERF-{i}",
        summary=f"Performance test incident {i}",
        webhook_id=f"perf-test-{i}"
    )
    
    start = time.time()
    response = sender.send_webhook(payload)
    duration_ms = (time.time() - start) * 1000
    latencies.append(duration_ms)
    
    if response.status_code != 200:
        print(f"Failed: {response.status_code}")

# Calculate statistics
import statistics
print(f"Average: {statistics.mean(latencies):.2f}ms")
print(f"Median: {statistics.median(latencies):.2f}ms")
print(f"P95: {statistics.quantiles(latencies, n=20)[18]:.2f}ms")
print(f"P99: {statistics.quantiles(latencies, n=100)[98]:.2f}ms")
```

**Target**: <500ms p95 latency

---

## Security Validation Checklist

After running tests, verify:

- [ ] **HMAC Verification**
  - [ ] Valid signatures accepted (HTTP 200)
  - [ ] Invalid signatures rejected (HTTP 401)
  - [ ] Missing signatures rejected (HTTP 401)
  - [ ] No HMAC secrets logged to console/files

- [ ] **Replay Prevention**
  - [ ] Fresh timestamps accepted (<5 min old)
  - [ ] Stale timestamps rejected (>5 min old)
  - [ ] Duplicate webhook IDs rejected (HTTP 409)
  - [ ] Redis stores webhook IDs with 24h TTL

- [ ] **Schema Validation**
  - [ ] Valid payloads accepted
  - [ ] Malformed JSON rejected (HTTP 400)
  - [ ] Path traversal attempts rejected (`../` in issue keys)
  - [ ] Issue key regex enforced (`^[A-Z]+-\d+$`)

- [ ] **Audit Logging**
  - [ ] All webhook receipts logged to console
  - [ ] Auth failures logged with error codes
  - [ ] Replay attacks logged with webhook IDs
  - [ ] No sensitive data in logs (check for secrets/tokens)

- [ ] **Performance**
  - [ ] Webhook processing <500ms (p95)
  - [ ] Service starts successfully
  - [ ] Health checks respond <100ms
  - [ ] Redis connection errors don't crash service

---

## Troubleshooting

### Mock sender can't connect to webhook listener

**Error**: `requests.exceptions.ConnectionError: ('Connection refused')`

**Fix**:
1. Verify webhook listener is running: `curl http://localhost:8080/health`
2. Check port number matches (default: 8080)
3. Check firewall settings

### Redis connection errors

**Error**: `redis.exceptions.ConnectionError: Error 61 connecting to localhost:6379. Connection refused.`

**Fix**:
1. Start Redis: `brew services start redis` or `docker run -d -p 6379:6379 redis`
2. Verify Redis is running: `redis-cli ping` (should return PONG)
3. Check Redis URL in environment: `echo $CORELINE_REDIS_URL`

### All webhooks rejected with HTTP 401

**Cause**: HMAC secret mismatch

**Fix**:
1. Ensure `JIRA_WEBHOOK_SECRET` matches in both webhook listener and mock sender
2. Default is `test-webhook-secret` for both
3. If using custom secret, pass to mock sender: `python tests/mock_jira_webhook_sender.py --secret your-secret`

### Docker health check fails

**Error**: Container exits with health check failure

**Fix**:
1. Check container logs: `docker logs coreline-webhook-listener`
2. Verify Redis connectivity from container: `docker exec coreline-webhook-listener curl localhost:8080/ready`
3. Ensure `JIRA_WEBHOOK_SECRET` environment variable is set

---

## Demo Script for Team Presentation

**Objective**: Demonstrate Coreline webhook listener to Joey and team

### Setup (5 minutes)

```bash
# Terminal 1: Start services
cd services/jira-webhook-listener
export CORELINE_ENVIRONMENT=dev
export CORELINE_REDIS_URL=redis://localhost:6379/0
export JIRA_WEBHOOK_SECRET=demo-secret-2026
python main.py

# Terminal 2: Prepare test script
# (Have this terminal ready with mock sender loaded)
```

### Demo Flow (10 minutes)

**1. Show Service Running**
```bash
# Show health endpoints
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

**2. Send Valid Security Incident**
```bash
python tests/mock_jira_webhook_sender.py
```

Point out in Terminal 1:
- HMAC verification success log
- Schema validation success log
- Audit event emission (JIRA_WEBHOOK_RECEIVED)
- Processing duration (<100ms)

**3. Demonstrate Security Guardrails**

Run full test suite:
```bash
python tests/mock_jira_webhook_sender.py --run-tests
```

Point out:
- ✅ Valid webhooks accepted (200)
- ❌ Invalid HMAC rejected (401)
- ❌ Replay attacks prevented (409)
- ❌ Path traversal blocked (400)

**4. Show Redis Replay Prevention**
```bash
redis-cli
> KEYS webhook:processed:*
> GET webhook:processed:webhook-INC-2026-001-*
> TTL webhook:processed:webhook-INC-2026-001-*  # Shows 24h TTL
```

**5. Explain Next Steps**
- Production deployment to Cloud Run
- Jira webhook configuration (IT team)
- Integration with Slack orchestrator (next sprint)
- SIEM integration (Chronicle ingestion)

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Test Webhook Listener

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          cd services/jira-webhook-listener
          pip install -r requirements.txt
      
      - name: Start webhook listener
        env:
          CORELINE_ENVIRONMENT: dev
          CORELINE_REDIS_URL: redis://localhost:6379/0
          JIRA_WEBHOOK_SECRET: test-secret-ci
        run: |
          cd services/jira-webhook-listener
          python main.py &
          sleep 5
      
      - name: Run security tests
        run: |
          cd services/jira-webhook-listener
          python tests/mock_jira_webhook_sender.py --run-tests
```

---

## Support

**Issues**: #security-engineering (Slack)  
**Documentation**: `README.md`, `TESTING.md`  
**Demo Recording**: [Link to be added after team demo]

---

**Maintained by**: Coreline Security Operations
