#!/usr/bin/env python3
"""
Shared pytest fixtures for the Jira Webhook Listener test suite.

These fixtures back the service with an in-memory ``fakeredis`` instance so the
security guardrails (replay prevention in particular) can be exercised offline,
without a running Redis server.
"""

import hashlib
import hmac
import json
from datetime import datetime, timezone

import fakeredis.aioredis
import pytest
import pytest_asyncio

from services.jira_webhook_listener.handlers.audit_logger import AuditLogger
from services.jira_webhook_listener.handlers.webhook_handler import WebhookHandler
from services.jira_webhook_listener.security.hmac_verifier import HMACVerifier
from services.jira_webhook_listener.security.replay_prevention import ReplayProtection

TEST_SECRET = "test-webhook-secret"


@pytest_asyncio.fixture
async def fake_redis():
    """An in-memory async Redis client (decode_responses=True like production)."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def hmac_verifier():
    return HMACVerifier(secret=TEST_SECRET)


@pytest_asyncio.fixture
async def replay_protection(fake_redis):
    return ReplayProtection(redis_client=fake_redis)


@pytest.fixture
def audit_logger():
    return AuditLogger(service_name="jira-webhook-listener", environment="dev")


@pytest_asyncio.fixture
async def webhook_handler(hmac_verifier, replay_protection, audit_logger, fake_redis):
    return WebhookHandler(
        hmac_verifier=hmac_verifier,
        replay_protection=replay_protection,
        audit_logger=audit_logger,
        max_webhook_age_seconds=300,
        redis_client=fake_redis,
        incident_channel_name="coreline:incident:created",
    )


def sign(payload_bytes: bytes, secret: str = TEST_SECRET) -> str:
    """Return an ``sha256=<hex>`` HMAC header for the given payload bytes."""
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_security_incident_payload(
    incident_id: str = "INC-42",
    webhook_id: str = "webhook-INC-42",
    issue_type: str = "Security Incident",
    timestamp_offset_seconds: int = 0,
) -> dict:
    """Build a minimal, schema-valid Jira security-incident webhook payload."""
    from datetime import timedelta

    ts = datetime.now(timezone.utc) + timedelta(seconds=timestamp_offset_seconds)
    return {
        "webhookEvent": "jira:issue_created",
        "timestamp": ts.isoformat(),
        "webhookEventId": webhook_id,
        "issue": {
            "id": "12345",
            "key": incident_id,
            "self": f"https://jira.example.com/rest/api/2/issue/{incident_id}",
            "fields": {
                "issuetype": {"id": "1", "name": issue_type, "subtask": False},
                "priority": {"id": "1", "name": "P1"},
                "status": {"id": "1", "name": "Open"},
                "summary": "Suspicious login attempts detected",
                "description": "Multiple failed logins from a foreign IP",
                "created": ts.isoformat(),
                "updated": ts.isoformat(),
                "customfield_severity": "Critical",
            },
        },
    }


def payload_to_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")
