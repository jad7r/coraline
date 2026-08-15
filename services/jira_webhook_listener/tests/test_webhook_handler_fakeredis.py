#!/usr/bin/env python3
"""
Integration tests for the webhook processing pipeline backed by fakeredis.

Exercises all security guardrails end-to-end through ``WebhookHandler`` without
a real Redis server:
    - G2.1 HMAC verification (valid / invalid / missing)
    - G2.2 replay prevention (stale timestamp, duplicate webhook ID)
    - G2.3 schema validation (path traversal rejection)
    - Non-security issue types accepted-but-ignored
"""

import pytest

from services.jira_webhook_listener.tests.conftest import (
    TEST_SECRET,
    build_security_incident_payload,
    payload_to_bytes,
    sign,
)

pytestmark = pytest.mark.asyncio


async def test_valid_security_incident_accepted(webhook_handler):
    payload = build_security_incident_payload(webhook_id="wh-valid-1")
    body = payload_to_bytes(payload)

    result = await webhook_handler.process_webhook(
        payload_bytes=body,
        signature_header=sign(body),
        source_ip="203.0.113.10",
    )

    assert result.status_code == 200
    assert result.incident_id == "INC-42"


async def test_invalid_signature_rejected(webhook_handler):
    payload = build_security_incident_payload(webhook_id="wh-badsig")
    body = payload_to_bytes(payload)

    result = await webhook_handler.process_webhook(
        payload_bytes=body,
        signature_header="sha256=" + "de" * 32,
        source_ip="203.0.113.10",
    )

    assert result.status_code == 401


async def test_missing_signature_rejected(webhook_handler):
    payload = build_security_incident_payload(webhook_id="wh-nosig")
    body = payload_to_bytes(payload)

    result = await webhook_handler.process_webhook(
        payload_bytes=body,
        signature_header=None,
        source_ip="203.0.113.10",
    )

    assert result.status_code == 401


async def test_stale_timestamp_rejected(webhook_handler):
    payload = build_security_incident_payload(
        webhook_id="wh-stale", timestamp_offset_seconds=-600
    )
    body = payload_to_bytes(payload)

    result = await webhook_handler.process_webhook(
        payload_bytes=body,
        signature_header=sign(body),
    )

    assert result.status_code == 400


async def test_duplicate_webhook_rejected(webhook_handler):
    payload = build_security_incident_payload(webhook_id="wh-dup-123")
    body = payload_to_bytes(payload)

    first = await webhook_handler.process_webhook(
        payload_bytes=body, signature_header=sign(body)
    )
    assert first.status_code == 200

    second = await webhook_handler.process_webhook(
        payload_bytes=body, signature_header=sign(body)
    )
    assert second.status_code == 409


async def test_non_security_incident_accepted_but_ignored(webhook_handler):
    payload = build_security_incident_payload(
        incident_id="BUG-7", webhook_id="wh-bug", issue_type="Bug"
    )
    body = payload_to_bytes(payload)

    result = await webhook_handler.process_webhook(
        payload_bytes=body, signature_header=sign(body)
    )

    assert result.status_code == 200
    assert "not a Security Incident" in result.message


async def test_path_traversal_key_rejected(webhook_handler):
    payload = build_security_incident_payload(webhook_id="wh-traversal")
    # Bypass the pydantic-side key regex is impossible from here; use an invalid
    # key so schema validation rejects it with 400.
    payload["issue"]["key"] = "../../../etc/passwd"
    body = payload_to_bytes(payload)

    result = await webhook_handler.process_webhook(
        payload_bytes=body, signature_header=sign(body)
    )

    assert result.status_code == 400


async def test_replay_protection_marks_and_detects(replay_protection):
    webhook_id = "unit-replay-1"

    is_dup, _ = await replay_protection.is_duplicate(webhook_id)
    assert is_dup is False

    assert await replay_protection.mark_processed(webhook_id) is True

    is_dup, msg = await replay_protection.is_duplicate(webhook_id)
    assert is_dup is True
    assert webhook_id in msg
