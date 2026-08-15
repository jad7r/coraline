#!/usr/bin/env python3
"""
Unit Tests for Security Components

Tests HMAC verifier, webhook models, and audit logger without requiring Redis or running service.
Can run independently to validate core security logic.

Usage:
    python tests/test_security_components.py
"""

import sys
import json
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

from services.jira_webhook_listener.security.hmac_verifier import (
    HMACVerifier,
    HMACVerificationError,
)
from services.jira_webhook_listener.models.webhook import JiraWebhookPayload
from services.jira_webhook_listener.models.audit import (
    AuditLogEvent,
    create_webhook_received_event,
)
from pydantic import ValidationError


def test_hmac_verifier():
    """Test HMAC signature verification."""
    print("\n" + "=" * 80)
    print("Test 1: HMAC Signature Verification")
    print("=" * 80)

    secret = "test-secret-key"
    verifier = HMACVerifier(secret=secret)

    # Test 1a: Valid signature
    payload = b'{"webhookEvent": "jira:issue_created"}'
    expected_sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    signature_header = f"sha256={expected_sig}"

    is_valid, error = verifier.verify(payload, signature_header)
    assert is_valid is True, "Valid signature should pass"
    assert error is None, "No error for valid signature"
    print("✅ Test 1a: Valid HMAC signature accepted")

    # Test 1b: Invalid signature
    is_valid, error = verifier.verify(payload, "sha256=deadbeef")
    assert is_valid is False, "Invalid signature should fail"
    assert error is not None, "Error message for invalid signature"
    print("✅ Test 1b: Invalid HMAC signature rejected")

    # Test 1c: Missing signature
    is_valid, error = verifier.verify(payload, None)
    assert is_valid is False, "Missing signature should fail"
    assert "Missing signature" in error, "Correct error message"
    print("✅ Test 1c: Missing HMAC signature rejected")

    # Test 1d: Constant-time comparison (timing attack prevention)
    # Both should take similar time
    import time

    valid_sig = f"sha256={expected_sig}"
    invalid_sig = "sha256=deadbeefdeadbeefdeadbeef"

    start = time.time()
    verifier.verify(payload, valid_sig)
    valid_time = time.time() - start

    start = time.time()
    verifier.verify(payload, invalid_sig)
    invalid_time = time.time() - start

    # Times should be within 2x of each other (constant-time)
    time_ratio = max(valid_time, invalid_time) / min(valid_time, invalid_time)
    assert time_ratio < 2.0, "Should use constant-time comparison"
    print("✅ Test 1d: Constant-time comparison (timing attack prevention)")

    print("\n✅ All HMAC verification tests passed!\n")


def test_webhook_validation():
    """Test webhook payload validation with Pydantic."""
    print("=" * 80)
    print("Test 2: Webhook Schema Validation")
    print("=" * 80)

    # Test 2a: Valid payload
    valid_payload = {
        "webhookEvent": "jira:issue_created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "webhookEventId": "test-webhook-123",
        "issue": {
            "id": "12345",
            "key": "INC-42",
            "self": "https://jira.example.com/issue/INC-42",
            "fields": {
                "issuetype": {"id": "1", "name": "Security Incident", "subtask": False},
                "priority": {"id": "1", "name": "P1"},
                "status": {"id": "1", "name": "Open"},
                "summary": "Test incident",
                "description": "Test description",
                "created": datetime.now(timezone.utc).isoformat(),
                "updated": datetime.now(timezone.utc).isoformat()
            }
        }
    }

    webhook = JiraWebhookPayload(**valid_payload)
    assert webhook.get_incident_id() == "INC-42"
    assert webhook.is_security_incident() is True
    print("✅ Test 2a: Valid webhook payload accepted")

    # Test 2b: Invalid issue key format (not matching ^[A-Z]+-\d+$)
    invalid_payload = valid_payload.copy()
    invalid_payload["issue"] = valid_payload["issue"].copy()
    invalid_payload["issue"]["key"] = "INVALID KEY"

    try:
        JiraWebhookPayload(**invalid_payload)
        assert False, "Should reject invalid issue key"
    except ValidationError:
        print("✅ Test 2b: Invalid issue key format rejected")

    # Test 2c: Path traversal attempt
    traversal_payload = valid_payload.copy()
    traversal_payload["issue"] = valid_payload["issue"].copy()
    traversal_payload["issue"]["key"] = "../../../etc/passwd"

    try:
        JiraWebhookPayload(**traversal_payload)
        assert False, "Should reject path traversal"
    except ValidationError as e:
        # The malicious key is rejected by schema validation. Depending on which
        # guard fires first, the error is either the issue-key `pattern` mismatch
        # (Pydantic v2) or the custom "path traversal" validator message. Either
        # outcome means the traversal attempt was blocked.
        err = str(e).lower()
        assert (
            "path traversal" in err
            or "unsafe" in err
            or "should match pattern" in err
        ), f"Path traversal key was not rejected as expected: {e}"
        print("✅ Test 2c: Path traversal attack prevented")

    # Test 2d: Non-security incident detection
    non_security = valid_payload.copy()
    non_security["issue"] = valid_payload["issue"].copy()
    non_security["issue"]["fields"] = valid_payload["issue"]["fields"].copy()
    non_security["issue"]["fields"]["issuetype"] = {"id": "2", "name": "Bug", "subtask": False}

    webhook = JiraWebhookPayload(**non_security)
    assert webhook.is_security_incident() is False
    print("✅ Test 2d: Non-security incident correctly identified")

    # Test 2e: Text sanitization (control characters)
    sanitize_payload = valid_payload.copy()
    sanitize_payload["issue"] = valid_payload["issue"].copy()
    sanitize_payload["issue"]["fields"] = valid_payload["issue"]["fields"].copy()
    sanitize_payload["issue"]["fields"]["summary"] = "Test\x00\x01\x02 with control chars"

    webhook = JiraWebhookPayload(**sanitize_payload)
    # Control characters should be stripped
    assert "\x00" not in webhook.issue.fields.summary
    print("✅ Test 2e: Control characters sanitized from text fields")

    print("\n✅ All webhook validation tests passed!\n")


def test_audit_logging():
    """Test audit event generation."""
    print("=" * 80)
    print("Test 3: Audit Event Generation")
    print("=" * 80)

    # Test 3a: Create webhook received event
    event = create_webhook_received_event(
        service="jira-webhook-listener",
        environment="dev",
        incident_id="INC-42",
        duration_ms=123,
        source_ip="203.0.113.42",
        metadata={"priority": "P1", "severity": "Critical"}
    )

    assert event.event_type == "JIRA_WEBHOOK_RECEIVED"
    assert event.success is True
    assert event.incident_id == "INC-42"
    assert event.duration_ms == 123
    print("✅ Test 3a: Webhook received event created")

    # Test 3b: Event serialization
    event_dict = event.to_log_dict()
    assert "event_id" in event_dict
    assert "timestamp" in event_dict
    assert event_dict["service"] == "jira-webhook-listener"
    print("✅ Test 3b: Audit event serialization works")

    # Test 3c: UUID generation
    event1 = AuditLogEvent(
        event_type="SERVICE_STARTED",
        service="test",
        environment="dev",
        success=True
    )
    event2 = AuditLogEvent(
        event_type="SERVICE_STARTED",
        service="test",
        environment="dev",
        success=True
    )
    assert event1.event_id != event2.event_id, "Each event should have unique ID"
    print("✅ Test 3c: Unique event IDs generated")

    print("\n✅ All audit logging tests passed!\n")


def test_mock_webhook_sender():
    """Test mock webhook sender can generate valid payloads."""
    print("=" * 80)
    print("Test 4: Mock Webhook Sender")
    print("=" * 80)

    from services.jira_webhook_listener.tests.mock_jira_webhook_sender import (
        MockJiraWebhookSender,
    )

    sender = MockJiraWebhookSender(secret="test-secret")

    # Test 4a: Generate valid payload
    payload = sender._create_security_incident_payload(
        incident_id="INC-TEST",
        summary="Test incident",
        priority="P1",
        severity="Critical"
    )

    assert payload["webhookEvent"] == "jira:issue_created"
    assert payload["issue"]["key"] == "INC-TEST"
    assert payload["issue"]["fields"]["priority"]["name"] == "P1"
    print("✅ Test 4a: Mock sender generates valid payloads")

    # Test 4b: HMAC signature generation
    payload_bytes = json.dumps(payload).encode('utf-8')
    signature = sender._generate_hmac_signature(payload_bytes)
    assert signature.startswith("sha256=")
    assert len(signature) == 71  # "sha256=" + 64 hex chars
    print("✅ Test 4b: Mock sender generates valid HMAC signatures")

    # Test 4c: Signature verification
    verifier = HMACVerifier(secret="test-secret")
    is_valid, error = verifier.verify(payload_bytes, signature)
    assert is_valid is True, "Mock sender signature should be valid"
    print("✅ Test 4c: Mock sender signatures verify correctly")

    print("\n✅ All mock webhook sender tests passed!\n")


def main():
    """Run all unit tests."""
    print("\n" + "=" * 80)
    print("Coreline Jira Webhook Listener - Core Security Component Tests")
    print("=" * 80)
    print()
    print("Running unit tests without requiring Redis or running service...")
    print()

    try:
        test_hmac_verifier()
        test_webhook_validation()
        test_audit_logging()
        test_mock_webhook_sender()

        print("=" * 80)
        print("✅ ALL TESTS PASSED!")
        print("=" * 80)
        print()
        print("Core security components validated:")
        print("  ✅ HMAC signature verification (G2.1)")
        print("  ✅ Schema validation with Pydantic (G2.3)")
        print("  ✅ Path traversal prevention")
        print("  ✅ Text sanitization")
        print("  ✅ Audit event generation")
        print("  ✅ Mock webhook sender")
        print()
        print("Next steps:")
        print("  1. Start Redis: docker run -d -p 6379:6379 redis:7-alpine")
        print("  2. Run full service: python main.py")
        print("  3. Run integration tests: python tests/mock_jira_webhook_sender.py --run-tests")
        print()

        return 0

    except AssertionError as e:
        print()
        print("=" * 80)
        print("❌ TEST FAILED")
        print("=" * 80)
        print(f"Error: {e}")
        print()
        return 1

    except Exception as e:
        print()
        print("=" * 80)
        print("❌ UNEXPECTED ERROR")
        print("=" * 80)
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
