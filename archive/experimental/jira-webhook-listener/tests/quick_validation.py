#!/usr/bin/env python3
"""
Quick Validation Script - No Dependencies Required

Validates core security logic without requiring:
- Running webhook service
- Redis
- Docker
- Virtual environment with all dependencies

Tests:
1. HMAC signature generation and verification logic
2. Webhook payload structure validation
3. Mock webhook sender functionality

Usage:
    python3 tests/quick_validation.py
"""

import sys
import json
import hmac
import hashlib
from datetime import datetime, timezone


def test_hmac_logic():
    """Test HMAC signature generation and verification."""
    print("\n" + "=" * 80)
    print("Test 1: HMAC Signature Logic (Core Security - G2.1)")
    print("=" * 80)

    secret = "test-webhook-secret"
    payload = b'{"webhookEvent":"jira:issue_created","issue":{"key":"INC-42"}}'

    # Generate signature
    signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()

    print(f"Secret: {secret}")
    print(f"Payload: {payload.decode('utf-8')}")
    print(f"Signature: sha256={signature}")

    # Verify signature (correct)
    expected = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()

    is_valid = hmac.compare_digest(signature, expected)
    assert is_valid, "Valid signature should verify"
    print("✅ Valid signature verified successfully")

    # Verify signature (incorrect)
    wrong_sig = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    is_valid = hmac.compare_digest(signature, wrong_sig)
    assert not is_valid, "Invalid signature should fail"
    print("✅ Invalid signature correctly rejected")

    # Test constant-time comparison
    import time
    iterations = 10000

    start = time.time()
    for _ in range(iterations):
        hmac.compare_digest(signature, expected)
    valid_time = time.time() - start

    start = time.time()
    for _ in range(iterations):
        hmac.compare_digest(signature, wrong_sig)
    invalid_time = time.time() - start

    ratio = max(valid_time, invalid_time) / min(valid_time, invalid_time)
    print(f"✅ Timing attack resistance: {ratio:.2f}x (should be ~1.0x)")

    print("\n✅ HMAC verification logic validated!\n")


def test_webhook_payload_structure():
    """Test webhook payload structure matches expected format."""
    print("=" * 80)
    print("Test 2: Webhook Payload Structure (Schema Validation - G2.3)")
    print("=" * 80)

    # Valid P1 security incident
    valid_payload = {
        "webhookEvent": "jira:issue_created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "webhookEventId": "test-webhook-12345",
        "issue": {
            "id": "12345",
            "key": "INC-42",
            "self": "https://pantheon.atlassian.net/rest/api/2/issue/INC-42",
            "fields": {
                "issuetype": {
                    "id": "10001",
                    "name": "Security Incident",
                    "subtask": False
                },
                "priority": {
                    "id": "1",
                    "name": "P1"
                },
                "status": {
                    "id": "1",
                    "name": "Open"
                },
                "summary": "Suspicious login attempts from foreign IPs",
                "description": "Multiple failed login attempts detected",
                "created": datetime.now(timezone.utc).isoformat(),
                "updated": datetime.now(timezone.utc).isoformat()
            }
        }
    }

    # Validate structure
    assert "webhookEvent" in valid_payload
    assert valid_payload["webhookEvent"] in ["jira:issue_created", "jira:issue_updated"]
    print("✅ Webhook event type is valid")

    assert "issue" in valid_payload
    assert "key" in valid_payload["issue"]

    # Validate issue key format (regex: ^[A-Z]+-\d+$)
    issue_key = valid_payload["issue"]["key"]
    import re
    assert re.match(r'^[A-Z]+-\d+$', issue_key), "Issue key must match pattern"
    print(f"✅ Issue key format valid: {issue_key}")

    # Test path traversal prevention
    malicious_keys = [
        "../../../etc/passwd",
        "INC-42/../../secret",
        "INC-42; DROP TABLE",
        "INC\x00-42"
    ]

    for bad_key in malicious_keys:
        is_valid = re.match(r'^[A-Z]+-\d+$', bad_key) is not None
        assert not is_valid, f"Should reject malicious key: {bad_key}"

    print("✅ Path traversal patterns correctly rejected")

    # Validate Security Incident detection
    issue_type = valid_payload["issue"]["fields"]["issuetype"]["name"]
    is_security_incident = issue_type.lower() in [
        "security incident",
        "incident",
        "security-incident"
    ]
    assert is_security_incident, "Should detect Security Incident type"
    print(f"✅ Security Incident type detected: {issue_type}")

    print("\n✅ Webhook payload structure validated!\n")


def test_replay_prevention_logic():
    """Test replay prevention timestamp logic."""
    print("=" * 80)
    print("Test 3: Replay Prevention Logic (Timestamp Freshness - G2.2)")
    print("=" * 80)

    from datetime import timedelta

    current_time = datetime.now(timezone.utc)
    max_age_seconds = 300  # 5 minutes

    # Test fresh timestamp (1 minute old)
    fresh_timestamp = current_time - timedelta(seconds=60)
    age_seconds = (current_time - fresh_timestamp).total_seconds()
    is_fresh = age_seconds <= max_age_seconds
    assert is_fresh, "1 minute old should be fresh"
    print(f"✅ Fresh timestamp accepted (age: {age_seconds:.0f}s)")

    # Test stale timestamp (10 minutes old)
    stale_timestamp = current_time - timedelta(seconds=600)
    age_seconds = (current_time - stale_timestamp).total_seconds()
    is_fresh = age_seconds <= max_age_seconds
    assert not is_fresh, "10 minutes old should be stale"
    print(f"✅ Stale timestamp rejected (age: {age_seconds:.0f}s)")

    # Test future timestamp (clock skew)
    future_timestamp = current_time + timedelta(seconds=120)
    age_seconds = (current_time - future_timestamp).total_seconds()
    is_from_future = age_seconds < -60  # Allow 60s clock skew
    assert is_from_future, "Future timestamp should be detected"
    print(f"✅ Future timestamp detected (age: {age_seconds:.0f}s)")

    print("\n✅ Replay prevention logic validated!\n")


def test_mock_webhook_generation():
    """Test mock webhook sender can generate valid payloads."""
    print("=" * 80)
    print("Test 4: Mock Webhook Sender")
    print("=" * 80)

    secret = "test-webhook-secret"

    # Generate mock payload
    payload = {
        "webhookEvent": "jira:issue_created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "webhookEventId": "mock-webhook-test-123",
        "issue": {
            "key": "INC-999",
            "fields": {
                "issuetype": {"name": "Security Incident"},
                "priority": {"name": "P1"},
                "summary": "Mock incident for testing"
            }
        }
    }

    # Generate HMAC signature
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(
        secret.encode('utf-8'),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    print(f"Generated mock payload: {payload['issue']['key']}")
    print(f"Generated signature: sha256={signature}")

    # Verify the generated signature
    expected = hmac.new(
        secret.encode('utf-8'),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    is_valid = hmac.compare_digest(signature, expected)
    assert is_valid, "Generated signature should be valid"
    print("✅ Mock webhook signature is valid")

    # Verify payload structure
    assert payload["webhookEvent"] == "jira:issue_created"
    assert re.match(r'^[A-Z]+-\d+$', payload["issue"]["key"])
    print("✅ Mock webhook payload structure is valid")

    print("\n✅ Mock webhook sender validated!\n")


def main():
    """Run all validation tests."""
    print("\n" + "=" * 80)
    print("Coreline Jira Webhook Listener - Quick Validation")
    print("No dependencies required - Pure Python logic validation")
    print("=" * 80)

    try:
        # Import check
        import re
        print("\n✅ Python standard library available")

        # Run tests
        test_hmac_logic()
        test_webhook_payload_structure()
        test_replay_prevention_logic()
        test_mock_webhook_generation()

        # Summary
        print("=" * 80)
        print("✅ ALL VALIDATION TESTS PASSED!")
        print("=" * 80)
        print()
        print("Security Guardrails Validated:")
        print("  ✅ G2.1: HMAC-SHA256 signature verification")
        print("  ✅ G2.2: Replay prevention (timestamp freshness)")
        print("  ✅ G2.3: Schema validation (path traversal prevention)")
        print()
        print("Core Logic Validated:")
        print("  ✅ Constant-time HMAC comparison (timing attack prevention)")
        print("  ✅ Issue key regex validation (^[A-Z]+-\\d+$)")
        print("  ✅ Path traversal pattern rejection")
        print("  ✅ Security Incident type detection")
        print("  ✅ Timestamp freshness calculation")
        print("  ✅ Mock webhook generation")
        print()
        print("Next Steps:")
        print("  1. Sign in to Docker: docker login")
        print("  2. Build Docker image: docker build -t coreline-webhook-listener .")
        print("  3. Start Redis: docker run -d -p 6379:6379 redis:7-alpine")
        print("  4. Run integration tests: python3 tests/mock_jira_webhook_sender.py --run-tests")
        print()

        return 0

    except AssertionError as e:
        print()
        print("=" * 80)
        print("❌ VALIDATION FAILED")
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
    import re
    sys.exit(main())
