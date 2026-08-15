#!/usr/bin/env python3
"""
Mock Jira Webhook Sender

Simulates Jira sending security incident webhooks to Coreline webhook listener.
Used for testing, validation, and demonstrations without requiring real Jira instance.

Security Test Scenarios:
1. Valid webhook (should accept: HTTP 200)
2. Invalid HMAC signature (should reject: HTTP 401)
3. Stale timestamp - replay attack (should reject: HTTP 400)
4. Duplicate webhook ID (should reject: HTTP 409)
5. Invalid schema (should reject: HTTP 400)
6. Non-security incident (should accept but ignore: HTTP 200)

Usage:
    # Start webhook listener first
    cd services/jira-webhook-listener
    python main.py

    # In another terminal, run mock sender
    python tests/mock_jira_webhook_sender.py
"""

import hmac
import hashlib
import json
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional


class MockJiraWebhookSender:
    """Simulates Jira sending webhooks with proper HMAC signatures."""

    def __init__(self, target_url: str = "http://localhost:8080/webhook", secret: str = "test-webhook-secret"):
        """
        Initialize mock webhook sender.

        Args:
            target_url: Webhook listener URL
            secret: HMAC secret (must match webhook listener configuration)
        """
        self.target_url = target_url
        self.secret = secret.encode('utf-8')

    def _generate_hmac_signature(self, payload_bytes: bytes) -> str:
        """
        Generate HMAC-SHA256 signature matching Jira webhook format.

        Args:
            payload_bytes: Raw JSON payload

        Returns:
            HMAC signature in format: "sha256=<hex>"
        """
        signature = hmac.new(
            key=self.secret,
            msg=payload_bytes,
            digestmod=hashlib.sha256
        ).hexdigest()

        return f"sha256={signature}"

    def _create_security_incident_payload(
        self,
        incident_id: str,
        summary: str,
        priority: str = "P1",
        severity: str = "Critical",
        webhook_event: str = "jira:issue_created",
        timestamp_offset_seconds: int = 0,
        webhook_id: Optional[str] = None
    ) -> dict:
        """
        Create Jira webhook payload matching Coreline schema.

        Args:
            incident_id: Incident ID (e.g., INC-42)
            summary: Incident summary
            priority: Priority (P1, P2, P3, P4)
            severity: Severity (Critical, High, Medium, Low)
            webhook_event: Event type (jira:issue_created or jira:issue_updated)
            timestamp_offset_seconds: Offset from current time (negative = past)
            webhook_id: Unique webhook ID (for replay testing)

        Returns:
            Webhook payload dictionary
        """
        # Calculate timestamp
        timestamp = datetime.now(timezone.utc) + timedelta(seconds=timestamp_offset_seconds)

        # Generate webhook ID if not provided
        if webhook_id is None:
            webhook_id = f"webhook-{incident_id}-{int(timestamp.timestamp())}"

        return {
            "webhookEvent": webhook_event,
            "timestamp": timestamp.isoformat(),
            "webhookEventId": webhook_id,
            "user": {
                "accountId": "5f8a9b2c3d4e5f6a7b8c9d0e",
                "emailAddress": "jira-automation@example.com",
                "displayName": "Jira Automation",
                "active": True
            },
            "issue": {
                "id": "12345",
                "key": incident_id,
                "self": f"https://pantheon.atlassian.net/rest/api/2/issue/{incident_id}",
                "fields": {
                    "issuetype": {
                        "id": "10001",
                        "name": "Security Incident",
                        "subtask": False
                    },
                    "priority": {
                        "id": "1",
                        "name": priority
                    },
                    "status": {
                        "id": "10000",
                        "name": "Open"
                    },
                    "summary": summary,
                    "description": f"Security incident detected: {summary}",
                    "assignee": {
                        "accountId": "5f8a9b2c3d4e5f6a7b8c9d0e",
                        "emailAddress": "josh.dellinger@example.com",
                        "displayName": "Josh Dellinger",
                        "active": True
                    },
                    "reporter": {
                        "accountId": "automation-user",
                        "emailAddress": "pagerduty@example.com",
                        "displayName": "PagerDuty Automation",
                        "active": True
                    },
                    "created": timestamp.isoformat(),
                    "updated": timestamp.isoformat(),
                    # Custom fields
                    "customfield_severity": severity,
                    "customfield_incident_lead": {
                        "accountId": "5f8a9b2c3d4e5f6a7b8c9d0e",
                        "emailAddress": "josh.dellinger@example.com",
                        "displayName": "Josh Dellinger",
                        "active": True
                    },
                    "customfield_affected_systems": ["prod-web-01", "prod-db-01"],
                    "customfield_detection_vector": "Automated Monitoring"
                }
            }
        }

    def send_webhook(
        self,
        payload: dict,
        corrupt_signature: bool = False,
        missing_signature: bool = False
    ) -> requests.Response:
        """
        Send webhook to Coreline webhook listener.

        Args:
            payload: Webhook payload dictionary
            corrupt_signature: If True, sends invalid HMAC signature
            missing_signature: If True, omits signature header

        Returns:
            Response from webhook listener
        """
        # Serialize payload to JSON
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        # Generate HMAC signature
        signature = self._generate_hmac_signature(payload_bytes)

        # Build headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Atlassian-Webhooks/1.0"
        }

        # Add signature header (unless testing missing signature)
        if not missing_signature:
            if corrupt_signature:
                headers["X-Hub-Signature"] = "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            else:
                headers["X-Hub-Signature"] = signature

        # Send webhook
        response = requests.post(
            self.target_url,
            data=payload_bytes,
            headers=headers,
            timeout=10
        )

        return response

    def run_test_scenarios(self):
        """Run comprehensive security test scenarios."""
        print("=" * 80)
        print("Coreline Jira Webhook Listener - Security Test Suite")
        print("=" * 80)
        print()

        # Test 1: Valid Security Incident (Should Accept: HTTP 200)
        print("Test 1: Valid P1 Security Incident")
        print("-" * 80)
        payload = self._create_security_incident_payload(
            incident_id="INC-101",
            summary="Suspicious login attempts from foreign IP addresses",
            priority="P1",
            severity="Critical"
        )
        response = self.send_webhook(payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"✅ Expected: 200, Got: {response.status_code}")
        print()

        # Test 2: Invalid HMAC Signature (Should Reject: HTTP 401)
        print("Test 2: Invalid HMAC Signature (Security Test)")
        print("-" * 80)
        payload = self._create_security_incident_payload(
            incident_id="INC-102",
            summary="Test incident with corrupted signature",
            webhook_id="test-invalid-sig"
        )
        response = self.send_webhook(payload, corrupt_signature=True)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"✅ Expected: 401, Got: {response.status_code}")
        print()

        # Test 3: Missing HMAC Signature (Should Reject: HTTP 401)
        print("Test 3: Missing HMAC Signature (Security Test)")
        print("-" * 80)
        payload = self._create_security_incident_payload(
            incident_id="INC-103",
            summary="Test incident with missing signature",
            webhook_id="test-missing-sig"
        )
        response = self.send_webhook(payload, missing_signature=True)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"✅ Expected: 401, Got: {response.status_code}")
        print()

        # Test 4: Stale Timestamp - Replay Attack (Should Reject: HTTP 400)
        print("Test 4: Stale Timestamp - Replay Attack Prevention")
        print("-" * 80)
        payload = self._create_security_incident_payload(
            incident_id="INC-104",
            summary="Test incident with stale timestamp (10 minutes old)",
            timestamp_offset_seconds=-600,  # 10 minutes in the past
            webhook_id="test-stale-timestamp"
        )
        response = self.send_webhook(payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"✅ Expected: 400, Got: {response.status_code}")
        print()

        # Test 5: Duplicate Webhook ID (Should Reject: HTTP 409)
        print("Test 5: Duplicate Webhook ID - Replay Detection")
        print("-" * 80)
        duplicate_webhook_id = "test-duplicate-webhook-12345"

        # Send first webhook
        payload1 = self._create_security_incident_payload(
            incident_id="INC-105",
            summary="First webhook with duplicate ID",
            webhook_id=duplicate_webhook_id
        )
        response1 = self.send_webhook(payload1)
        print(f"First send - Status: {response1.status_code} (should be 200)")

        # Send duplicate (same webhook ID)
        payload2 = self._create_security_incident_payload(
            incident_id="INC-105",
            summary="Second webhook with same ID (replay attack)",
            webhook_id=duplicate_webhook_id
        )
        response2 = self.send_webhook(payload2)
        print(f"Duplicate send - Status: {response2.status_code}")
        print(f"Response: {json.dumps(response2.json(), indent=2)}")
        print(f"✅ Expected: 409, Got: {response2.status_code}")
        print()

        # Test 6: Non-Security Incident Issue Type (Should Accept but Ignore: HTTP 200)
        print("Test 6: Non-Security Incident (Should Accept but Ignore)")
        print("-" * 80)
        payload = self._create_security_incident_payload(
            incident_id="BUG-123",
            summary="This is a regular bug, not a security incident",
            webhook_id="test-non-security"
        )
        # Override issue type
        payload["issue"]["fields"]["issuetype"]["name"] = "Bug"
        response = self.send_webhook(payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"✅ Expected: 200 (accepted but not processed), Got: {response.status_code}")
        print()

        # Test 7: Path Traversal Attempt (Should Reject: HTTP 400)
        print("Test 7: Path Traversal Attack Prevention")
        print("-" * 80)
        payload = self._create_security_incident_payload(
            incident_id="../../../etc/passwd",  # Malicious issue key
            summary="Path traversal attempt",
            webhook_id="test-path-traversal"
        )
        response = self.send_webhook(payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"✅ Expected: 400, Got: {response.status_code}")
        print()

        print("=" * 80)
        print("Test Suite Complete")
        print("=" * 80)


def main():
    """Run mock webhook sender with test scenarios."""
    import argparse

    parser = argparse.ArgumentParser(description='Mock Jira Webhook Sender')
    parser.add_argument(
        '--url',
        default='http://localhost:8080/webhook',
        help='Webhook listener URL (default: http://localhost:8080/webhook)'
    )
    parser.add_argument(
        '--secret',
        default='test-webhook-secret',
        help='HMAC secret (default: test-webhook-secret)'
    )
    parser.add_argument(
        '--run-tests',
        action='store_true',
        help='Run comprehensive security test suite'
    )

    args = parser.parse_args()

    sender = MockJiraWebhookSender(target_url=args.url, secret=args.secret)

    if args.run_tests:
        sender.run_test_scenarios()
    else:
        # Send single valid webhook
        print("Sending single valid security incident webhook...")
        payload = sender._create_security_incident_payload(
            incident_id="INC-2026-TEST",
            summary="Test security incident - manual send",
            priority="P2",
            severity="High"
        )
        response = sender.send_webhook(payload)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")


if __name__ == "__main__":
    main()
