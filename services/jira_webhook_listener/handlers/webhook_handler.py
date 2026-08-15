#!/usr/bin/env python3
"""
Core Webhook Processing Logic

Orchestrates all security guardrails for incoming Jira webhooks:
1. HMAC signature verification (G2.1)
2. Schema validation (G2.3)
3. Replay attack prevention (G2.2)
4. Audit logging to SIEM

Processing Flow:
    Receive webhook → Verify HMAC → Validate schema → Check freshness →
    Check duplicate → Mark processed → Emit audit event → Return success
"""

import json
import structlog
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import ValidationError
import redis.asyncio as redis

from services.jira_webhook_listener.security.hmac_verifier import (
    HMACVerifier,
    HMACVerificationError,
)
from services.jira_webhook_listener.security.replay_prevention import ReplayProtection
from services.jira_webhook_listener.handlers.audit_logger import AuditLogger
from services.jira_webhook_listener.models.webhook import JiraWebhookPayload

logger = structlog.get_logger(__name__)


class WebhookResponse:
    """Response from webhook processing."""

    def __init__(
        self,
        status_code: int,
        message: str,
        duration_ms: int,
        incident_id: Optional[str] = None
    ):
        self.status_code = status_code
        self.message = message
        self.duration_ms = duration_ms
        self.incident_id = incident_id

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for HTTP response."""
        result = {
            "status": "success" if self.status_code == 200 else "error",
            "message": self.message,
            "duration_ms": self.duration_ms
        }
        if self.incident_id:
            result["incident_id"] = self.incident_id
        return result


class WebhookHandler:
    """Handles incoming Jira webhook requests with security guardrails."""

    def __init__(
        self,
        hmac_verifier: HMACVerifier,
        replay_protection: ReplayProtection,
        audit_logger: AuditLogger,
        max_webhook_age_seconds: int = 300,
        redis_client: Optional[redis.Redis] = None,
        incident_channel_name: str = "coreline:incident:created"
    ):
        """
        Initialize webhook handler.

        Args:
            hmac_verifier: HMAC signature verifier
            replay_protection: Replay attack prevention
            audit_logger: Audit event logger
            max_webhook_age_seconds: Maximum acceptable webhook age
            redis_client: Optional Redis client for Pub/Sub publishing
            incident_channel_name: Redis Pub/Sub channel for incident notifications
        """
        self.hmac_verifier = hmac_verifier
        self.replay_protection = replay_protection
        self.audit_logger = audit_logger
        self.max_webhook_age_seconds = max_webhook_age_seconds
        self.redis_client = redis_client
        self.incident_channel_name = incident_channel_name

        logger.info(
            "webhook_handler.initialized",
            max_webhook_age_seconds=max_webhook_age_seconds,
            pubsub_enabled=redis_client is not None,
            msg="Webhook handler initialized"
        )

    async def process_webhook(
        self,
        payload_bytes: bytes,
        signature_header: Optional[str],
        source_ip: Optional[str] = None
    ) -> WebhookResponse:
        """
        Process incoming Jira webhook with all security guardrails.

        Args:
            payload_bytes: Raw webhook body (bytes)
            signature_header: HMAC signature header value
            source_ip: Source IP address of request

        Returns:
            WebhookResponse with status code, message, and duration

        Processing Flow:
            1. Verify HMAC signature (G2.1)
            2. Parse and validate JSON schema (G2.3)
            3. Check webhook timestamp freshness (G2.2)
            4. Check for duplicate webhook ID (G2.2)
            5. Mark webhook as processed
            6. Emit audit event to SIEM
            7. Return success response
        """
        start_time = datetime.now()

        try:
            # === Step 1: HMAC Verification (G2.1) ===
            logger.debug(
                "webhook_handler.verifying_hmac",
                payload_length=len(payload_bytes),
                msg="Verifying HMAC signature"
            )

            is_valid, error_message = self.hmac_verifier.verify(
                payload=payload_bytes,
                signature_header=signature_header
            )

            if not is_valid:
                # HMAC verification failed - reject immediately
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                self.audit_logger.log_auth_failure(
                    error_message=error_message,
                    source_ip=source_ip
                )

                return WebhookResponse(
                    status_code=401,
                    message=f"Authentication failed: {error_message}",
                    duration_ms=duration_ms
                )

            # === Step 2: Schema Validation (G2.3) ===
            logger.debug(
                "webhook_handler.validating_schema",
                msg="Validating webhook payload schema"
            )

            try:
                # Parse JSON
                payload_dict = json.loads(payload_bytes.decode('utf-8'))

                # Validate with Pydantic
                webhook = JiraWebhookPayload(**payload_dict)

            except json.JSONDecodeError as e:
                # Invalid JSON
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                self.audit_logger.log_validation_error(
                    error_message=f"Invalid JSON: {str(e)}",
                    source_ip=source_ip
                )

                return WebhookResponse(
                    status_code=400,
                    message="Invalid JSON payload",
                    duration_ms=duration_ms
                )

            except ValidationError as e:
                # Schema validation failed
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                validation_errors = e.errors()
                self.audit_logger.log_validation_error(
                    error_message=f"Schema validation failed: {str(e)}",
                    source_ip=source_ip,
                    validation_errors=validation_errors
                )

                return WebhookResponse(
                    status_code=400,
                    message=f"Schema validation failed: {validation_errors[0]['msg']}",
                    duration_ms=duration_ms
                )

            # === Step 3: Check if Security Incident ===
            # Coreline only processes webhooks for Security Incident issue type
            if not webhook.is_security_incident():
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                logger.info(
                    "webhook_handler.ignored_issue_type",
                    issue_type=webhook.issue.fields.issuetype.name,
                    incident_id=webhook.get_incident_id(),
                    msg="Webhook ignored: not a Security Incident"
                )

                # Return success (accepted but not processed)
                return WebhookResponse(
                    status_code=200,
                    message="Webhook accepted (not a Security Incident, no action taken)",
                    duration_ms=duration_ms,
                    incident_id=webhook.get_incident_id()
                )

            # === Step 4: Replay Prevention - Timestamp Check (G2.2) ===
            logger.debug(
                "webhook_handler.checking_timestamp",
                webhook_timestamp=webhook.timestamp.isoformat(),
                msg="Checking webhook timestamp freshness"
            )

            is_fresh, error_message = await self.replay_protection.is_webhook_fresh(
                timestamp=webhook.timestamp,
                max_age_seconds=self.max_webhook_age_seconds
            )

            if not is_fresh:
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                self.audit_logger.log_validation_error(
                    error_message=f"Stale webhook: {error_message}",
                    source_ip=source_ip
                )

                return WebhookResponse(
                    status_code=400,
                    message=f"Webhook rejected: {error_message}",
                    duration_ms=duration_ms
                )

            # === Step 5: Replay Prevention - Duplicate Check (G2.2) ===
            webhook_id = webhook.webhookEventId or webhook.get_incident_id()

            logger.debug(
                "webhook_handler.checking_duplicate",
                webhook_id=webhook_id,
                msg="Checking for duplicate webhook ID"
            )

            is_duplicate, error_message = await self.replay_protection.is_duplicate(webhook_id)

            if is_duplicate:
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                self.audit_logger.log_replay_detected(
                    webhook_id=webhook_id,
                    incident_id=webhook.get_incident_id(),
                    source_ip=source_ip
                )

                return WebhookResponse(
                    status_code=409,
                    message=f"Duplicate webhook detected: {webhook_id}",
                    duration_ms=duration_ms,
                    incident_id=webhook.get_incident_id()
                )

            # === Step 6: Mark Webhook as Processed ===
            await self.replay_protection.mark_processed(webhook_id)

            # === Step 6.5: Publish to Slack Orchestrator (Redis Pub/Sub) ===
            # Only publish if Redis client is configured and webhook is Security Incident
            if self.redis_client and webhook.is_security_incident():
                await self._publish_incident_event(webhook)

            # === Step 7: Emit Audit Event ===
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            metadata = {
                "webhook_event": webhook.webhookEvent,
                "priority": webhook.get_priority(),
                "severity": webhook.get_severity(),
                "incident_commander": webhook.get_incident_commander(),
                "summary": webhook.get_incident_summary()
            }

            self.audit_logger.log_webhook_received(
                incident_id=webhook.get_incident_id(),
                duration_ms=duration_ms,
                source_ip=source_ip,
                metadata=metadata
            )

            # === Step 8: Success Response ===
            logger.info(
                "webhook_handler.success",
                incident_id=webhook.get_incident_id(),
                webhook_event=webhook.webhookEvent,
                duration_ms=duration_ms,
                msg="Webhook processed successfully"
            )

            return WebhookResponse(
                status_code=200,
                message="Webhook processed successfully",
                duration_ms=duration_ms,
                incident_id=webhook.get_incident_id()
            )

        except Exception as e:
            # Unexpected error - log and return 500
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            logger.exception(
                "webhook_handler.unexpected_error",
                error=str(e),
                error_type=type(e).__name__,
                duration_ms=duration_ms,
                msg="Unexpected error processing webhook"
            )

            self.audit_logger.log_custom_event(
                event_type="JIRA_WEBHOOK_RECEIVED",
                success=False,
                error_message=str(e),
                error_code="INTERNAL_ERROR",
                duration_ms=duration_ms
            )

            return WebhookResponse(
                status_code=500,
                message="Internal server error",
                duration_ms=duration_ms
            )

    async def _publish_incident_event(self, webhook: JiraWebhookPayload):
        """
        Publish incident event to Redis Pub/Sub for Slack Orchestrator.

        Non-fatal: Logs errors but does not fail webhook processing.
        Webhook listener's primary responsibility is validation and audit logging.
        Publishing to Slack is a secondary concern.

        Args:
            webhook: Validated Jira webhook payload
        """
        try:
            # Build incident event payload matching slack-orchestrator's IncidentEvent schema
            incident_event = {
                "incident_id": webhook.get_incident_id(),
                "summary": webhook.get_incident_summary(),
                "priority": webhook.get_priority(),
                "severity": webhook.get_severity(),
                "incident_commander": webhook.get_incident_commander(),
                "detection_time": webhook.timestamp.isoformat(),
                "affected_systems": [],  # TODO: Extract from custom fields if available
                "webhook_event": webhook.webhookEvent,
                "jira_url": webhook.issue.self
            }

            # Publish to Redis Pub/Sub channel
            await self.redis_client.publish(
                self.incident_channel_name,
                json.dumps(incident_event)
            )

            logger.info(
                "webhook_handler.published_to_slack",
                incident_id=webhook.get_incident_id(),
                channel=self.incident_channel_name,
                msg="Published incident event to Slack orchestrator"
            )

        except redis.RedisError as e:
            # Non-fatal - log error but don't fail webhook processing
            logger.error(
                "webhook_handler.publish_failed",
                incident_id=webhook.get_incident_id(),
                error=str(e),
                error_type=type(e).__name__,
                msg="Failed to publish to Slack (incident still logged, non-fatal)"
            )

        except Exception as e:
            # Unexpected error - log but don't fail
            logger.exception(
                "webhook_handler.publish_unexpected_error",
                incident_id=webhook.get_incident_id(),
                error=str(e),
                error_type=type(e).__name__,
                msg="Unexpected error publishing to Slack (non-fatal)"
            )
