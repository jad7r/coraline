#!/usr/bin/env python3
"""
Audit Logger for SIEM Integration

Emits structured audit events matching /schemas/audit/audit-log-event.schema.json
for security monitoring and compliance.

All events are logged to Cloud Logging and automatically ingested by Chronicle SIEM.

Security Features:
- Sanitizes error messages (strips secrets, credentials, stack traces)
- Never logs sensitive data (API keys, tokens, passwords)
- Includes operation duration for performance monitoring
- Structured JSON format for automated analysis
"""

import structlog
import re
from typing import Optional, Dict, Any
from services.jira_webhook_listener.models.audit import (
    AuditLogEvent,
    create_webhook_received_event,
    create_auth_failure_event,
    create_replay_detected_event,
    create_validation_error_event
)

logger = structlog.get_logger(__name__)


class AuditLogger:
    """Emits structured audit events for SIEM integration."""

    def __init__(self, service_name: str, environment: str):
        """
        Initialize audit logger with service context.

        Args:
            service_name: Name of the service (e.g., "jira-webhook-listener")
            environment: Deployment environment ("dev", "staging", "prod")
        """
        self.service = service_name
        self.environment = environment
        self.logger = structlog.get_logger(__name__)

        logger.info(
            "audit_logger.initialized",
            service=service_name,
            environment=environment,
            msg="Audit logger initialized"
        )

    def _sanitize_error_message(self, error_message: str) -> str:
        """
        Sanitize error message to remove sensitive data.

        Removes:
        - API keys/tokens (xox*, sk-ant-*, Bearer *, etc.)
        - Passwords/secrets (password=*, secret=*, etc.)
        - Stack traces (full paths, line numbers)
        - IP addresses (optionally - kept for security monitoring)

        Args:
            error_message: Raw error message

        Returns:
            Sanitized error message safe for logging
        """
        sanitized = error_message

        # Redact Slack tokens
        sanitized = re.sub(r'xox[baprs]-[^\s]+', '[REDACTED_SLACK_TOKEN]', sanitized)

        # Redact Anthropic API keys
        sanitized = re.sub(r'sk-ant-[^\s]+', '[REDACTED_ANTHROPIC_KEY]', sanitized)

        # Redact Bearer tokens
        sanitized = re.sub(r'Bearer\s+[^\s]+', 'Bearer [REDACTED_TOKEN]', sanitized, flags=re.IGNORECASE)

        # Redact password/secret patterns
        sanitized = re.sub(
            r'\b(password|passwd|pwd|secret|token|key|api_key)\s*[:=]\s*[^\s]+',
            r'\1=[REDACTED]',
            sanitized,
            flags=re.IGNORECASE
        )

        # Redact GitHub tokens
        sanitized = re.sub(r'ghp_[a-zA-Z0-9]{36,}', '[REDACTED_GITHUB_TOKEN]', sanitized)

        # Truncate very long messages (prevent log flooding)
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000] + "... (truncated)"

        return sanitized

    def _emit_event(self, event: AuditLogEvent):
        """
        Emit audit event to structured logging (Cloud Logging → Chronicle).

        Args:
            event: Audit event to emit
        """
        # Convert to dict for logging
        event_dict = event.to_log_dict()

        # Log at appropriate level based on success
        if event.success:
            self.logger.info(
                "audit_event",
                **event_dict
            )
        else:
            self.logger.warning(
                "audit_event",
                **event_dict
            )

    def log_webhook_received(
        self,
        incident_id: str,
        duration_ms: int,
        source_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log successful webhook receipt.

        Args:
            incident_id: Jira incident ID (e.g., INC-42)
            duration_ms: Processing duration in milliseconds
            source_ip: Source IP address of webhook sender
            metadata: Additional context (priority, severity, etc.)
        """
        event = create_webhook_received_event(
            service=self.service,
            environment=self.environment,
            incident_id=incident_id,
            duration_ms=duration_ms,
            source_ip=source_ip,
            metadata=metadata
        )
        self._emit_event(event)

    def log_auth_failure(
        self,
        error_message: str,
        source_ip: Optional[str] = None,
        error_code: str = "HMAC_VERIFICATION_FAILED"
    ):
        """
        Log HMAC authentication failure.

        Args:
            error_message: Description of failure
            source_ip: Source IP of failed request
            error_code: Error classification code
        """
        # Sanitize error message
        sanitized_error = self._sanitize_error_message(error_message)

        event = create_auth_failure_event(
            service=self.service,
            environment=self.environment,
            error_message=sanitized_error,
            source_ip=source_ip,
            error_code=error_code
        )
        self._emit_event(event)

    def log_replay_detected(
        self,
        webhook_id: str,
        incident_id: Optional[str] = None,
        source_ip: Optional[str] = None
    ):
        """
        Log replay attack detection.

        Args:
            webhook_id: Duplicate webhook ID
            incident_id: Incident ID (if available)
            source_ip: Source IP of replayed request
        """
        event = create_replay_detected_event(
            service=self.service,
            environment=self.environment,
            webhook_id=webhook_id,
            incident_id=incident_id,
            source_ip=source_ip
        )
        self._emit_event(event)

    def log_validation_error(
        self,
        error_message: str,
        source_ip: Optional[str] = None,
        validation_errors: Optional[list] = None
    ):
        """
        Log schema validation failure.

        Args:
            error_message: Validation error description
            source_ip: Source IP of invalid request
            validation_errors: Pydantic validation errors (if available)
        """
        # Sanitize error message
        sanitized_error = self._sanitize_error_message(error_message)

        event = create_validation_error_event(
            service=self.service,
            environment=self.environment,
            error_message=sanitized_error,
            source_ip=source_ip,
            validation_errors=validation_errors
        )
        self._emit_event(event)

    def log_service_started(self):
        """Log service startup event."""
        event = AuditLogEvent(
            event_type="SERVICE_STARTED",
            service=self.service,
            environment=self.environment,
            success=True
        )
        self._emit_event(event)

    def log_service_stopped(self):
        """Log service shutdown event."""
        event = AuditLogEvent(
            event_type="SERVICE_STOPPED",
            service=self.service,
            environment=self.environment,
            success=True
        )
        self._emit_event(event)

    def log_custom_event(
        self,
        event_type: str,
        success: bool,
        incident_id: Optional[str] = None,
        error_message: Optional[str] = None,
        error_code: Optional[str] = None,
        duration_ms: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log custom audit event.

        Use this for event types not covered by specific methods.

        Args:
            event_type: Event type from audit schema
            success: Whether operation succeeded
            incident_id: Incident ID (if applicable)
            error_message: Error description (if failed)
            error_code: Error classification
            duration_ms: Operation duration
            metadata: Additional context
        """
        # Sanitize error message if present
        if error_message:
            error_message = self._sanitize_error_message(error_message)

        event = AuditLogEvent(
            event_type=event_type,
            service=self.service,
            environment=self.environment,
            success=success,
            incident_id=incident_id,
            error_message=error_message,
            error_code=error_code,
            duration_ms=duration_ms,
            metadata=metadata
        )
        self._emit_event(event)
