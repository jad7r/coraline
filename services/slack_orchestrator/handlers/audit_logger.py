#!/usr/bin/env python3
"""
Audit Event Logger

Emits structured audit events to Cloud Logging for SIEM ingestion via Chronicle.
All events match /schemas/audit/audit-log-event.schema.json.
"""

import structlog
from typing import Optional, Dict, Any
from services.slack_orchestrator.models.audit import (
    AuditLogEvent,
    create_channel_created_event,
    create_service_started_event,
    create_service_stopped_event
)

logger = structlog.get_logger(__name__)


class AuditLogger:
    """Emits structured audit events to SIEM."""

    def __init__(self, service_name: str, environment: str):
        """
        Initialize audit logger.

        Args:
            service_name: Service identifier (e.g., "slack-orchestrator")
            environment: Deployment environment (dev, staging, prod)
        """
        self.service = service_name
        self.environment = environment
        self.logger = structlog.get_logger(__name__)

    def _emit(self, event: AuditLogEvent):
        """
        Emit audit event to structured logging.

        Args:
            event: AuditLogEvent to emit
        """
        # Convert to dict for structlog
        event_dict = event.to_log_dict()

        # Emit as structured log entry
        # Cloud Logging automatically captures these for SIEM ingestion
        self.logger.info(
            "audit_event",
            **event_dict
        )

    def log_channel_created(
        self,
        incident_id: str,
        channel_id: str,
        channel_name: str,
        duration_ms: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Emit INCIDENT_CHANNEL_CREATED audit event.

        Args:
            incident_id: Jira incident ID
            channel_id: Slack channel ID
            channel_name: Slack channel name
            duration_ms: Operation duration in milliseconds
            metadata: Additional metadata (priority, severity, etc.)
        """
        event = create_channel_created_event(
            service=self.service,
            environment=self.environment,
            incident_id=incident_id,
            channel_id=channel_id,
            channel_name=channel_name,
            duration_ms=duration_ms,
            metadata=metadata
        )
        self._emit(event)

    def log_channel_creation_failed(
        self,
        incident_id: str,
        error_message: str,
        error_code: str,
        duration_ms: int
    ):
        """
        Emit failed channel creation audit event.

        Args:
            incident_id: Jira incident ID
            error_message: Sanitized error message
            error_code: Machine-readable error code
            duration_ms: Operation duration before failure
        """
        event = AuditLogEvent(
            event_type="INCIDENT_CHANNEL_CREATED",
            service=self.service,
            environment=self.environment,
            success=False,
            incident_id=incident_id,
            error_message=error_message,
            error_code=error_code,
            duration_ms=duration_ms
        )
        self._emit(event)

    def log_service_started(self):
        """Emit SERVICE_STARTED audit event."""
        event = create_service_started_event(
            service=self.service,
            environment=self.environment
        )
        self._emit(event)

    def log_service_stopped(self):
        """Emit SERVICE_STOPPED audit event."""
        event = create_service_stopped_event(
            service=self.service,
            environment=self.environment
        )
        self._emit(event)

    def log_healthcheck_failed(self, error_message: str):
        """
        Emit HEALTHCHECK_FAILED audit event.

        Args:
            error_message: Sanitized error message
        """
        event = AuditLogEvent(
            event_type="HEALTHCHECK_FAILED",
            service=self.service,
            environment=self.environment,
            success=False,
            error_message=error_message
        )
        self._emit(event)
