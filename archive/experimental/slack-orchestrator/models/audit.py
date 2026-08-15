#!/usr/bin/env python3
"""
Audit Event Models

Structured audit events matching /schemas/audit/audit-log-event.schema.json
for emission to SIEM via Cloud Logging.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid


class AuditLogEvent(BaseModel):
    """
    Coreline audit event schema.

    Matches /schemas/audit/audit-log-event.schema.json for SIEM compliance.
    """

    # === Required Fields ===
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this audit event (UUID v4)"
    )

    event_type: str = Field(
        ...,
        description="Type of security-relevant event that occurred"
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO 8601 timestamp when event occurred (UTC)"
    )

    service: str = Field(
        ...,
        description="Coreline service that generated this event"
    )

    environment: str = Field(
        ...,
        description="Deployment environment (dev, staging, prod)"
    )

    success: bool = Field(
        ...,
        description="Whether the operation succeeded (true) or failed (false)"
    )

    # === Optional Fields ===
    incident_id: Optional[str] = Field(
        default=None,
        description="Jira issue key (e.g., INC-42) if event is incident-related"
    )

    resource: Optional[Dict[str, str]] = Field(
        default=None,
        description="Resource being acted upon"
    )

    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Event-specific metadata (flexible schema)"
    )

    error_message: Optional[str] = Field(
        default=None,
        description="Error message if success=false (sanitized, no secrets)"
    )

    error_code: Optional[str] = Field(
        default=None,
        description="Machine-readable error code"
    )

    duration_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="Operation duration in milliseconds"
    )

    labels: Optional[Dict[str, str]] = Field(
        default=None,
        description="Key-value pairs for custom tagging"
    )

    # === Configuration ===
    class Config:
        """Pydantic model configuration."""

        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

    def to_log_dict(self) -> Dict[str, Any]:
        """
        Convert event to dictionary for structured logging.

        Returns:
            Dictionary representation of the audit event
        """
        return self.model_dump(exclude_none=True)


def create_channel_created_event(
    service: str,
    environment: str,
    incident_id: str,
    channel_id: str,
    channel_name: str,
    duration_ms: int,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLogEvent:
    """
    Create INCIDENT_CHANNEL_CREATED audit event.

    Args:
        service: Service name (slack-orchestrator)
        environment: Deployment environment
        incident_id: Jira incident ID
        channel_id: Slack channel ID
        channel_name: Slack channel name
        duration_ms: Operation duration in milliseconds
        metadata: Additional metadata

    Returns:
        AuditLogEvent instance
    """
    return AuditLogEvent(
        event_type="INCIDENT_CHANNEL_CREATED",
        service=service,
        environment=environment,
        success=True,
        incident_id=incident_id,
        resource={
            "type": "slack_channel",
            "id": channel_id,
            "name": channel_name
        },
        duration_ms=duration_ms,
        metadata=metadata or {}
    )


def create_service_started_event(
    service: str,
    environment: str
) -> AuditLogEvent:
    """
    Create SERVICE_STARTED audit event.

    Args:
        service: Service name
        environment: Deployment environment

    Returns:
        AuditLogEvent instance
    """
    return AuditLogEvent(
        event_type="SERVICE_STARTED",
        service=service,
        environment=environment,
        success=True
    )


def create_service_stopped_event(
    service: str,
    environment: str
) -> AuditLogEvent:
    """
    Create SERVICE_STOPPED audit event.

    Args:
        service: Service name
        environment: Deployment environment

    Returns:
        AuditLogEvent instance
    """
    return AuditLogEvent(
        event_type="SERVICE_STOPPED",
        service=service,
        environment=environment,
        success=True
    )
