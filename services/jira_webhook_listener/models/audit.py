#!/usr/bin/env python3
"""
Audit Event Models

Implements structured audit logging for SIEM integration.
Matches schema: /schemas/audit/audit-log-event.schema.json

All Coreline services emit audit events matching this structure for:
- Security monitoring
- Compliance (ISO 27001, FedRAMP)
- Incident investigation
- Performance monitoring
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4


class Actor(BaseModel):
    """Entity that triggered the event (user, service account, bot)."""
    type: Literal["user", "service_account", "bot", "system"]
    id: str
    ip_address: Optional[str] = None


class Resource(BaseModel):
    """Resource affected by the event (incident, channel, evidence, etc.)."""
    type: Literal[
        "incident",
        "slack_channel",
        "evidence_marker",
        "pir",
        "archive_file",
        "secret",
        "webhook"
    ]
    id: str
    name: Optional[str] = None


class AuditLogEvent(BaseModel):
    """
    Audit event matching /schemas/audit/audit-log-event.schema.json

    This structure is shipped to SIEM (Chronicle via Cloud Logging) for
    security monitoring and compliance.
    """
    # Required fields
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: Literal[
        "JIRA_WEBHOOK_RECEIVED",
        "JIRA_WEBHOOK_AUTH_FAILURE",
        "JIRA_WEBHOOK_REPLAYED",
        "JIRA_WEBHOOK_VALIDATION_ERROR",
        "INCIDENT_CHANNEL_CREATED",
        "EVIDENCE_MARKER_ADDED",
        "PIR_GENERATION_TRIGGERED",
        "PIR_GENERATION_COMPLETED",
        "PIR_GENERATION_FAILED",
        "PROMPT_INJECTION_DETECTED",
        "ARCHIVE_UPLOAD_INITIATED",
        "ARCHIVE_UPLOAD_COMPLETED",
        "ARCHIVE_UPLOAD_FAILED",
        "SECRET_ACCESS_REQUESTED",
        "SECRET_ACCESS_GRANTED",
        "SECRET_ACCESS_DENIED",
        "SERVICE_STARTED",
        "SERVICE_STOPPED",
        "RATE_LIMIT_EXCEEDED",
        "AUTHORIZATION_FAILURE",
        "DATA_REDACTION_APPLIED"
    ]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service: str  # "jira-webhook-listener", "slack-orchestrator", etc.
    environment: Literal["dev", "staging", "prod"]
    success: bool

    # Optional fields
    incident_id: Optional[str] = Field(None, pattern=r"^[A-Z]+-\d+$")
    actor: Optional[Actor] = None
    resource: Optional[Resource] = None
    metadata: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None  # Sanitized error (no secrets/stack traces)
    error_code: Optional[str] = None  # Error classification
    duration_ms: Optional[int] = None  # Operation duration

    class Config:
        """Pydantic configuration."""
        # Use enum values for serialization
        use_enum_values = True
        # Allow JSON serialization
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

    def to_log_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for structured logging.

        Returns:
            Dictionary safe for JSON serialization and SIEM ingestion
        """
        return self.dict(exclude_none=True, by_alias=True)


# Helper functions for creating common audit events

def create_webhook_received_event(
    service: str,
    environment: str,
    incident_id: str,
    duration_ms: int,
    source_ip: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLogEvent:
    """Create audit event for successful webhook receipt."""
    return AuditLogEvent(
        event_type="JIRA_WEBHOOK_RECEIVED",
        service=service,
        environment=environment,
        success=True,
        incident_id=incident_id,
        actor=Actor(
            type="service_account",
            id="jira-webhook-sender",
            ip_address=source_ip
        ) if source_ip else None,
        resource=Resource(
            type="incident",
            id=incident_id
        ),
        duration_ms=duration_ms,
        metadata=metadata
    )


def create_auth_failure_event(
    service: str,
    environment: str,
    error_message: str,
    source_ip: Optional[str] = None,
    error_code: str = "HMAC_VERIFICATION_FAILED"
) -> AuditLogEvent:
    """Create audit event for HMAC authentication failure."""
    return AuditLogEvent(
        event_type="JIRA_WEBHOOK_AUTH_FAILURE",
        service=service,
        environment=environment,
        success=False,
        actor=Actor(
            type="system",
            id="unknown",
            ip_address=source_ip
        ) if source_ip else None,
        resource=Resource(
            type="webhook",
            id="unknown"
        ),
        error_message=error_message,
        error_code=error_code
    )


def create_replay_detected_event(
    service: str,
    environment: str,
    webhook_id: str,
    incident_id: Optional[str] = None,
    source_ip: Optional[str] = None
) -> AuditLogEvent:
    """Create audit event for replay attack detection."""
    return AuditLogEvent(
        event_type="JIRA_WEBHOOK_REPLAYED",
        service=service,
        environment=environment,
        success=False,
        incident_id=incident_id,
        actor=Actor(
            type="system",
            id="unknown",
            ip_address=source_ip
        ) if source_ip else None,
        resource=Resource(
            type="webhook",
            id=webhook_id
        ),
        error_message=f"Duplicate webhook ID detected: {webhook_id}",
        error_code="REPLAY_ATTACK_DETECTED"
    )


def create_validation_error_event(
    service: str,
    environment: str,
    error_message: str,
    source_ip: Optional[str] = None,
    validation_errors: Optional[list] = None
) -> AuditLogEvent:
    """Create audit event for schema validation failure."""
    metadata = {}
    if validation_errors:
        metadata["validation_errors"] = validation_errors

    return AuditLogEvent(
        event_type="JIRA_WEBHOOK_VALIDATION_ERROR",
        service=service,
        environment=environment,
        success=False,
        actor=Actor(
            type="system",
            id="unknown",
            ip_address=source_ip
        ) if source_ip else None,
        resource=Resource(
            type="webhook",
            id="unknown"
        ),
        error_message=error_message,
        error_code="SCHEMA_VALIDATION_FAILED",
        metadata=metadata if metadata else None
    )
