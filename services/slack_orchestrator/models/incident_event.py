#!/usr/bin/env python3
"""
Incident Event Model

Schema for incident notification events published by jira-webhook-listener
via Redis Pub/Sub and consumed by slack-orchestrator.

Redis Channel: coreline:incident:created
Publisher: jira-webhook-listener (after successful webhook validation)
Consumer: slack-orchestrator (IncidentSubscriber)
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import Optional
from datetime import datetime


class IncidentEvent(BaseModel):
    """
    Incident notification event published to Redis Pub/Sub.

    Published after Jira webhook validation succeeds and incident is confirmed
    to be a Security Incident type.
    """

    # === Required Fields ===
    incident_id: str = Field(
        ...,
        pattern=r"^[A-Z]+-\d+$",
        description="Jira incident ID (e.g., INC-42, INCIDENT-2026-001)"
    )

    summary: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Brief incident summary from Jira issue summary field"
    )

    priority: str = Field(
        ...,
        description="Incident priority (P1, P2, P3, P4)"
    )

    severity: str = Field(
        ...,
        description="Incident severity (Critical, High, Medium, Low)"
    )

    detection_time: datetime = Field(
        ...,
        description="When incident was detected (ISO 8601 timestamp)"
    )

    webhook_event: str = Field(
        ...,
        description="Jira webhook event type (jira:issue_created or jira:issue_updated)"
    )

    jira_url: str = Field(
        ...,
        description="Direct URL to Jira issue for navigation"
    )

    # === Optional Fields ===
    incident_commander: Optional[str] = Field(
        default=None,
        description="Assigned incident commander (if specified in Jira)"
    )

    affected_systems: Optional[list[str]] = Field(
        default=None,
        description="List of affected systems/services"
    )

    # === Configuration ===
    # Pydantic v2 serializes datetime to ISO 8601 by default (model_dump_json),
    # so no custom json_encoders are needed.
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "incident_id": "INC-42",
                "summary": "Suspected ransomware on PROD-FILE-01",
                "priority": "P1",
                "severity": "Critical",
                "detection_time": "2026-05-21T14:32:00.123Z",
                "incident_commander": "Josh Dellinger",
                "affected_systems": ["PROD-FILE-01", "PROD-BACKUP-02"],
                "webhook_event": "jira:issue_created",
                "jira_url": "https://pantheon.atlassian.net/browse/INC-42"
            }
        }
    )

    def to_json_string(self) -> str:
        """
        Serialize event to JSON string for Redis publishing.

        Returns:
            JSON string representation of the event
        """
        return self.model_dump_json()
