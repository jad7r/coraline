#!/usr/bin/env python3
"""
Pydantic Models for Jira Webhook Payloads

Implements Security Guardrail G2.3: Schema Validation
Validates webhook payload structure and sanitizes inputs to prevent injection attacks.

Security Features:
- Strict regex validation on issue keys (prevents path traversal)
- Field length limits (prevents DoS via large payloads)
- Type safety via Pydantic
- Custom validators for security-critical fields
"""

from pydantic import BaseModel, Field, validator
from typing import Literal, Optional, Dict, Any, List
from datetime import datetime


class JiraUser(BaseModel):
    """Jira user representation in webhooks."""
    accountId: str
    emailAddress: Optional[str] = None
    displayName: str
    active: bool = True


class JiraIssuetype(BaseModel):
    """Jira issue type information."""
    id: str
    name: str
    subtask: bool = False


class JiraPriority(BaseModel):
    """Jira priority information."""
    id: str
    name: str  # P1, P2, P3, P4, etc.


class JiraStatus(BaseModel):
    """Jira status information."""
    id: str
    name: str  # Open, In Progress, Resolved, Closed, etc.


class JiraFields(BaseModel):
    """
    Jira issue fields from webhook payload.

    Matches structure from /schemas/jira/security-incident.schema.json
    """
    issuetype: JiraIssuetype
    priority: Optional[JiraPriority] = None
    status: JiraStatus
    summary: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = Field(None, max_length=10000)
    assignee: Optional[JiraUser] = None
    reporter: Optional[JiraUser] = None
    created: datetime
    updated: datetime

    # Custom fields (optional, populated if configured)
    # These map to customfield_* in actual Jira webhooks
    customfield_severity: Optional[str] = None  # Critical, High, Medium, Low
    customfield_incident_lead: Optional[JiraUser] = None
    customfield_affected_systems: Optional[List[str]] = None
    customfield_detection_vector: Optional[str] = None

    @validator('summary', 'description')
    def sanitize_text_fields(cls, v):
        """
        Sanitize text fields to prevent injection attacks.

        - Strips control characters
        - Normalizes Unicode
        - Prevents homoglyph attacks
        """
        if v is None:
            return v

        # Strip control characters (except newlines/tabs for description)
        import unicodedata
        v = ''.join(ch for ch in v if unicodedata.category(ch)[0] != 'C' or ch in '\n\t')

        # Normalize Unicode to prevent homoglyph attacks
        v = unicodedata.normalize('NFKC', v)

        return v.strip()


class JiraIssue(BaseModel):
    """
    Jira issue representation from webhook.

    Security: Issue key validation prevents path traversal attacks.
    """
    id: str
    key: str = Field(..., pattern=r"^[A-Z]+-\d+$")
    self: str  # URL to issue in Jira
    fields: JiraFields

    @validator('key')
    def validate_issue_key_security(cls, v):
        """
        Additional security validation for issue keys.

        Prevents:
        - Path traversal: ../../../etc/passwd
        - Null bytes: INC-42\x00
        - Special characters: INC-42; DROP TABLE
        """
        # Check for path traversal attempts
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError("Invalid issue key: contains path traversal characters")

        # Check for null bytes
        if '\x00' in v:
            raise ValueError("Invalid issue key: contains null bytes")

        # Check for shell metacharacters
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r']
        if any(char in v for char in dangerous_chars):
            raise ValueError("Invalid issue key: contains dangerous characters")

        return v


class JiraWebhookPayload(BaseModel):
    """
    Complete Jira webhook payload.

    Validates webhook event type and structure to ensure only
    security incident creation/updates trigger Coreline workflow.

    Example webhook event types:
    - jira:issue_created
    - jira:issue_updated
    - jira:issue_deleted (rejected by Coreline)
    """
    webhookEvent: Literal["jira:issue_created", "jira:issue_updated"]
    timestamp: datetime
    issue: JiraIssue

    # Webhook metadata
    webhookEventId: Optional[str] = None  # For replay prevention
    user: Optional[JiraUser] = None  # User who triggered the webhook

    @validator('webhookEvent')
    def validate_webhook_event_type(cls, v):
        """Ensure webhook event is a supported type."""
        # Pydantic Literal already enforces this, but explicit for clarity
        allowed_events = ["jira:issue_created", "jira:issue_updated"]
        if v not in allowed_events:
            raise ValueError(f"Unsupported webhook event type: {v}")
        return v

    def is_security_incident(self) -> bool:
        """
        Check if this webhook represents a Security Incident.

        Coreline only processes webhooks for Security Incident issue types.
        Other issue types (Bug, Story, Task, etc.) are ignored.

        Returns:
            True if issue type is "Security Incident", False otherwise
        """
        issue_type_name = self.issue.fields.issuetype.name
        return issue_type_name.lower() in [
            "security incident",
            "incident",
            "security-incident"
        ]

    def get_incident_id(self) -> str:
        """Get incident ID (issue key)."""
        return self.issue.key

    def get_incident_summary(self) -> str:
        """Get incident summary (issue summary)."""
        return self.issue.fields.summary

    def get_priority(self) -> Optional[str]:
        """Get incident priority (P1, P2, P3, P4)."""
        if self.issue.fields.priority:
            return self.issue.fields.priority.name
        return None

    def get_severity(self) -> Optional[str]:
        """Get incident severity from custom field."""
        return self.issue.fields.customfield_severity

    def get_incident_commander(self) -> Optional[str]:
        """Get Incident Commander from custom field or assignee."""
        # Prefer custom field if set
        if self.issue.fields.customfield_incident_lead:
            return self.issue.fields.customfield_incident_lead.displayName

        # Fallback to assignee
        if self.issue.fields.assignee:
            return self.issue.fields.assignee.displayName

        return None

    class Config:
        """Pydantic configuration."""
        # Allow extra fields (Jira webhooks have many fields we don't need)
        extra = "allow"
        # Use enum values for serialization
        use_enum_values = True
