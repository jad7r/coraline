"""
Coreline Jira Webhook Listener Service

Receives and validates webhook events from Jira when security incidents
are created or updated. Implements security guardrails (HMAC verification,
replay prevention, schema validation) before triggering downstream
incident response automation.
"""

__version__ = "1.0.0"
