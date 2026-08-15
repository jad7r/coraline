"""Shared helpers for Coreline always-on services.

Currently exposes the secrets loader used by the revived FastAPI services
(Slack orchestrator, Jira webhook listener, brain service). Secrets are read
from environment variables first, then the OS keychain via ``keyring`` — never
hardcoded in source.
"""

from .secrets import (
    Secrets,
    SecretLoadError,
    initialize_secrets,
)

__all__ = [
    "Secrets",
    "SecretLoadError",
    "initialize_secrets",
]
