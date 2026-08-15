"""Secret loading for Coreline services.

Resolution order for every secret:

1. Environment variable (e.g. ``SLACK_BOT_TOKEN``) — preferred for containers
   and CI.
2. OS keychain via ``keyring`` under service name ``Coreline`` — preferred for local
   developer machines (matches ``storage.py``).

Secrets are **never** hardcoded here. If ``fail_fast`` is set, a missing secret
raises :class:`SecretLoadError` at lookup time so a misconfigured service exits
during startup rather than failing later against Slack/Jira.

The keychain is best-effort: if ``keyring`` is not installed or the backend is
unavailable (common in headless CI), we silently fall back to environment
variables only.
"""

from __future__ import annotations

import os
from typing import Optional

# Keychain service name — matches Coreline's storage.py convention.
KEYCHAIN_SERVICE = "Coreline"


class SecretLoadError(Exception):
    """Raised when a required secret cannot be resolved."""


def _keychain_get(key: str) -> Optional[str]:
    """Best-effort keychain lookup. Returns None if unavailable."""
    try:
        import keyring  # imported lazily so the dependency stays optional
    except Exception:
        return None
    try:
        return keyring.get_password(KEYCHAIN_SERVICE, key)
    except Exception:
        # Keychain locked / no backend (headless CI) — treat as "not found".
        return None


class Secrets:
    """Resolves named secrets from the environment or OS keychain.

    Args:
        environment: Deployment environment label (dev/staging/prod). Retained
            for parity with callers and future per-environment behaviour.
        fail_fast: When True, missing required secrets raise ``SecretLoadError``
            immediately; when False, getters return ``None``.
    """

    def __init__(self, environment: str = "prod", fail_fast: bool = True):
        self.environment = environment
        self.fail_fast = fail_fast

    def get(
        self,
        env_var: str,
        *,
        keychain_key: Optional[str] = None,
        required: bool = True,
    ) -> Optional[str]:
        """Resolve a single secret by env var name, then keychain key."""
        value = os.environ.get(env_var)
        if not value:
            value = _keychain_get(keychain_key or env_var.lower())

        if not value and required and self.fail_fast:
            raise SecretLoadError(
                f"Required secret '{env_var}' not found in environment "
                f"or OS keychain (service '{KEYCHAIN_SERVICE}')."
            )
        return value

    # --- Named accessors used by the revived services -----------------------

    def get_slack_bot_token(self) -> Optional[str]:
        """Slack bot token (``xoxb-...``)."""
        return self.get("SLACK_BOT_TOKEN", keychain_key="slack_bot_token")

    def get_jira_webhook_secret(self) -> Optional[str]:
        """Shared HMAC secret for validating Jira webhooks."""
        return self.get("JIRA_WEBHOOK_SECRET", keychain_key="jira_webhook_secret")

    def get_claude_api_key(self) -> Optional[str]:
        """Anthropic API key for the brain service."""
        return self.get("CLAUDE_API_KEY", keychain_key="claude_api_key")


def initialize_secrets(environment: str = "prod", fail_fast: bool = True) -> Secrets:
    """Construct a :class:`Secrets` resolver.

    Secrets are resolved lazily on each getter call, so this never raises on its
    own; ``SecretLoadError`` surfaces when a required secret is actually
    requested (e.g. ``get_slack_bot_token()``).
    """
    return Secrets(environment=environment, fail_fast=fail_fast)
