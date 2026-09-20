"""Secret loading for Coreline services.

Resolution order: CORELINE_ environment name, legacy environment aliases,
Coreline OS keychain (lowercase key), then legacy secops-secure-enclave keychain
(environment-style names). Empty values are treated as absent.

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


def _keychain_get(key: str, service: str = KEYCHAIN_SERVICE) -> Optional[str]:
    """Best-effort keychain lookup. Returns None if unavailable."""
    try:
        import keyring  # imported lazily so the dependency stays optional
    except Exception:
        return None
    try:
        return keyring.get_password(service, key)
    except Exception:
        # Keychain locked / no backend (headless CI) — treat as "not found".
        return None


# Preserve both the old shared-loader and brain-service Anthropic names.
_SECRET_ALIASES = {
    "ANTHROPIC_API_KEY": ("ANTHROPIC_API_KEY", "CLAUDE_API_KEY"),
}


def _secret_names(env_var: str) -> tuple[str, ...]:
    name = env_var.removeprefix("CORELINE_")
    if name == "CLAUDE_API_KEY":
        name = "ANTHROPIC_API_KEY"
    aliases = _SECRET_ALIASES.get(name, (name,))
    return tuple(f"CORELINE_{alias}" for alias in aliases) + aliases


def read_secret(env_var: str, *, keychain_key: Optional[str] = None) -> Optional[str]:
    """Resolve a secret consistently for startup, providers, and readiness."""
    names = _secret_names(env_var)
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    key = keychain_key or names[0].removeprefix("CORELINE_").lower()
    # The original shared accessor used claude_api_key, not anthropic_api_key.
    keys = (key, "claude_api_key") if names[0] == "CORELINE_ANTHROPIC_API_KEY" else (key,)
    for candidate in dict.fromkeys(keys):
        value = _keychain_get(candidate)
        if value:
            return value
    for name in names:
        value = _keychain_get(name, "secops-secure-enclave")
        if value:
            return value
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
        value = read_secret(env_var, keychain_key=keychain_key)

        if not value and required and self.fail_fast:
            raise SecretLoadError(
                f"Required secret '{_secret_names(env_var)[0]}' not found in environment "
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
        return self.get("ANTHROPIC_API_KEY")

    def get_jira_api_token(self) -> Optional[str]:
        return self.get("JIRA_API_TOKEN")

    def get_jira_email(self) -> Optional[str]:
        return self.get("JIRA_EMAIL")


def initialize_secrets(environment: str = "prod", fail_fast: bool = True) -> Secrets:
    """Construct a :class:`Secrets` resolver.

    Secrets are resolved lazily on each getter call, so this never raises on its
    own; ``SecretLoadError`` surfaces when a required secret is actually
    requested (e.g. ``get_slack_bot_token()``).
    """
    return Secrets(environment=environment, fail_fast=fail_fast)
