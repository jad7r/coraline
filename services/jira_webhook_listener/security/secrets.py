#!/usr/bin/env python3
"""
Secret loading for the Jira Webhook Listener.

The archived service pulled the HMAC webhook secret from a `services.shared`
secrets manager backed by Google Secret Manager. That shared module was never
un-archived, and the coordinator directive is explicit: the HMAC webhook secret
and any Jira credentials MUST come from the environment or the OS keychain
(via ``keyring``) and must NEVER be hardcoded.

This module implements that contract with a small, dependency-light loader:

Resolution order for the webhook secret:
    1. ``JIRA_WEBHOOK_SECRET`` environment variable (used in CI / containers).
    2. OS keychain entry ``coreline-jira-webhook-listener / <secret_name>`` via
       ``keyring`` (used on developer workstations).

If neither source yields a value, ``SecretLoadError`` is raised so callers can
fail fast rather than starting the service with an empty secret.
"""

import os
import structlog

logger = structlog.get_logger(__name__)

# Keychain service name and the account/key used for the webhook secret.
KEYRING_SERVICE = "coreline-jira-webhook-listener"
WEBHOOK_SECRET_ENV = "JIRA_WEBHOOK_SECRET"
WEBHOOK_SECRET_KEYRING_KEY = "jira-webhook-secret"


class SecretLoadError(Exception):
    """Raised when a required secret cannot be loaded from any source."""


def _load_from_keyring(key: str) -> str | None:
    """Return a secret from the OS keychain, or None if unavailable.

    ``keyring`` is an optional dependency; if it is not installed or no backend
    is configured, keychain lookup is silently skipped so environment-based
    configuration still works.
    """
    try:
        import keyring
    except ImportError:
        logger.debug(
            "secrets.keyring_unavailable",
            msg="keyring not installed; skipping keychain lookup",
        )
        return None

    try:
        value = keyring.get_password(KEYRING_SERVICE, key)
    except Exception as exc:  # keyring backend errors should not crash startup
        logger.warning(
            "secrets.keyring_error",
            error=str(exc),
            error_type=type(exc).__name__,
            msg="Keychain lookup failed; falling back to environment only",
        )
        return None

    return value or None


class SecretsProvider:
    """Loads service secrets from environment variables or the OS keychain.

    Never logs secret values; only their presence and length are recorded.
    """

    def __init__(self, environment: str):
        self.environment = environment

    def get_jira_webhook_secret(self) -> str:
        """Return the HMAC webhook secret.

        Raises:
            SecretLoadError: if the secret is not found in the environment or
                the OS keychain.
        """
        secret = os.environ.get(WEBHOOK_SECRET_ENV)
        source = "env"

        if not secret:
            secret = _load_from_keyring(WEBHOOK_SECRET_KEYRING_KEY)
            source = "keyring"

        if not secret:
            raise SecretLoadError(
                "JIRA webhook secret not found. Set the "
                f"{WEBHOOK_SECRET_ENV} environment variable or store it in the "
                f"OS keychain (service='{KEYRING_SERVICE}', "
                f"key='{WEBHOOK_SECRET_KEYRING_KEY}')."
            )

        logger.info(
            "secrets.webhook_secret_loaded",
            source=source,
            secret_length=len(secret),
            msg="Webhook secret loaded (value not logged)",
        )
        return secret


def initialize_secrets(environment: str, fail_fast: bool = True) -> SecretsProvider:
    """Create a :class:`SecretsProvider` for the given environment.

    Args:
        environment: Deployment environment ("dev", "staging", "prod").
        fail_fast: Retained for API compatibility with the archived
            ``services.shared`` interface. Secret resolution here is lazy
            (performed by ``get_jira_webhook_secret``), so this flag currently
            only documents intent.

    Returns:
        A configured :class:`SecretsProvider`.
    """
    return SecretsProvider(environment=environment)
