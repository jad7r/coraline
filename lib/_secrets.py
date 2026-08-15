"""
Secret resolution helper shared by the HTTP clients.

Order of precedence for a secret: **OS keychain first, then environment variable**. Nothing
in ``lib`` accepts a hardcoded key — a missing secret raises so a service fails fast at
startup rather than silently making unauthenticated calls.

The keyring backend is injectable so tests can supply an in-memory fake and never touch the
real OS keychain.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import keyring

# Single keychain namespace for Coreline third-party API keys.
KEYRING_SERVICE = "coreline-secrets"


class SecretNotFoundError(Exception):
    """Raised when a required secret is absent from both keychain and environment."""


def resolve_secret(
    keyring_username: str,
    env_var: str,
    *,
    explicit: Optional[str] = None,
    keyring_backend: Any = keyring,
    service: str = KEYRING_SERVICE,
) -> str:
    """Return a secret from (in order): ``explicit`` arg, OS keychain, then env var.

    ``explicit`` exists only so a caller/test can pass a key directly; production callers
    leave it ``None`` and the value comes from the keychain or environment. Raises
    :class:`SecretNotFoundError` if nothing is found.
    """
    if explicit:
        return explicit

    try:
        from_keychain = keyring_backend.get_password(service, keyring_username)
    except Exception:
        # Keychain unavailable/locked -> fall back to env rather than hard-failing here.
        from_keychain = None
    if from_keychain:
        return from_keychain

    from_env = os.environ.get(env_var)
    if from_env:
        return from_env

    raise SecretNotFoundError(
        f"secret not found: set keychain {service!r}/{keyring_username!r} "
        f"or env {env_var!r}"
    )
