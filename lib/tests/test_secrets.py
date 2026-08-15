"""Tests for lib._secrets.resolve_secret — keychain-first, env fallback, no hardcoding."""
from __future__ import annotations

import pytest

from lib._secrets import SecretNotFoundError, resolve_secret


def test_explicit_wins(fake_keyring, monkeypatch):
    monkeypatch.setenv("MY_ENV", "from-env")
    fake_keyring.set_password("coreline-secrets", "user", "from-keychain")
    got = resolve_secret(
        "user", "MY_ENV", explicit="explicit-key", keyring_backend=fake_keyring
    )
    assert got == "explicit-key"


def test_keychain_preferred_over_env(fake_keyring, monkeypatch):
    monkeypatch.setenv("MY_ENV", "from-env")
    fake_keyring.set_password("coreline-secrets", "user", "from-keychain")
    got = resolve_secret("user", "MY_ENV", keyring_backend=fake_keyring)
    assert got == "from-keychain"


def test_env_fallback_when_no_keychain(fake_keyring, monkeypatch):
    monkeypatch.setenv("MY_ENV", "from-env")
    got = resolve_secret("user", "MY_ENV", keyring_backend=fake_keyring)
    assert got == "from-env"


def test_missing_everywhere_raises(fake_keyring, monkeypatch):
    monkeypatch.delenv("MY_ENV", raising=False)
    with pytest.raises(SecretNotFoundError):
        resolve_secret("user", "MY_ENV", keyring_backend=fake_keyring)
