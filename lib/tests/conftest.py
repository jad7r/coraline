"""Shared test fixtures for ``lib`` — all offline (fake keychain, fake HTTP)."""
from __future__ import annotations

from typing import Optional

import pytest

from lib._http import FakeTransport, HTTPResponse


class FakeKeyring:
    """In-memory keyring stand-in so tests never touch the real OS keychain."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> Optional[str]:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self._store.pop((service, username), None)


@pytest.fixture
def fake_keyring() -> FakeKeyring:
    return FakeKeyring()


@pytest.fixture
def fake_transport() -> FakeTransport:
    return FakeTransport()


def json_response(status: int, payload) -> HTTPResponse:
    import json

    return HTTPResponse(
        status=status,
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
