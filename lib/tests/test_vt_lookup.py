"""Tests for lib.vt_lookup.VTClient — offline via FakeTransport + fake keychain."""
from __future__ import annotations

import pytest

from lib._http import FakeTransport
from lib.tests.conftest import json_response
from lib.vt_lookup import VTClient, VTError

SHA256 = "a" * 64


def make_client(fake_keyring, transport):
    fake_keyring.set_password("coreline-secrets", "virustotal_api_key", "fake-key")
    return VTClient(transport=transport, keyring_backend=fake_keyring)


def test_lookup_hash_parses_stats(fake_keyring):
    transport = FakeTransport()
    transport.add(
        "GET",
        f"/files/{SHA256}",
        json_response(
            200,
            {
                "data": {
                    "id": SHA256,
                    "attributes": {
                        "last_analysis_stats": {"malicious": 7, "harmless": 60}
                    },
                }
            },
        ),
    )
    client = make_client(fake_keyring, transport)
    out = client.lookup_hash(SHA256)
    assert out["found"] is True
    assert out["stats"]["malicious"] == 7
    # API key sent in header, not URL.
    assert transport.calls[0]["headers"]["x-apikey"] == "fake-key"


def test_lookup_ip_and_domain(fake_keyring):
    transport = FakeTransport()
    transport.add("GET", "/ip_addresses/8.8.8.8", json_response(200, {"data": {"id": "8.8.8.8", "attributes": {}}}))
    transport.add("GET", "/domains/evil.test", json_response(200, {"data": {"id": "evil.test", "attributes": {}}}))
    client = make_client(fake_keyring, transport)
    assert client.lookup_ip("8.8.8.8")["found"] is True
    assert client.lookup_domain("evil.test")["found"] is True


def test_404_is_not_found_not_error(fake_keyring):
    transport = FakeTransport()
    transport.add("GET", f"/files/{SHA256}", json_response(404, {"error": {"code": "NotFoundError"}}))
    client = make_client(fake_keyring, transport)
    out = client.lookup_hash(SHA256)
    assert out["found"] is False
    assert out["stats"] is None


def test_invalid_hash_rejected(fake_keyring):
    client = make_client(fake_keyring, FakeTransport())
    with pytest.raises(VTError):
        client.lookup_hash("nope")


def test_server_error_raises(fake_keyring):
    transport = FakeTransport()
    transport.add("GET", f"/files/{SHA256}", json_response(500, {"error": "boom"}))
    client = make_client(fake_keyring, transport)
    with pytest.raises(VTError):
        client.lookup_hash(SHA256)


def test_missing_key_raises_before_any_request(fake_keyring, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(Exception):
        VTClient(transport=FakeTransport(), keyring_backend=fake_keyring)
