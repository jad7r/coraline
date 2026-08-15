"""Tests for lib.misp_client.MISPClient — offline via FakeTransport + fake keychain."""
from __future__ import annotations

import pytest

from lib._http import FakeTransport
from lib.misp_client import MISPClient, MISPError
from lib.tests.conftest import json_response

BASE = "https://misp.example.org"


def make_client(fake_keyring, transport):
    fake_keyring.set_password("coreline-secrets", "misp_api_key", "fake-misp-key")
    return MISPClient(BASE, transport=transport, keyring_backend=fake_keyring)


def test_search_attributes_returns_list(fake_keyring):
    transport = FakeTransport()
    transport.add(
        "POST",
        "/attributes/restSearch",
        json_response(200, {"response": {"Attribute": [{"value": "1.2.3.4", "type": "ip-dst"}]}}),
    )
    client = make_client(fake_keyring, transport)
    results = client.search_attributes(value="1.2.3.4", type_="ip-dst")
    assert results == [{"value": "1.2.3.4", "type": "ip-dst"}]
    # Auth header uses raw key (no Bearer).
    assert transport.calls[0]["headers"]["Authorization"] == "fake-misp-key"


def test_search_empty_when_no_attribute_key(fake_keyring):
    transport = FakeTransport()
    transport.add("POST", "/attributes/restSearch", json_response(200, {"response": {}}))
    client = make_client(fake_keyring, transport)
    assert client.search_attributes(value="x") == []


def test_add_event_wraps_under_event_key(fake_keyring):
    transport = FakeTransport()
    transport.add("POST", "/events/add", json_response(200, {"Event": {"id": "42", "info": "test"}}))
    client = make_client(fake_keyring, transport)
    out = client.add_event({"info": "test"})
    assert out["id"] == "42"
    # Request body wrapped under Event.
    assert transport.calls[0]["json"] == {"Event": {"info": "test"}}


def test_add_event_does_not_double_wrap(fake_keyring):
    transport = FakeTransport()
    transport.add("POST", "/events/add", json_response(200, {"Event": {"id": "1"}}))
    client = make_client(fake_keyring, transport)
    client.add_event({"Event": {"info": "already wrapped"}})
    assert transport.calls[0]["json"] == {"Event": {"info": "already wrapped"}}


def test_sync_records_partial_errors(fake_keyring):
    transport = FakeTransport()

    def responder(req):
        info = req["json"]["Event"].get("info")
        if info == "bad":
            return json_response(500, {"error": "boom"})
        return json_response(200, {"Event": {"id": info}})

    transport.add("POST", "/events/add", responder)
    client = make_client(fake_keyring, transport)
    summary = client.sync([{"info": "ok1"}, {"info": "bad"}, {"info": "ok2"}])
    assert summary["added"] == 2
    assert len(summary["errors"]) == 1
    assert summary["errors"][0]["index"] == 1


def test_add_event_error_raises(fake_keyring):
    transport = FakeTransport()
    transport.add("POST", "/events/add", json_response(403, {"error": "forbidden"}))
    client = make_client(fake_keyring, transport)
    with pytest.raises(MISPError):
        client.add_event({"info": "x"})


def test_base_url_required(fake_keyring):
    with pytest.raises(MISPError):
        MISPClient("", transport=FakeTransport(), keyring_backend=fake_keyring, api_key="k")
