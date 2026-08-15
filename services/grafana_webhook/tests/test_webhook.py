"""Tests for the Grafana IRM webhook service."""

import hashlib
import hmac
import importlib
import json

import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    """A Flask test client with a known WEBHOOK_SECRET.

    The secret is read at import time into a module-level constant, so we set
    the env var and (re)import the module fresh inside the fixture.
    """
    monkeypatch.setenv("WEBHOOK_SECRET", "testsecret")
    # Isolate the JSONL log file away from the repo working dir.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEBHOOK_LOG_PATH", str(tmp_path / "webhooks.jsonl"))

    from services.grafana_webhook import main as main_module

    importlib.reload(main_module)
    main_module.app.config.update(TESTING=True)
    return main_module.app.test_client()


def _sign(body: bytes, secret: str = "testsecret") -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "grafana-webhook"


def test_webhook_valid_signature(client):
    payload = {"event_type": "incident.created", "incident": {"id": "abc123"}}
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        data=body,
        headers={
            "X-Grafana-Signature": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "accepted"
    assert data["grafana_incident_id"] == "abc123"


def test_webhook_invalid_signature(client):
    payload = {"event_type": "incident.created", "incident": {"id": "abc123"}}
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        data=body,
        headers={
            "X-Grafana-Signature": "deadbeef",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid signature"


def test_webhook_non_ascii_signature(client):
    """A non-ASCII X-Grafana-Signature must be a clean 401, not a 500.

    hmac.compare_digest raises TypeError on non-ASCII input; verify_signature
    swallows that into a failed comparison.
    """
    payload = {"event_type": "incident.created", "incident": {"id": "abc123"}}
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        data=body,
        headers={
            "X-Grafana-Signature": "café",  # non-ASCII
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid signature"


def test_webhook_malformed_body_is_400(client):
    """A correctly-signed but non-JSON body is a client 400, not a 500."""
    body = b"this is not json"
    resp = client.post(
        "/webhook",
        data=body,
        headers={
            "X-Grafana-Signature": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 400
    assert "Malformed" in resp.get_json()["error"]


def test_webhook_non_object_body_is_400(client):
    """A valid-JSON but non-object body (list) is a client 400, not a 500."""
    body = b"[]"
    resp = client.post(
        "/webhook",
        data=body,
        headers={
            "X-Grafana-Signature": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 400
    assert "Malformed" in resp.get_json()["error"]


def test_webhook_internal_error_body_is_generic(client, monkeypatch):
    """When event processing raises, the 500 body must not leak internals."""
    from services.grafana_webhook import main as main_module

    def boom(_payload):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(main_module.sync_handler, "handle_webhook", boom)

    payload = {"event_type": "incident.created", "incident": {"id": "abc123"}}
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        data=body,
        headers={
            "X-Grafana-Signature": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 500
    assert resp.get_json()["error"] == "Internal error processing webhook"
    assert "secret internal detail" not in resp.get_data(as_text=True)
