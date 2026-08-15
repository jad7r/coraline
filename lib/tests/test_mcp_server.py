"""
Tests for scripts/coreline_mcp_server.py.

Exercises the signed-envelope contract directly (no stdio server needed) and confirms the
server object registers the expected tools. All offline: VT/MISP tool paths are driven with
fake transports + fake keychains where invoked, and envelope signing uses a fake keychain
via a patched adapter.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

# Make scripts/ importable.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from lib.enclave_adapter import EnclaveAdapter  # noqa: E402
from lib.tests.conftest import FakeKeyring  # noqa: E402


@pytest.fixture
def server_mod(monkeypatch):
    """Import the MCP server module with its signing adapter backed by a fake keychain."""
    import scripts.coreline_mcp_server as mod

    importlib.reload(mod)
    # Swap the module-level adapter for one using an in-memory keychain.
    mod._adapter = EnclaveAdapter(key_id="coreline-mcp-server", keyring_backend=FakeKeyring())
    return mod


def test_sign_envelope_shape_and_verifies(server_mod):
    env = server_mod.sign_envelope({"indicator": "1.2.3.4", "verdict": "clean"})
    assert set(env) == {"result", "signature", "public_key", "algorithm"}
    assert env["algorithm"] == "Ed25519"
    assert server_mod.verify_envelope(env) is True


def test_tampered_envelope_fails_verification(server_mod):
    env = server_mod.sign_envelope({"n": 1})
    env["result"] = {"n": 2}  # tamper after signing
    assert server_mod.verify_envelope(env) is False


def test_envelope_verifies_against_reported_public_key(server_mod):
    env = server_mod.sign_envelope({"x": "y"})
    # Verify independently using ONLY the fields in the envelope.
    ok = EnclaveAdapter.verify(
        {"result": env["result"]}, env["signature"], env["public_key"]
    )
    assert ok is True


def test_vt_tool_returns_signed_envelope(server_mod, fake_keyring):
    from lib._http import FakeTransport
    from lib.tests.conftest import json_response
    from lib import vt_lookup as vt

    sha = "b" * 64
    transport = FakeTransport()
    transport.add(
        "GET",
        f"/files/{sha}",
        json_response(200, {"data": {"id": sha, "attributes": {"last_analysis_stats": {"malicious": 3}}}}),
    )
    fake_keyring.set_password("coreline-secrets", "virustotal_api_key", "k")

    # Patch VTClient construction inside the server to use fakes.
    def fake_vt_client(*a, **kw):
        return vt.VTClient(transport=transport, keyring_backend=fake_keyring)

    server_mod.VTClient = fake_vt_client

    envelope = server_mod.sign_envelope(server_mod._vt_lookup("hash", sha))
    assert envelope["result"]["stats"]["malicious"] == 3
    assert server_mod.verify_envelope(envelope) is True


def test_build_server_registers_expected_tools(server_mod):
    server = server_mod.build_server()
    import asyncio

    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert {"vt_lookup", "misp_search", "misp_sync", "secret_present"} <= names


def test_secret_tool_never_returns_value(server_mod, fake_keyring, monkeypatch):
    fake_keyring.set_password("coreline-secrets", "virustotal_api_key", "super-secret")
    monkeypatch.setattr(server_mod, "keyring", fake_keyring)
    out = server_mod._get_secret("virustotal_api_key", "coreline-secrets")
    assert out == {"service": "coreline-secrets", "name": "virustotal_api_key", "present": True}
    assert "super-secret" not in str(out)
