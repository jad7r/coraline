#!/usr/bin/env python3
"""
Coreline MCP server — signed threat-intel tools over FastMCP.

Exposes VirusTotal lookups (:mod:`lib.vt_lookup`), MISP sync (:mod:`lib.misp_client`), and
keychain secret retrieval as MCP tools. **Every tool output is signed** with the Ed25519
enclave adapter (:mod:`lib.enclave_adapter`) before it leaves the process: each tool returns

    {"result": <payload>, "signature": <b64>, "public_key": <b64>, "algorithm": "Ed25519"}

so a client can verify the envelope came from this server's key and was not tampered with in
transit. This is the "sign all MCP tool outputs" requirement.

Secrets (VT/MISP API keys) are pulled from the OS keychain via ``keyring`` (env fallback) —
never from plaintext files, never hardcoded.

Run as a stdio MCP server::

    python scripts/coreline_mcp_server.py

The tool *functions* are also importable and callable directly (they are plain functions),
which is how the offline e2e test exercises the signed-envelope contract without launching
a stdio server.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Optional

# Allow running as a script: ensure the repo root is importable so ``lib`` / ``core`` resolve.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keyring

from lib.enclave_adapter import EnclaveAdapter
from lib.misp_client import MISPClient
from lib.vt_lookup import VTClient

# Single adapter instance -> one stable server signing key (generated+stored on first use).
_adapter = EnclaveAdapter(key_id="coreline-mcp-server")


def sign_envelope(result: Any) -> dict[str, Any]:
    """Wrap a tool result in a signed envelope ``{result, signature, public_key, algorithm}``.

    The signature is computed over a canonical form of ``{"result": result}`` so the bound
    bytes are exactly what a verifier reconstructs from the envelope's ``result`` field.
    """
    to_sign = {"result": result}
    env = _adapter.sign(to_sign)
    return {
        "result": result,
        "signature": env["signature"],
        "public_key": env["public_key"],
        "algorithm": env["algorithm"],
    }


def verify_envelope(envelope: dict[str, Any]) -> bool:
    """Verify a signed envelope produced by :func:`sign_envelope`. Fail-closed."""
    try:
        return EnclaveAdapter.verify(
            {"result": envelope["result"]},
            envelope["signature"],
            envelope["public_key"],
        )
    except Exception:
        return False


# -- tool implementations (plain functions -> directly unit-testable) -------------------

def _vt_lookup(kind: str, indicator: str) -> dict[str, Any]:
    client = VTClient()  # key from keychain/env; default urllib transport
    if kind == "hash":
        return client.lookup_hash(indicator)
    if kind == "ip":
        return client.lookup_ip(indicator)
    if kind == "domain":
        return client.lookup_domain(indicator)
    raise ValueError(f"kind must be one of hash|ip|domain, got {kind!r}")


def _misp_search(value: str, type_: Optional[str], base_url: str) -> list[dict[str, Any]]:
    client = MISPClient(base_url)  # key from keychain/env
    return client.search_attributes(value=value, type_=type_)


def _misp_sync(events: list[dict[str, Any]], base_url: str) -> dict[str, Any]:
    client = MISPClient(base_url)
    return client.sync(events)


def _get_secret(name: str, service: str) -> dict[str, Any]:
    """Report only whether a secret is present — never returns the secret value itself."""
    value = keyring.get_password(service, name)
    return {"service": service, "name": name, "present": value is not None}


# -- FastMCP registration ---------------------------------------------------------------

def build_server() -> Any:
    """Construct and return the FastMCP server with all tools registered.

    Each registered tool wraps its result via :func:`sign_envelope`, so every MCP tool
    output is signed before return.
    """
    from fastmcp import FastMCP

    mcp = FastMCP("coreline-threat-intel")

    @mcp.tool(
        name="vt_lookup",
        description="VirusTotal v3 lookup of a hash, IP, or domain. Returns a signed envelope.",
    )
    def vt_lookup(kind: str, indicator: str) -> dict[str, Any]:
        return sign_envelope(_vt_lookup(kind, indicator))

    @mcp.tool(
        name="misp_search",
        description="Search MISP attributes by value/type. Returns a signed envelope.",
    )
    def misp_search(
        value: str, base_url: str, type: Optional[str] = None
    ) -> dict[str, Any]:
        return sign_envelope(_misp_search(value, type, base_url))

    @mcp.tool(
        name="misp_sync",
        description="Push a batch of events to MISP. Returns a signed envelope.",
    )
    def misp_sync(events: list[dict[str, Any]], base_url: str) -> dict[str, Any]:
        return sign_envelope(_misp_sync(events, base_url))

    @mcp.tool(
        name="secret_present",
        description=(
            "Check whether an API key exists in the OS keychain (never returns the value). "
            "Returns a signed envelope."
        ),
    )
    def secret_present(name: str, service: str = "coreline-secrets") -> dict[str, Any]:
        return sign_envelope(_get_secret(name, service))

    return mcp


def main() -> None:
    server = build_server()
    server.run()  # stdio transport by default


if __name__ == "__main__":
    main()
