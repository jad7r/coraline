"""
VirusTotal v3 API client.

``VTClient`` looks up file hashes, IP addresses, and domains against the VirusTotal v3 API.

Security / testability contract:

- **No hardcoded key.** The API key is resolved OS-keychain-first, then ``VT_API_KEY`` env
  (see :func:`lib._secrets.resolve_secret`). A missing key raises before any request.
- **HTTP is injectable.** The client talks to a :class:`lib._http.HTTPTransport`; tests pass
  a :class:`lib._http.FakeTransport` so the suite is fully offline. The default transport is
  urllib-backed and only constructed lazily when no transport is injected.

Returned values are the parsed JSON ``data`` object from VirusTotal, plus a small normalized
summary the MCP layer can sign and hand back without leaking the full raw response.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from lib._http import HTTPTransport, UrllibTransport
from lib._secrets import resolve_secret

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_KEYRING_USERNAME = "virustotal_api_key"
VT_ENV_VAR = "VT_API_KEY"

# Accept MD5 (32), SHA-1 (40), SHA-256 (64) hex digests.
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


class VTError(Exception):
    """VirusTotal client error (bad input, auth failure, or non-2xx response)."""


class VTClient:
    """Client for VirusTotal v3 IOC lookups."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        transport: Optional[HTTPTransport] = None,
        keyring_backend: Any = None,
        base_url: str = VT_API_BASE,
    ):
        """
        Args:
            api_key: explicit key (mainly for tests). Production leaves this ``None`` and the
                key is pulled from keychain/env.
            transport: injectable HTTP transport; defaults to a urllib transport.
            keyring_backend: injectable keyring (tests pass a fake); defaults to real keyring.
            base_url: override for the API root (tests).
        """
        kwargs = {"explicit": api_key}
        if keyring_backend is not None:
            kwargs["keyring_backend"] = keyring_backend
        self._api_key = resolve_secret(VT_KEYRING_USERNAME, VT_ENV_VAR, **kwargs)
        self._transport = transport or UrllibTransport()
        self._base = base_url.rstrip("/")

    # -- public lookups ----------------------------------------------------------------

    def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        if not isinstance(file_hash, str) or not _HASH_RE.match(file_hash.strip()):
            raise VTError(f"not a valid md5/sha1/sha256 hash: {file_hash!r}")
        return self._get(f"/files/{file_hash.strip()}", indicator=file_hash.strip())

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        if not isinstance(ip, str) or not ip.strip():
            raise VTError("ip must be a non-empty string")
        return self._get(f"/ip_addresses/{ip.strip()}", indicator=ip.strip())

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        if not isinstance(domain, str) or not domain.strip():
            raise VTError("domain must be a non-empty string")
        return self._get(f"/domains/{domain.strip()}", indicator=domain.strip())

    # -- internals ---------------------------------------------------------------------

    def _get(self, path: str, *, indicator: str) -> dict[str, Any]:
        resp = self._transport.request(
            "GET",
            f"{self._base}{path}",
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )
        if resp.status == 404:
            # VT returns 404 for indicators it has never seen — a normal, non-error result.
            return {
                "indicator": indicator,
                "found": False,
                "stats": None,
                "data": None,
            }
        if resp.status < 200 or resp.status >= 300:
            raise VTError(f"VirusTotal returned HTTP {resp.status} for {path}")

        payload = resp.json() or {}
        data = payload.get("data")
        stats = None
        if isinstance(data, dict):
            attrs = data.get("attributes") or {}
            stats = attrs.get("last_analysis_stats")
        return {
            "indicator": indicator,
            "found": True,
            "stats": stats,
            "data": data,
        }
