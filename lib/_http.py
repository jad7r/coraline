"""
Minimal injectable HTTP transport for the ``lib`` API clients.

The clients (:mod:`lib.vt_lookup`, :mod:`lib.misp_client`) depend on the small
:class:`HTTPTransport` protocol below rather than on ``requests``/``urllib`` directly. In
production a default urllib-backed transport is used; tests inject a
:class:`FakeTransport` so the whole suite runs **offline** with no network.

``HTTPResponse`` is a tiny value object exposing ``status`` and ``json()`` — enough for the
JSON REST APIs these clients call, without dragging in a heavy dependency.
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes
    headers: dict[str, str]

    def json(self) -> Any:
        if not self.body:
            return None
        return _json.loads(self.body.decode("utf-8"))


@runtime_checkable
class HTTPTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        ...


class UrllibTransport:
    """Default transport backed by the standard library (``urllib``). Network-using.

    Kept dependency-free on purpose so ``lib`` needs no ``requests`` at runtime. Not used in
    tests (they inject a fake), so its network path is not exercised offline.
    """

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        import urllib.error
        import urllib.parse
        import urllib.request

        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        data: Optional[bytes] = None
        req_headers = dict(headers or {})
        if json is not None:
            data = _json.dumps(json).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(
            url, data=data, headers=req_headers, method=method.upper()
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read()
                return HTTPResponse(
                    status=resp.status,
                    body=body,
                    headers={k: v for k, v in resp.headers.items()},
                )
        except urllib.error.HTTPError as e:
            # Surface HTTP error responses as HTTPResponse (with body) rather than raising,
            # so clients can inspect status/body uniformly.
            return HTTPResponse(
                status=e.code,
                body=e.read(),
                headers={k: v for k, v in (e.headers or {}).items()},
            )


class FakeTransport:
    """Deterministic in-memory transport for offline tests.

    Configure with a ``routes`` mapping of ``(METHOD, url_substring) -> HTTPResponse`` (or a
    callable taking the request kwargs and returning an ``HTTPResponse``). Records every
    request in ``.calls`` for assertions. Unmatched requests raise ``AssertionError`` so a
    test can never accidentally depend on the real network.
    """

    def __init__(self, routes: Optional[dict[tuple[str, str], Any]] = None):
        self.routes: dict[tuple[str, str], Any] = routes or {}
        self.calls: list[dict[str, Any]] = []

    def add(self, method: str, url_substring: str, response: Any) -> "FakeTransport":
        self.routes[(method.upper(), url_substring)] = response
        return self

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "json": json,
            }
        )
        for (m, sub), resp in self.routes.items():
            if m == method.upper() and sub in url:
                if callable(resp):
                    return resp(
                        {"url": url, "headers": headers, "params": params, "json": json}
                    )
                return resp
        raise AssertionError(f"FakeTransport: no route for {method.upper()} {url}")
