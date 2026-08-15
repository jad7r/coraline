"""
MISP (Malware Information Sharing Platform) client.

``MISPClient`` searches attributes and creates/syncs events against a MISP instance's REST
API. Same security/testability contract as :mod:`lib.vt_lookup`:

- **No hardcoded key.** The API key is resolved OS-keychain-first, then ``MISP_API_KEY``
  env. A missing key raises before any request.
- **HTTP is injectable.** Talks to a :class:`lib._http.HTTPTransport`; tests inject a
  :class:`lib._http.FakeTransport` so the suite runs offline.

MISP auth uses the ``Authorization: <key>`` header (MISP does not use a Bearer prefix) with
JSON accept/content-type headers on every call.
"""
from __future__ import annotations

from typing import Any, Optional

from lib._http import HTTPTransport, UrllibTransport
from lib._secrets import resolve_secret

MISP_KEYRING_USERNAME = "misp_api_key"
MISP_ENV_VAR = "MISP_API_KEY"


class MISPError(Exception):
    """MISP client error (bad input, auth failure, or non-2xx response)."""


class MISPClient:
    """Client for a MISP instance's REST API."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        transport: Optional[HTTPTransport] = None,
        keyring_backend: Any = None,
    ):
        """
        Args:
            base_url: root URL of the MISP instance (e.g. ``https://misp.example.org``).
            api_key: explicit key (mainly tests); production leaves ``None`` -> keychain/env.
            transport: injectable HTTP transport; defaults to urllib transport.
            keyring_backend: injectable keyring (tests pass a fake).
        """
        if not base_url or not base_url.strip():
            raise MISPError("base_url is required")
        self._base = base_url.rstrip("/")
        kwargs = {"explicit": api_key}
        if keyring_backend is not None:
            kwargs["keyring_backend"] = keyring_backend
        self._api_key = resolve_secret(MISP_KEYRING_USERNAME, MISP_ENV_VAR, **kwargs)
        self._transport = transport or UrllibTransport()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # -- search ------------------------------------------------------------------------

    def search_attributes(
        self, value: Optional[str] = None, *, type_: Optional[str] = None, **filters: Any
    ) -> list[dict[str, Any]]:
        """Search MISP attributes. Returns the list of attribute dicts (possibly empty).

        ``value``/``type_`` are the common filters; arbitrary additional MISP
        ``restSearch`` filters may be passed as keyword args.
        """
        body: dict[str, Any] = {"returnFormat": "json"}
        if value is not None:
            body["value"] = value
        if type_ is not None:
            body["type"] = type_
        body.update(filters)

        resp = self._transport.request(
            "POST",
            f"{self._base}/attributes/restSearch",
            headers=self._headers(),
            json=body,
        )
        self._raise_for_status(resp, "attribute search")
        payload = resp.json() or {}
        # MISP nests results under response.Attribute.
        response = payload.get("response") or {}
        attributes = response.get("Attribute")
        if attributes is None:
            return []
        return attributes

    # -- create / sync -----------------------------------------------------------------

    def add_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Create a MISP event. ``event`` is the inner event body (info, attributes, …).

        Returns the created event dict as MISP reports it.
        """
        if not isinstance(event, dict):
            raise MISPError(f"event must be a dict, got {type(event).__name__}")
        # MISP expects the event wrapped under an "Event" key.
        body = event if "Event" in event else {"Event": event}
        resp = self._transport.request(
            "POST", f"{self._base}/events/add", headers=self._headers(), json=body
        )
        self._raise_for_status(resp, "event add")
        payload = resp.json() or {}
        return payload.get("Event", payload)

    def sync(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Push multiple events to MISP, one ``add_event`` call each.

        Returns a summary ``{"added": n, "events": [...], "errors": [...]}``. A single event
        failing does not abort the batch — its error is recorded so the caller sees partial
        progress instead of losing the whole sync.
        """
        if not isinstance(events, list):
            raise MISPError("events must be a list")
        added: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for idx, ev in enumerate(events):
            try:
                added.append(self.add_event(ev))
            except MISPError as e:
                errors.append({"index": idx, "error": str(e)})
        return {"added": len(added), "events": added, "errors": errors}

    # -- internals ---------------------------------------------------------------------

    @staticmethod
    def _raise_for_status(resp: Any, what: str) -> None:
        if resp.status < 200 or resp.status >= 300:
            raise MISPError(f"MISP {what} failed with HTTP {resp.status}")
