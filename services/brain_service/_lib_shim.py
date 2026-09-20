"""
Minimal local shims for the dependencies this service was archived against.

The archived ``coreline-brain-service`` imported modules that do NOT exist in the
active tree (they belonged to sibling services / net-new builds that were never
brought forward):

  * ``collectors.jira_incident``   — Jira metadata collector
  * ``brain.assemble_pir_input``   — PIR data-packet assembler
  * ``brain.generate_pir``         — Claude-backed PIR generator

To keep this service independently mergeable and *offline-testable* under ADR-0003,
we vendor minimal stand-ins here that satisfy exactly the interface the handlers use.

The important design point is the **AI provider boundary** (:class:`PIRProvider`):
per ADR-0002 §2 the LLM is a *replaceable, advisory* plugin behind a narrow interface.
PIR generation goes through this boundary, so tests inject :class:`FakePIRProvider`
and never touch a live LLM or the network. The real Claude implementation
(:class:`ClaudePIRProvider`) is import-guarded and only constructed when an API key
is present.

Secrets (LLM API keys, tokens) are read from the environment or the OS keychain
(``keyring``) through ``services.shared.secrets`` — never hardcoded.

# TODO(ADR-0003 integration): swap these shims for the real
#   collectors.jira_incident / brain.* modules once those land.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, runtime_checkable

import structlog

from services.shared.secrets import SecretLoadError, read_secret

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# AI provider boundary (ADR-0002 §2: replaceable, advisory LLM plugin)
# ---------------------------------------------------------------------------
@runtime_checkable
class PIRProvider(Protocol):
    """Narrow, replaceable AI-provider interface for PIR generation.

    Any implementation takes an assembled evidence data packet and returns a
    Markdown PIR. Output is *advisory* — the deterministic core decides what to
    do with it. Implementations must be interchangeable (Claude, OpenAI, local,
    or a fake for tests).
    """

    def generate(self, data_packet: str, *, max_tokens: int = 16000, temperature: float = 0.3) -> str:
        """Synthesize a PIR (Markdown) from an evidence data packet."""
        ...


class FakePIRProvider:
    """Deterministic, offline PIR provider for tests and no-LLM operation.

    Produces a structurally valid, PIR-shaped Markdown document from the data
    packet without any network call. Used by default whenever no real provider
    is configured, satisfying ADR-0002 §3 ("the platform must function with no
    AI at all").
    """

    model = "fake-offline"

    def generate(self, data_packet: str, *, max_tokens: int = 16000, temperature: float = 0.3) -> str:
        generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return (
            "# Post-Incident Review\n\n"
            f"_Generated {generated_at} by advisory provider `{self.model}` "
            "(no live LLM — offline stand-in)._\n\n"
            "## Summary\n\n"
            "This PIR was assembled deterministically from the evidence packet below.\n\n"
            "## Timeline\n\n"
            "See evidence packet.\n\n"
            "## Root Cause\n\n"
            "Pending analyst review.\n\n"
            "## Remediation\n\n"
            "Pending analyst review.\n\n"
            "## Evidence Packet\n\n"
            "```\n"
            f"{data_packet}\n"
            "```\n"
        )


class ClaudePIRProvider:
    """Real Claude-backed provider. Constructed only when an API key is present.

    The ``anthropic`` import is deferred so the module imports offline and tests
    never require the SDK.
    """

    def __init__(self, model: str, api_key: Optional[str] = None) -> None:
        api_key = api_key if api_key is not None else read_secret("ANTHROPIC_API_KEY")
        if not isinstance(api_key, str) or not api_key.strip():
            raise SecretLoadError("ClaudePIRProvider requires an Anthropic API key.")
        if not isinstance(model, str) or not model.strip():
            raise SecretLoadError("ClaudePIRProvider requires a model.")
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key)
        except Exception:
            # SDK exceptions can contain credentials. Do not retain their text
            # or exception chain in the public error.
            raise SecretLoadError("Anthropic provider initialization failed.") from None
        self.model = model

    def generate(self, data_packet: str, *, max_tokens: int = 16000, temperature: float = 0.3) -> str:  # pragma: no cover - needs network
        message = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": data_packet}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        )


def default_pir_provider(model: str) -> PIRProvider:
    """Select a provider: real Claude if a key is configured, else the fake.

    This keeps AI strictly optional and advisory — with no key (e.g. offline /
    tests) the deterministic :class:`FakePIRProvider` is used automatically.
    """
    key = read_secret("ANTHROPIC_API_KEY")
    if key:
        return ClaudePIRProvider(model=model, api_key=key)
    return FakePIRProvider()


# ---------------------------------------------------------------------------
# Jira collector (shim for collectors.jira_incident)
# ---------------------------------------------------------------------------
class JiraIncidentCollector:
    """Fetches incident metadata from Jira.

    Shim: with no Jira credentials configured (offline / tests) it returns a
    minimal metadata dict derived from the incident id so the orchestration flow
    can run end to end without a live Jira. The real collector will query Jira.
    """

    def __init__(self, server: str = "https://pantheon.atlassian.net") -> None:
        parsed = urlsplit(server)
        self.server = urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1],
                                 parsed.path, "", ""))

    def get_incident_metadata(self, incident_id: str) -> Dict[str, Any]:
        return {
            "incident_id": incident_id,
            "status": os.getenv("CORELINE_FAKE_JIRA_STATUS", "Resolved"),
            "summary": f"Incident {incident_id}",
            "server": self.server,
        }

    def format_for_pir(self, metadata: Dict[str, Any]) -> str:
        lines = ["=== JIRA_METADATA ==="]
        for key, value in metadata.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# PIR data assembler (shim for brain.assemble_pir_input)
# ---------------------------------------------------------------------------
class PIRDataAssembler:
    """Assembles the evidence data packet fed to the AI provider.

    Shim: combines Jira metadata (via the collector shim) with a placeholder for
    Slack logs. The real assembler pulls live Slack history.
    """

    def __init__(self, jira_server: str = "https://pantheon.atlassian.net") -> None:
        self._jira = JiraIncidentCollector(server=jira_server)

    def assemble(
        self,
        incident_id: str,
        slack_channel_id: Optional[str] = None,
        message_limit: int = 1000,
    ) -> str:
        metadata = self._jira.get_incident_metadata(incident_id)
        jira_formatted = self._jira.format_for_pir(metadata)
        slack_note = (
            f"[Slack channel {slack_channel_id}: up to {message_limit} messages]"
            if slack_channel_id
            else "[No Slack channel found - PIR generated from Jira data only]"
        )
        return (
            "### INPUT DATA PACKET\n\n"
            f"{jira_formatted}\n\n"
            "=== SLACK_RAW_LOGS ===\n"
            f"{slack_note}\n\n"
            "---\nEND OF DATA PACKET\n"
        )


class PIRGenerator:
    """Thin adapter that runs a :class:`PIRProvider` to produce a PIR.

    Shim for ``brain.generate_pir.PIRGenerator``. A provider may be injected
    (tests inject :class:`FakePIRProvider`); otherwise one is selected via
    :func:`default_pir_provider`.
    """

    def __init__(self, model: str = "claude-sonnet-4-5", provider: Optional[PIRProvider] = None) -> None:
        self.model = model
        self.provider = provider or default_pir_provider(model)

    def generate(self, data_packet: str, max_tokens: int = 16000, temperature: float = 0.3) -> str:
        return self.provider.generate(data_packet, max_tokens=max_tokens, temperature=temperature)
