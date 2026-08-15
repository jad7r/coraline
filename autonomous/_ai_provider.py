#!/usr/bin/env python3
"""
AI provider contract + offline fake for the autonomous investigation engine.

Per ADR-0002 §2, the LLM is a *replaceable, advisory* provider exposed behind a
narrow interface: ``reason()``, ``plan()``, ``summarize()``, ``recommend()``.
The autonomous engine must run fully with **no** provider configured and must
never require a live LLM or network access in tests.

This module defines a lightweight structural contract (:class:`AIProvider`) and
a deterministic offline implementation (:class:`OfflineHeuristicProvider`) that
the state machine falls back to when no real provider is injected. Real
providers (``ai/providers/claude`` etc.) are wired in during Phase 3.
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable


@runtime_checkable
class AIProvider(Protocol):
    """
    Narrow, advisory LLM interface (ADR-0002 §2).

    Every method takes a JSON-serializable context and returns a
    JSON-serializable result. Providers are advisory only: their output becomes
    an action or state change only when a deterministic policy accepts it.
    """

    def reason(self, context: Dict[str, Any]) -> Dict[str, Any]: ...

    def plan(self, context: Dict[str, Any]) -> Dict[str, Any]: ...

    def summarize(self, context: Dict[str, Any]) -> str: ...

    def recommend(self, context: Dict[str, Any]) -> List[Dict[str, Any]]: ...


class OfflineHeuristicProvider:
    """
    Deterministic, network-free provider used as the default.

    Implements the :class:`AIProvider` contract with simple keyword heuristics
    so the state machine can advance offline with canned telemetry. It carries
    no learned model and makes no external calls.
    """

    name = "offline-heuristic"
    model = "rules-v1"

    def reason(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a threat category from raw telemetry alerts."""
        alerts = context.get("alerts", [])
        blob = " ".join(str(a).lower() for a in alerts)

        if "ransomware" in blob:
            return {
                "threat_category": "Ransomware / Living-off-the-Land",
                "confidence": "High",
                "required_artifacts": [
                    "scheduled_tasks",
                    "process_tree",
                    "security_evtx",
                    "file_system_timeline",
                ],
                "indicators": [
                    "Suspicious PowerShell execution",
                    "Potential credential access",
                    "File encryption patterns",
                ],
                "rationale": (
                    "Multiple indicators suggest ransomware deployment with "
                    "credential theft"
                ),
            }
        if "phishing" in blob:
            return {
                "threat_category": "Phishing / Credential Compromise",
                "confidence": "High",
                "required_artifacts": [
                    "email_headers",
                    "browser_history",
                    "auth_logs",
                    "network_connections",
                ],
                "indicators": [
                    "Suspicious email received",
                    "Unusual authentication attempts",
                    "Potential credential exposure",
                ],
                "rationale": "Phishing indicators with potential credential compromise",
            }
        return {
            "threat_category": "Unknown / Requires Investigation",
            "confidence": "Medium",
            "required_artifacts": [
                "system_logs",
                "process_tree",
                "network_connections",
            ],
            "indicators": ["Anomalous activity detected"],
            "rationale": "Initial indicators require further investigation",
        }

    def plan(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Return the artifact collection plan derived from a hypothesis."""
        return {"required_artifacts": context.get("required_artifacts", [])}

    def summarize(self, context: Dict[str, Any]) -> str:
        """Produce a one-line summary of the investigation state."""
        return (
            f"{context.get('threat_category', 'Unknown')} — "
            f"{context.get('total_findings', 0)} finding(s), "
            f"{context.get('recommendations_count', 0)} recommendation(s)"
        )

    def recommend(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Advisory recommendations are produced deterministically upstream."""
        return context.get("recommendations", [])


__all__ = ["AIProvider", "OfflineHeuristicProvider"]
