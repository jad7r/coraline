"""
Coreline autonomous investigation engine.

A self-contained library/engine (no always-on services) that runs a
TRIAGE → COLLECTING → CORRELATING → COMPLETED state machine over incident
telemetry and emits a cryptographically sealed investigation report.

Revived from ``archive/experimental/brain-autonomous`` per ADR-0003. Both the
signer (enclave adapter) and the AI provider are dependency-injected and
default to offline, network-free shims so the engine works standalone:

- ``enclave_adapter`` -> :class:`autonomous._enclave_shim.EnclaveShim`
  # TODO(ADR-0003 integration): replace shim with lib.enclave_adapter
- ``llm_client`` -> :class:`autonomous._ai_provider.OfflineHeuristicProvider`
  (ADR-0002 §2: AI is a replaceable, advisory provider)
"""

from .agent_orchestrator import (
    AutonomousIRBrain,
    ForensicFinding,
    InvestigationHypothesis,
    InvestigationStatus,
)
from .recommendation_engine import (
    ActionPriority,
    ContainmentAction,
    RecommendationEngine,
    RemediationRecommendation,
)
from ._ai_provider import AIProvider, OfflineHeuristicProvider
from ._enclave_shim import EnclaveShim

__all__ = [
    "AutonomousIRBrain",
    "InvestigationStatus",
    "ForensicFinding",
    "InvestigationHypothesis",
    "RecommendationEngine",
    "RemediationRecommendation",
    "ActionPriority",
    "ContainmentAction",
    "AIProvider",
    "OfflineHeuristicProvider",
    "EnclaveShim",
]
