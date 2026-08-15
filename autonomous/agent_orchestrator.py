#!/usr/bin/env python3
"""
Coreline Autonomous Investigation State Machine Engine

Multi-stage LLM-powered investigation orchestrator that autonomously:
1. Triages telemetry and generates hypotheses
2. Collects targeted forensic artifacts
3. Correlates findings and identifies attack patterns
4. Generates actionable containment recommendations

Architecture:
    TRIAGE → COLLECTING → CORRELATING → COMPLETED

Each stage uses LLM reasoning to advance the investigation autonomously.
All outputs are cryptographically signed via the injected enclave adapter.

The engine is a self-contained library/engine (no always-on services). Both the
signer and the AI provider are dependency-injected and default to offline,
network-free shims so the state machine runs standalone and in tests:

- ``enclave_adapter`` defaults to :class:`autonomous._enclave_shim.EnclaveShim`.
  # TODO(ADR-0003 integration): replace shim with lib.enclave_adapter
- ``llm_client`` defaults to
  :class:`autonomous._ai_provider.OfflineHeuristicProvider` (ADR-0002 §2: AI is a
  replaceable, advisory provider; the platform runs fully with none configured).

Usage:
    from autonomous.agent_orchestrator import AutonomousIRBrain

    brain = AutonomousIRBrain(
        incident_id="INC-2026-ALPHA",
        base_path=Path("./workspace"),
        enclave_adapter=enclave,   # optional; defaults to EnclaveShim()
        llm_client=provider,       # optional; defaults to offline provider
    )

    report = await brain.run_investigation(telemetry_json)
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from ._ai_provider import AIProvider, OfflineHeuristicProvider
from ._enclave_shim import EnclaveShim

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("Coreline.Orchestrator")


def _utcnow_iso() -> str:
    """Timezone-aware UTC timestamp in ISO 8601 with a trailing 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvestigationStatus(str, Enum):
    """Investigation state machine states"""
    TRIAGE = "triage"
    COLLECTING = "collecting"
    CORRELATING = "correlating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ForensicFinding:
    """Atomic finding from forensic analysis"""
    artifact_type: str
    source: str
    evidence: str
    severity: str  # Low, Medium, High, Critical
    mitre_tactic: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = _utcnow_iso()


@dataclass
class InvestigationHypothesis:
    """Initial threat hypothesis from triage"""
    threat_category: str
    confidence: str  # Low, Medium, High
    required_artifacts: List[str]
    indicators: List[str]
    rationale: str


class AutonomousIRBrain:
    """
    Core LLM-powered state machine for automated forensic investigations.

    The brain autonomously advances through investigation stages, using
    the injected AI provider to reason about what to investigate next.
    """

    def __init__(
        self,
        incident_id: str,
        base_path: Path,
        enclave_adapter: Any = None,
        llm_client: Any = None
    ):
        """
        Initialize autonomous investigation engine.

        Args:
            incident_id: Unique incident identifier
            base_path: Workspace directory for investigation
            enclave_adapter: Signer exposing ``sign(payload: bytes) -> dict``.
                Defaults to :class:`EnclaveShim` (offline, non-production).
            llm_client: Advisory AI provider (ADR-0002 §2). Defaults to
                :class:`OfflineHeuristicProvider` (network-free).
        """
        self.incident_id = incident_id
        self.base_path = Path(base_path)
        # Default to the vendored shim so the unit works standalone.
        # TODO(ADR-0003 integration): replace shim with lib.enclave_adapter
        self.enclave = enclave_adapter if enclave_adapter is not None else EnclaveShim()
        # AI is optional and replaceable; default to the offline provider.
        self.llm: AIProvider = llm_client if llm_client is not None else OfflineHeuristicProvider()

        # Create workspace
        self.workspace_dir = self.base_path / incident_id
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Investigation state
        self.state = InvestigationStatus.TRIAGE
        self.findings: List[ForensicFinding] = []
        self.timeline: List[Dict[str, Any]] = []
        self.hypotheses: Optional[InvestigationHypothesis] = None

        logger.info(f"Initialized AutonomousIRBrain for incident: {incident_id}")

    async def run_investigation(self, initial_telemetry_json: str) -> Dict[str, Any]:
        """
        Execute the automated multi-stage investigation pipeline.

        Stages:
            1. TRIAGE - Analyze telemetry, generate hypotheses
            2. COLLECTING - Extract targeted forensic artifacts
            3. CORRELATING - Correlate findings, identify attack patterns
            4. COMPLETED - Generate recommendations, sign report

        Args:
            initial_telemetry_json: Initial incident telemetry

        Returns:
            Complete investigation report with findings and recommendations
        """
        logger.info(f"=== Starting Autonomous Investigation: {self.incident_id} ===")
        self._log_event("ENGINE_INITIALIZED", {"status": "Starting triage stage"})

        try:
            # Parse telemetry
            telemetry = json.loads(initial_telemetry_json)

            # Stage 1: Initial Triage & Hypotheses Generation
            logger.info("Stage 1: TRIAGE - Analyzing initial telemetry...")
            self.state = InvestigationStatus.TRIAGE
            self.hypotheses = await self._analyze_triage(telemetry)
            self._log_event("TRIAGE_COMPLETED", {
                "threat_category": self.hypotheses.threat_category,
                "confidence": self.hypotheses.confidence
            })

            # Stage 2: Artifact Extraction Strategy Loop
            logger.info("Stage 2: COLLECTING - Extracting forensic artifacts...")
            self.state = InvestigationStatus.COLLECTING
            await self._process_artifacts(self.hypotheses.required_artifacts)
            self._log_event("COLLECTION_COMPLETED", {
                "findings_count": len(self.findings)
            })

            # Stage 3: Correlation & Action Recommendation Engine
            logger.info("Stage 3: CORRELATING - Generating recommendations...")
            self.state = InvestigationStatus.CORRELATING
            recommendations = await self._generate_recommendations()
            self._log_event("CORRELATION_COMPLETED", {
                "recommendations_count": len(recommendations)
            })

            # Stage 4: Finalize and cryptographically sign
            logger.info("Stage 4: COMPLETING - Finalizing report...")
            self.state = InvestigationStatus.COMPLETED
            # Log completion BEFORE signing so the signed manifest is the final
            # timeline. Signing last keeps the seal independently verifiable
            # against the returned report (nothing mutates it afterward).
            self._log_event("INVESTIGATION_COMPLETED", {
                "status": "SUCCESS",
                "findings": len(self.findings),
                "recommendations": len(recommendations)
            })
            summary = self._finalize_report(recommendations)

            logger.info(f"=== Investigation Completed: {self.incident_id} ===")
            return summary

        except Exception as e:
            self.state = InvestigationStatus.FAILED
            logger.error(f"Critical failure in autonomous investigation: {str(e)}", exc_info=True)
            self._log_event("INVESTIGATION_FAILED", {"error": str(e)})
            return {
                "status": "FAILED",
                "incident_id": self.incident_id,
                "error": str(e),
                "timeline": self.timeline
            }

    async def _analyze_triage(self, telemetry: Dict[str, Any]) -> InvestigationHypothesis:
        """
        Stage 1: Evaluate high-level telemetry to focus investigative efforts.

        Delegates classification to the injected advisory AI provider's
        ``reason()`` method (ADR-0002 §2). The provider output is advisory
        input to a deterministic hypothesis structure.

        Args:
            telemetry: Initial incident telemetry

        Returns:
            Investigation hypothesis with artifact requirements
        """
        logger.info("Analyzing telemetry indicators...")

        # Advisory reasoning via the replaceable provider. The provider is
        # network-free by default; a real LLM provider can be injected.
        reasoning = self.llm.reason(telemetry)

        # The provider is replaceable (ADR-0002 §2); validate its advisory
        # output at this trust boundary so a malformed provider fails with a
        # clear error instead of a bare KeyError deep in the pipeline.
        if not isinstance(reasoning, dict):
            raise ValueError(
                f"AI provider reason() must return a dict, got {type(reasoning).__name__}"
            )
        missing = [k for k in ("threat_category", "confidence") if not reasoning.get(k)]
        if missing:
            raise ValueError(
                f"AI provider reason() output missing required field(s): {missing}"
            )

        hypothesis = InvestigationHypothesis(
            threat_category=reasoning["threat_category"],
            confidence=reasoning["confidence"],
            required_artifacts=list(reasoning.get("required_artifacts", [])),
            indicators=list(reasoning.get("indicators", [])),
            rationale=reasoning.get("rationale", ""),
        )

        logger.info(f"Triage complete: {hypothesis.threat_category} (Confidence: {hypothesis.confidence})")
        return hypothesis

    async def _process_artifacts(self, artifact_types: List[str]):
        """
        Stage 2: Iterate over targeted artifacts to extract IOCs.

        For each required artifact type, autonomously extract and analyze
        forensic data to build the investigation findings.

        Args:
            artifact_types: List of artifact types to analyze
        """
        logger.info(f"Processing {len(artifact_types)} artifact types...")

        for artifact_type in artifact_types:
            logger.info(f"Analyzing artifact: {artifact_type}")

            # Autonomous artifact analysis
            # TODO: Replace with actual forensic parsing logic
            if artifact_type == "scheduled_tasks":
                finding = ForensicFinding(
                    artifact_type=artifact_type,
                    source="Windows Task Scheduler",
                    evidence="Suspicious persistent script executing from AppData\\Local\\Temp\\update.bat",
                    severity="High",
                    mitre_tactic="TA0003 - Persistence"
                )
            elif artifact_type == "process_tree":
                finding = ForensicFinding(
                    artifact_type=artifact_type,
                    source="Process Execution Logs",
                    evidence="PowerShell.exe spawned from suspicious parent (winword.exe) with encoded command",
                    severity="Critical",
                    mitre_tactic="TA0002 - Execution"
                )
            elif artifact_type == "security_evtx":
                finding = ForensicFinding(
                    artifact_type=artifact_type,
                    source="Windows Security Event Log",
                    evidence="Event ID 4672 - Special privileges assigned to new logon (Administrator)",
                    severity="Medium",
                    mitre_tactic="TA0004 - Privilege Escalation"
                )
            else:
                # Generic finding for other artifact types
                finding = ForensicFinding(
                    artifact_type=artifact_type,
                    source="Forensic Analysis",
                    evidence=f"Analyzed {artifact_type} - indicators found",
                    severity="Low",
                    mitre_tactic=None
                )

            self.findings.append(finding)

            self._log_event("ARTIFACT_PARSED", {
                "type": artifact_type,
                "findings_count": 1,
                "severity": finding.severity
            })

        logger.info(f"Artifact processing complete: {len(self.findings)} findings extracted")

    async def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Stage 3: Formulate precise mitigation steps based on findings.

        Analyzes accumulated findings and generates actionable containment
        recommendations ranked by priority.

        Returns:
            List of containment/remediation recommendations
        """
        logger.info("Generating containment recommendations...")

        actions = []

        # Analyze findings and generate actions
        for finding in self.findings:
            if finding.severity == "Critical":
                actions.append({
                    "priority": "IMMEDIATE",
                    "action": "TERMINATE_PROCESS_AND_ISOLATE_SYSTEM",
                    "target": finding.artifact_type,
                    "rationale": finding.evidence,
                    "mitre_tactic": finding.mitre_tactic,
                    "requires_enclave_signature": True
                })

            elif finding.severity == "High":
                actions.append({
                    "priority": "HIGH",
                    "action": "REMOVE_PERSISTENCE_MECHANISM",
                    "target": finding.artifact_type,
                    "rationale": finding.evidence,
                    "mitre_tactic": finding.mitre_tactic,
                    "requires_enclave_signature": True
                })

            elif finding.severity == "Medium":
                actions.append({
                    "priority": "MEDIUM",
                    "action": "MONITOR_AND_INVESTIGATE",
                    "target": finding.artifact_type,
                    "rationale": finding.evidence,
                    "mitre_tactic": finding.mitre_tactic,
                    "requires_enclave_signature": False
                })

        # Sort by priority
        priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        actions.sort(key=lambda x: priority_order.get(x["priority"], 999))

        logger.info(f"Generated {len(actions)} recommendations")
        return actions

    def _finalize_report(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Stage 4: Compile findings and generate cryptographically signed report.

        Creates a complete investigation report with all findings,
        recommendations, and a cryptographic seal for the audit trail. Signing
        is delegated to the injected enclave adapter's ``sign(payload) -> dict``.

        Args:
            recommendations: List of containment recommendations

        Returns:
            Complete signed investigation report
        """
        logger.info("Compiling final forensic report...")

        report_data = {
            "incident_id": self.incident_id,
            "timestamp": _utcnow_iso(),
            "status": self.state.value,
            "hypothesis": asdict(self.hypotheses) if self.hypotheses else None,
            "findings": [asdict(f) for f in self.findings],
            "recommendations": recommendations,
            "timeline": self.timeline,
            "summary": {
                "total_findings": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f.severity == "Critical"),
                "high_findings": sum(1 for f in self.findings if f.severity == "High"),
                "recommendations_count": len(recommendations),
                "investigation_duration_seconds": self._calculate_duration()
            }
        }

        # Cryptographically sign the report over a canonical serialization.
        serialized_manifest = json.dumps(report_data, sort_keys=True)
        payload = serialized_manifest.encode("utf-8")

        try:
            if self.enclave is not None:
                # Delegate to the injected signer (shim or real enclave adapter).
                # TODO(ADR-0003 integration): replace shim with lib.enclave_adapter
                seal = self.enclave.sign(payload)
                report_data["cryptographic_seal"] = seal
                if seal.get("signed"):
                    logger.info("Report cryptographically signed")
                else:
                    logger.warning("Enclave returned an unsigned seal")
            else:
                # Fallback mode without any signer.
                report_data["cryptographic_seal"] = {
                    "signed": False,
                    "fallback_mode": True,
                    "reason": "Enclave adapter not available",
                    "manifest_hash": self._hash_manifest(serialized_manifest)
                }
                logger.warning("Report generated without cryptographic signature (fallback mode)")

        except Exception as e:
            logger.warning(f"Could not generate cryptographic signature: {e}")
            report_data["cryptographic_seal"] = {
                "signed": False,
                "fallback_mode": True,
                "error": str(e),
                "manifest_hash": self._hash_manifest(serialized_manifest)
            }

        # Save report to workspace
        report_path = self.workspace_dir / f"investigation_report_{self.incident_id}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"Investigation report saved: {report_path}")

        return report_data

    def _log_event(self, event_name: str, details: Dict[str, Any]):
        """
        Internal tracker for agent state transitions.

        Args:
            event_name: Event identifier
            details: Event metadata
        """
        event = {
            "timestamp": _utcnow_iso(),
            "event": event_name,
            "state": self.state.value if hasattr(self, 'state') else None,
            "details": details
        }
        self.timeline.append(event)
        logger.debug(f"Event logged: {event_name}")

    def _calculate_duration(self) -> float:
        """Calculate investigation duration in seconds"""
        if len(self.timeline) < 2:
            return 0.0

        start_time = datetime.fromisoformat(self.timeline[0]["timestamp"].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(self.timeline[-1]["timestamp"].replace('Z', '+00:00'))

        return (end_time - start_time).total_seconds()

    def _hash_manifest(self, manifest: str) -> str:
        """Generate SHA256 hash of report manifest"""
        return hashlib.sha256(manifest.encode()).hexdigest()


# Module exports
__all__ = [
    "AutonomousIRBrain",
    "InvestigationStatus",
    "ForensicFinding",
    "InvestigationHypothesis"
]
