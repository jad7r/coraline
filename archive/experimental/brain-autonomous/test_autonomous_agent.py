#!/usr/bin/env python3
"""
Verification suite for Coreline Autonomous IR Agent State Machine.

Tests the complete investigation lifecycle across all states:
- TRIAGE
- COLLECTING
- CORRELATING
- COMPLETED

Validates findings extraction, recommendation generation, and
cryptographic signing integration.
"""

import pytest
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from brain.agent_orchestrator import (
    AutonomousIRBrain,
    InvestigationStatus,
    ForensicFinding,
    InvestigationHypothesis
)
from brain.recommendation_engine import (
    RecommendationEngine,
    ActionPriority,
    ContainmentAction
)


class MockEnclaveAdapter:
    """
    Mock interface conforming to lib/enclave_adapter.py mechanics.

    Simulates cryptographic signing without requiring macOS Keychain.
    """

    def generate_and_store_keypair(self) -> str:
        """Mock keypair generation"""
        return "mock_enclave_key_id_xyz_123"

    def encrypt_evidence(self, data: bytes) -> bytes:
        """Mock encryption"""
        return b"encrypted:" + data

    def sign_manifest(self, manifest: str) -> str:
        """Mock signature generation"""
        import hashlib
        return hashlib.sha256(manifest.encode()).hexdigest()


@pytest.fixture
def mock_telemetry_ransomware():
    """Sample ransomware telemetry"""
    return json.dumps({
        "host_metadata": {
            "hostname": "PROD-DC-01",
            "os": "Windows Server 2022",
            "ip": "192.168.1.100"
        },
        "alerts": [
            {
                "engine": "EDR",
                "severity": "Critical",
                "description": "Ransomware behavior detected",
                "indicators": ["File encryption", "Ransom note"]
            },
            {
                "engine": "Sysmon",
                "event_id": 1,
                "image": "powershell.exe",
                "args": "-enc Z2V0LXByb2Nlc3M=",
                "parent": "winword.exe"
            }
        ]
    })


@pytest.fixture
def mock_telemetry_phishing():
    """Sample phishing telemetry"""
    return json.dumps({
        "host_metadata": {
            "hostname": "USER-LAPTOP-01",
            "os": "Windows 11",
            "user": "alice@example.com"
        },
        "alerts": [
            {
                "engine": "Email Security",
                "severity": "High",
                "description": "Phishing email detected",
                "subject": "Urgent: Password Reset Required"
            },
            {
                "engine": "Browser",
                "description": "Credential input on suspicious domain",
                "url": "http://evil-phishing-site.com/login"
            }
        ]
    })


@pytest.fixture
def mock_enclave():
    """Mock enclave adapter"""
    return MockEnclaveAdapter()


@pytest.mark.asyncio
async def test_autonomous_investigation_lifecycle_complete(mock_telemetry_ransomware, mock_enclave, tmp_path):
    """
    Test complete investigation lifecycle from triage to completion.

    Verifies:
    - State transitions (TRIAGE → COLLECTING → CORRELATING → COMPLETED)
    - Findings extraction
    - Recommendation generation
    - Cryptographic signing
    """
    # Arrange
    brain = AutonomousIRBrain(
        incident_id="INC-2026-ALPHA",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    # Act
    report = await brain.run_investigation(mock_telemetry_ransomware)

    # Assert - Basic report structure
    assert report["incident_id"] == "INC-2026-ALPHA"
    assert report["status"] == InvestigationStatus.COMPLETED.value
    assert "timestamp" in report

    # Assert - Hypothesis generated
    assert report["hypothesis"] is not None
    assert report["hypothesis"]["threat_category"] is not None
    assert report["hypothesis"]["confidence"] is not None

    # Assert - Findings extracted
    assert len(report["findings"]) > 0
    assert all("artifact_type" in f for f in report["findings"])
    assert all("severity" in f for f in report["findings"])

    # Assert - Recommendations generated
    assert len(report["recommendations"]) > 0
    assert all("priority" in r for r in report["recommendations"])
    assert all("action" in r for r in report["recommendations"])

    # Assert - Cryptographic seal
    assert "cryptographic_seal" in report
    assert report["cryptographic_seal"]["signed"] is True
    assert "key_id" in report["cryptographic_seal"]

    # Assert - Timeline captured
    assert len(report["timeline"]) >= 4  # At least 4 events
    assert report["timeline"][0]["event"] == "ENGINE_INITIALIZED"
    assert any(e["event"] == "TRIAGE_COMPLETED" for e in report["timeline"])
    assert any(e["event"] == "COLLECTION_COMPLETED" for e in report["timeline"])
    assert any(e["event"] == "CORRELATION_COMPLETED" for e in report["timeline"])

    # Assert - Summary statistics
    assert "summary" in report
    assert report["summary"]["total_findings"] > 0
    assert "investigation_duration_seconds" in report["summary"]


@pytest.mark.asyncio
async def test_triage_ransomware_hypothesis(mock_telemetry_ransomware, mock_enclave, tmp_path):
    """Test triage stage generates correct ransomware hypothesis"""
    brain = AutonomousIRBrain(
        incident_id="INC-TRIAGE-TEST",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    report = await brain.run_investigation(mock_telemetry_ransomware)

    assert "Ransomware" in report["hypothesis"]["threat_category"]
    assert report["hypothesis"]["confidence"] == "High"
    assert "scheduled_tasks" in report["hypothesis"]["required_artifacts"]
    assert "process_tree" in report["hypothesis"]["required_artifacts"]


@pytest.mark.asyncio
async def test_triage_phishing_hypothesis(mock_telemetry_phishing, mock_enclave, tmp_path):
    """Test triage stage generates correct phishing hypothesis"""
    brain = AutonomousIRBrain(
        incident_id="INC-PHISHING-TEST",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    report = await brain.run_investigation(mock_telemetry_phishing)

    assert "Phishing" in report["hypothesis"]["threat_category"]
    assert "email_headers" in report["hypothesis"]["required_artifacts"]
    assert "auth_logs" in report["hypothesis"]["required_artifacts"]


@pytest.mark.asyncio
async def test_artifact_collection_generates_findings(mock_telemetry_ransomware, mock_enclave, tmp_path):
    """Test artifact collection stage extracts forensic findings"""
    brain = AutonomousIRBrain(
        incident_id="INC-COLLECT-TEST",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    report = await brain.run_investigation(mock_telemetry_ransomware)

    # Verify findings extracted
    findings = report["findings"]
    assert len(findings) > 0

    # Verify finding structure
    for finding in findings:
        assert "artifact_type" in finding
        assert "evidence" in finding
        assert "severity" in finding
        assert finding["severity"] in ["Low", "Medium", "High", "Critical"]


@pytest.mark.asyncio
async def test_recommendations_prioritized_correctly(mock_telemetry_ransomware, mock_enclave, tmp_path):
    """Test recommendations are correctly prioritized"""
    brain = AutonomousIRBrain(
        incident_id="INC-RECO-TEST",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    report = await brain.run_investigation(mock_telemetry_ransomware)

    recommendations = report["recommendations"]
    assert len(recommendations) > 0

    # Verify priority ordering (IMMEDIATE first, then HIGH, etc.)
    priorities = [r["priority"] for r in recommendations]
    priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for i in range(len(priorities) - 1):
        current_rank = priority_order.get(priorities[i], 999)
        next_rank = priority_order.get(priorities[i + 1], 999)
        assert current_rank <= next_rank, "Recommendations not properly prioritized"


@pytest.mark.asyncio
async def test_critical_findings_require_signature(mock_telemetry_ransomware, mock_enclave, tmp_path):
    """Test critical findings generate actions requiring signature"""
    brain = AutonomousIRBrain(
        incident_id="INC-SIG-TEST",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    report = await brain.run_investigation(mock_telemetry_ransomware)

    # Find critical recommendations
    critical_recs = [r for r in report["recommendations"] if r["priority"] == "IMMEDIATE"]

    assert len(critical_recs) > 0, "No critical recommendations generated"

    for rec in critical_recs:
        assert rec["requires_enclave_signature"] is True, \
            "Critical recommendation does not require signature"


@pytest.mark.asyncio
async def test_investigation_without_enclave_fallback(mock_telemetry_ransomware, tmp_path):
    """Test investigation completes gracefully without enclave"""
    brain = AutonomousIRBrain(
        incident_id="INC-NO-ENCLAVE",
        base_path=tmp_path,
        enclave_adapter=None  # No enclave
    )

    report = await brain.run_investigation(mock_telemetry_ransomware)

    # Should complete successfully
    assert report["status"] == InvestigationStatus.COMPLETED.value

    # Should indicate fallback mode
    assert report["cryptographic_seal"]["signed"] is False
    assert report["cryptographic_seal"]["fallback_mode"] is True


@pytest.mark.asyncio
async def test_investigation_report_saved_to_workspace(mock_telemetry_ransomware, mock_enclave, tmp_path):
    """Test investigation report is saved to workspace"""
    brain = AutonomousIRBrain(
        incident_id="INC-SAVE-TEST",
        base_path=tmp_path,
        enclave_adapter=mock_enclave
    )

    await brain.run_investigation(mock_telemetry_ransomware)

    # Check report file exists
    report_path = tmp_path / "INC-SAVE-TEST" / "investigation_report_INC-SAVE-TEST.json"
    assert report_path.exists(), "Investigation report not saved"

    # Verify report contents
    with open(report_path) as f:
        saved_report = json.load(f)

    assert saved_report["incident_id"] == "INC-SAVE-TEST"
    assert saved_report["status"] == InvestigationStatus.COMPLETED.value


def test_recommendation_engine_maps_severity_to_priority():
    """Test recommendation engine maps severities correctly"""
    engine = RecommendationEngine()

    findings = [
        {"severity": "Critical", "artifact_type": "process", "evidence": "Malicious process"},
        {"severity": "High", "artifact_type": "persistence", "evidence": "Backdoor"},
        {"severity": "Medium", "artifact_type": "logs", "evidence": "Anomaly"},
        {"severity": "Low", "artifact_type": "config", "evidence": "Misconfiguration"}
    ]

    recommendations = engine.generate_recommendations(findings)

    assert len(recommendations) == 4

    # Verify priority mapping
    assert recommendations[0].priority == ActionPriority.IMMEDIATE  # Critical
    assert recommendations[1].priority == ActionPriority.HIGH       # High
    assert recommendations[2].priority == ActionPriority.MEDIUM     # Medium
    assert recommendations[3].priority == ActionPriority.LOW        # Low


def test_recommendation_engine_exports_runbook():
    """Test recommendation engine exports markdown runbook"""
    engine = RecommendationEngine()

    findings = [
        {
            "severity": "Critical",
            "artifact_type": "process_tree",
            "evidence": "Suspicious PowerShell execution",
            "mitre_tactic": "TA0002 - Execution"
        }
    ]

    engine.generate_recommendations(findings)
    runbook = engine.export_runbook()

    assert "# Incident Response Runbook" in runbook
    assert "## Containment Recommendations" in runbook
    assert "TERMINATE_PROCESS" in runbook
    assert "IMMEDIATE" in runbook


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
