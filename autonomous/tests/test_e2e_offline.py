#!/usr/bin/env python3
"""
Offline end-to-end test for the autonomous investigation engine.

Instantiates :class:`AutonomousIRBrain` with a fake AI provider, the vendored
enclave shim, and a canned telemetry JSON fixture; runs the full investigation;
and asserts it reaches COMPLETED and produces a signed report dict.

No network and no live LLM are used.
"""

import json
from pathlib import Path

import pytest

from autonomous import (
    AutonomousIRBrain,
    EnclaveShim,
    InvestigationStatus,
    OfflineHeuristicProvider,
)

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "telemetry_ransomware.json"


class FakeAIProvider(OfflineHeuristicProvider):
    """A fake, network-free provider that records that it was consulted."""

    def __init__(self) -> None:
        self.reason_calls = 0

    def reason(self, context):  # type: ignore[override]
        self.reason_calls += 1
        return super().reason(context)


@pytest.mark.asyncio
async def test_end_to_end_offline_signed_report(tmp_path):
    # Arrange: canned telemetry fixture + fake provider + enclave shim.
    telemetry_json = FIXTURE.read_text()
    provider = FakeAIProvider()
    enclave = EnclaveShim()

    brain = AutonomousIRBrain(
        incident_id="INC-E2E-OFFLINE",
        base_path=tmp_path,
        enclave_adapter=enclave,
        llm_client=provider,
    )

    # Act
    report = await brain.run_investigation(telemetry_json)

    # Assert: state machine reached COMPLETED.
    assert brain.state == InvestigationStatus.COMPLETED
    assert report["status"] == InvestigationStatus.COMPLETED.value

    # The fake AI provider was actually consulted during triage.
    assert provider.reason_calls == 1

    # Ransomware hypothesis drove artifact collection into findings.
    assert "Ransomware" in report["hypothesis"]["threat_category"]
    assert report["summary"]["total_findings"] > 0
    assert report["summary"]["critical_findings"] > 0

    # Recommendations were produced and IMMEDIATE ones require a signature.
    assert len(report["recommendations"]) > 0
    immediate = [r for r in report["recommendations"] if r["priority"] == "IMMEDIATE"]
    assert immediate and all(r["requires_enclave_signature"] for r in immediate)

    # Signed report dict: seal verifies against the canonical manifest.
    seal = report["cryptographic_seal"]
    assert seal["signed"] is True

    manifest = {k: v for k, v in report.items() if k != "cryptographic_seal"}
    payload = json.dumps(manifest, sort_keys=True).encode("utf-8")
    assert enclave.verify(payload, seal) is True

    # Report was persisted to the workspace as a JSON dict.
    saved = tmp_path / "INC-E2E-OFFLINE" / "investigation_report_INC-E2E-OFFLINE.json"
    assert saved.exists()
    on_disk = json.loads(saved.read_text())
    assert on_disk["status"] == InvestigationStatus.COMPLETED.value
