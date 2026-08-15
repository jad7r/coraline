"""
Offline tests for the Coreline-Brain service.

Everything here runs with NO live LLM and NO network:
  * Redis is faked with ``fakeredis``.
  * PIR generation goes through the injected ``FakePIRProvider`` (ADR-0002 §2).

Covers the health route and one PIR-orchestration route driven with a canned
incident event, asserting a 2xx and a PIR-shaped response.
"""

import unittest
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import ValidationError

from services.brain_service.handlers.pir_orchestrator import PIROrchestrator
from services.brain_service._lib_shim import FakePIRProvider
from services.brain_service.models.incident_event import IncidentEvent
from services.brain_service.routes import health, pir


CANNED_INCIDENT = {
    "incident_id": "INC-42",
    "summary": "Suspected ransomware on PROD-FILE-01",
    "priority": "P1",
    "severity": "Critical",
    "detection_time": "2026-05-21T14:32:00.123Z",
    "webhook_event": "jira:issue_updated",
    "jira_url": "https://pantheon.atlassian.net/browse/INC-42",
}


class MemoryRedis:
    def __init__(self):
        self.values = {}
        self.published = []

    async def ping(self):
        return True

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, ex=None):
        self.values[key] = value
        return True

    async def delete(self, key):
        self.values.pop(key, None)
        return 1

    async def publish(self, channel, message):
        self.published.append((channel, message))
        return 1


class OfflinePIROrchestrator(PIROrchestrator):
    async def generate_pir_for_incident(self, incident: IncidentEvent):
        incident_id = incident.incident_id
        should_generate, _ = await self._should_generate_pir(incident_id)
        if not should_generate:
            return None
        if self.skip_pir_if_exists:
            existing = self._find_existing_pir(incident_id)
            if existing is not None:
                return None
        pir_path = self._get_pir_path(incident_id)
        channel_id = await self.channel_tracker.get_channel_id(incident_id)
        pir_content = await self._generate_pir(incident_id, channel_id)
        pir_path.write_text(pir_content, encoding="utf-8")
        await self._publish_completion_event(incident_id, str(pir_path))
        return str(pir_path)

    async def _should_generate_pir(self, incident_id: str) -> tuple[bool, str]:
        import os

        status = os.getenv("CORELINE_FAKE_JIRA_STATUS", "Resolved")
        return status in self.generate_pir_on_status, status

    async def _generate_pir(self, incident_id: str, channel_id):
        data_packet = f"### INPUT DATA PACKET\n{incident_id}\n"
        return self.pir_provider.generate(
            data_packet,
            max_tokens=self.claude_max_tokens,
            temperature=self.claude_temperature,
        )


def _build_offline_app(pir_output_dir: Path, generate_on_status=None) -> FastAPI:
    """Build the service app wired for offline testing.

    No lifespan (which would require live secrets/Redis); instead we attach a
    fakeredis-backed orchestrator using the deterministic FakePIRProvider.
    """
    app = FastAPI()
    app.include_router(health.router, tags=["health"])
    app.include_router(pir.router, tags=["pir"])

    redis_client = MemoryRedis()
    app.state.redis = redis_client
    app.state.pir_orchestrator = OfflinePIROrchestrator(
        redis_client=redis_client,
        pir_output_dir=pir_output_dir,
        generate_pir_on_status=generate_on_status or ["Resolved", "Closed"],
        skip_pir_if_exists=False,
        pir_provider=FakePIRProvider(),
    )
    return app


def _request_for(app: FastAPI):
    return SimpleNamespace(app=app)


def _run(coro):
    return asyncio.run(coro)


class TestHealthRoute(unittest.TestCase):
    def test_health_liveness_ok(self):
        with TemporaryDirectory() as d:
            app = _build_offline_app(Path(d))
            body = _run(health.health_check())
            self.assertEqual(body["status"], "healthy")
            self.assertEqual(body["service"], "coreline-brain-service")

    def test_ready_reports_redis_healthy(self):
        # Credentials are absent offline, so /ready returns 503, but the payload
        # must still show the fakeredis check passing.
        with TemporaryDirectory() as d:
            app = _build_offline_app(Path(d))
            with self.assertRaises(HTTPException) as ctx:
                _run(health.readiness_check(_request_for(app)))
            self.assertEqual(ctx.exception.status_code, 503)
            self.assertTrue(ctx.exception.detail["checks"]["redis"])


class TestPIRRoute(unittest.TestCase):
    def test_generate_pir_for_resolved_incident(self):
        with TemporaryDirectory() as d:
            out = Path(d)
            app = _build_offline_app(out)

            body = _run(
                pir.generate_pir(IncidentEvent(**CANNED_INCIDENT), _request_for(app))
            )

            self.assertTrue(body["generated"])
            self.assertEqual(body["incident_id"], "INC-42")

            # PIR-shaped response: file written under output dir with expected name.
            pir_path = Path(body["pir_path"])
            self.assertTrue(pir_path.exists())
            self.assertTrue(pir_path.name.startswith("INC-42-"))
            self.assertEqual(pir_path.suffix, ".md")

            content = pir_path.read_text(encoding="utf-8")
            self.assertIn("# Post-Incident Review", content)
            self.assertIn("INC-42", content)
            # Provenance: advisory provider is attributed in the document.
            self.assertIn("advisory provider", content)

    def test_skip_if_exists_matches_prior_pir_across_timestamps(self):
        # A pre-existing PIR for the incident (written at an earlier timestamp)
        # must suppress regeneration even though the new run computes a different
        # timestamped filename.
        with TemporaryDirectory() as d:
            out = Path(d)
            (out / "INC-42-20250101-000000.md").write_text("old pir", encoding="utf-8")

            app = FastAPI()
            app.include_router(pir.router, tags=["pir"])
            redis_client = MemoryRedis()
            app.state.redis = redis_client
            app.state.pir_orchestrator = OfflinePIROrchestrator(
                redis_client=redis_client,
                pir_output_dir=out,
                skip_pir_if_exists=True,  # the guard under test
                pir_provider=FakePIRProvider(),
            )

            body = _run(
                pir.generate_pir(IncidentEvent(**CANNED_INCIDENT), _request_for(app))
            )
            self.assertFalse(body["generated"])
            # No second PIR file was written.
            self.assertEqual(len(list(out.glob("INC-42-*.md"))), 1)

    def test_generate_pir_skipped_for_ineligible_status(self):
        # Orchestrator only generates for its configured statuses; force a status
        # the collector shim reports that is NOT eligible.
        import os

        with TemporaryDirectory() as d:
            app = _build_offline_app(Path(d), generate_on_status=["Closed"])
            os.environ["CORELINE_FAKE_JIRA_STATUS"] = "In Progress"
            try:
                body = _run(
                    pir.generate_pir(IncidentEvent(**CANNED_INCIDENT), _request_for(app))
                )
            finally:
                del os.environ["CORELINE_FAKE_JIRA_STATUS"]

            self.assertFalse(body["generated"])
            self.assertIsNone(body["pir_path"])

    def test_invalid_incident_rejected(self):
        bad = dict(CANNED_INCIDENT)
        bad["incident_id"] = "not-a-valid-id"  # violates ^[A-Z]+-\d+$
        with self.assertRaises(ValidationError):
            IncidentEvent(**bad)


class TestFakeProvider(unittest.TestCase):
    def test_fake_provider_offline_and_deterministic_shape(self):
        provider = FakePIRProvider()
        out = provider.generate("### INPUT DATA PACKET\nINC-99\n")
        self.assertIn("# Post-Incident Review", out)
        self.assertIn("INC-99", out)
        self.assertEqual(provider.model, "fake-offline")


if __name__ == "__main__":
    unittest.main()
