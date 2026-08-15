"""Health/readiness route tests (offline via fakeredis + Slack stub)."""

from fastapi import FastAPI
from fastapi import HTTPException
from types import SimpleNamespace

from services.slack_orchestrator.routes import health
from services.slack_orchestrator.tests.conftest import StubSlackClient


def _request_for(app: FastAPI):
    return SimpleNamespace(app=app)


async def test_health_liveness():
    """/health is dependency-free and always reports healthy."""
    assert await health.health_check() == {
        "status": "healthy",
        "service": "slack-orchestrator",
    }


async def test_ready_all_dependencies_up(test_app):
    """/ready returns 200 when both Redis and Slack are reachable."""
    body = await health.readiness_check(_request_for(test_app))
    assert body["status"] == "ready"
    assert body["checks"] == {"redis": True, "slack": True}


async def test_ready_returns_503_when_slack_down(fake_redis):
    """/ready returns 503 when a dependency (Slack) is unhealthy."""
    app = FastAPI()
    app.include_router(health.router)
    app.state.redis = fake_redis
    app.state.slack = StubSlackClient(auth_ok=False)

    try:
        await health.readiness_check(_request_for(app))
    except HTTPException as exc:
        assert exc.status_code == 503
        detail = exc.detail
    else:  # pragma: no cover - defensive
        raise AssertionError("expected readiness_check to raise HTTPException")
    assert detail["status"] == "not ready"
    assert detail["checks"]["redis"] is True
    assert detail["checks"]["slack"] is False
