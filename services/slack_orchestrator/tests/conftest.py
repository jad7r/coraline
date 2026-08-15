"""Shared fixtures for slack_orchestrator tests.

These tests must run fully offline: no live Redis, no live Slack. Redis is
replaced with ``fakeredis`` and Slack with a lightweight stub.
"""

import fakeredis.aioredis
import pytest
from fastapi import FastAPI

from services.slack_orchestrator.routes import health


class StubSlackResponse(dict):
    """Mimics slack_sdk's SlackResponse (dict-like with .get)."""


class StubSlackClient:
    """Minimal stand-in for slack_sdk.WebClient used by the readiness probe."""

    def __init__(self, auth_ok: bool = True):
        self._auth_ok = auth_ok

    def auth_test(self):
        return StubSlackResponse(
            ok=self._auth_ok,
            user_id="U_BOT",
            team_id="T_TEST",
            team="test-workspace",
        )


@pytest.fixture
def fake_redis():
    """Async fakeredis client (drop-in for redis.asyncio.Redis)."""
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def test_app(fake_redis):
    """A FastAPI app with the health router mounted and stubbed app.state.

    The production lifespan (which loads secrets and pings live Redis/Slack) is
    intentionally not used; we inject fakes directly so the routes can be
    exercised offline.
    """
    app = FastAPI()
    app.include_router(health.router, tags=["health"])
    app.state.redis = fake_redis
    app.state.slack = StubSlackClient(auth_ok=True)
    return app
