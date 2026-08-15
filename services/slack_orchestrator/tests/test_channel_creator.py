"""End-to-end-ish test of the core channel-creation flow.

Uses fakeredis for the duplicate tracker and a recording mock for the Slack
WebClient so we exercise SlackChannelCreator.create_incident_channel without a
live Slack workspace.
"""

import pytest

from services.slack_orchestrator.handlers.audit_logger import AuditLogger
from services.slack_orchestrator.handlers.slack_channel_creator import (
    SlackChannelCreator,
)
from services.slack_orchestrator.models.incident_event import IncidentEvent
from services.slack_orchestrator.utils.duplicate_tracker import DuplicateTracker

pytestmark = pytest.mark.asyncio


class MockSlackClient:
    """Records calls and returns canned Slack API responses."""

    def __init__(self):
        self.calls = []

    def conversations_create(self, name, is_private):
        self.calls.append(("conversations_create", name, is_private))
        return {"channel": {"id": "C0NEW", "name": name}}

    def conversations_setTopic(self, channel, topic):
        self.calls.append(("setTopic", channel, topic))
        return {"ok": True}

    def conversations_setPurpose(self, channel, purpose):
        self.calls.append(("setPurpose", channel, purpose))
        return {"ok": True}

    def conversations_invite(self, channel, users):
        self.calls.append(("invite", channel, users))
        return {"ok": True}

    def chat_postMessage(self, channel, blocks, text):
        self.calls.append(("postMessage", channel, text))
        return {"ok": True, "ts": "1700000000.000100"}

    def pins_add(self, channel, timestamp):
        self.calls.append(("pins_add", channel, timestamp))
        return {"ok": True}


def _incident() -> IncidentEvent:
    return IncidentEvent(
        incident_id="INC-42",
        summary="Suspected ransomware on PROD-FILE-01",
        priority="P1",
        severity="Critical",
        detection_time="2026-05-21T14:32:00.123Z",
        webhook_event="jira:issue_created",
        jira_url="https://pantheon.atlassian.net/browse/INC-42",
        incident_commander="Josh Dellinger",
        affected_systems=["PROD-FILE-01"],
    )


@pytest.fixture
def creator(fake_redis):
    return SlackChannelCreator(
        slack_client=MockSlackClient(),
        duplicate_tracker=DuplicateTracker(redis_client=fake_redis, ttl_seconds=3600),
        audit_logger=AuditLogger(service_name="slack-orchestrator", environment="dev"),
        response_team_user_ids=["U01234567"],
    )


async def test_creates_channel_and_records_it(creator, fake_redis):
    channel_id = await creator.create_incident_channel(_incident())

    assert channel_id == "C0NEW"
    call_names = [c[0] for c in creator.slack.calls]
    assert "conversations_create" in call_names
    assert "invite" in call_names
    assert "postMessage" in call_names
    # Duplicate tracker persisted the mapping.
    assert await fake_redis.get("coreline:slack:channel:INC-42") == "C0NEW"


async def test_duplicate_incident_skips_creation(creator):
    first = await creator.create_incident_channel(_incident())
    creator.slack.calls.clear()

    second = await creator.create_incident_channel(_incident())

    assert second == first
    # No new Slack channel created the second time.
    assert not any(c[0] == "conversations_create" for c in creator.slack.calls)


class _RateLimitedResponse:
    """Stand-in for slack_sdk's response carried on SlackApiError."""

    def __init__(self, error, headers=None):
        self._error = error
        self.headers = headers or {}

    def get(self, key, default=None):
        return {"error": self._error}.get(key, default)


async def test_rate_limit_backoff_uses_async_sleep(monkeypatch, fake_redis):
    """A rate_limited error must retry using a non-blocking async sleep."""
    from slack_sdk.errors import SlackApiError

    from services.slack_orchestrator.handlers import slack_channel_creator as scc

    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(scc.asyncio, "sleep", fake_sleep)

    class FlakySlack(MockSlackClient):
        def __init__(self):
            super().__init__()
            self._calls = 0

        def conversations_create(self, name, is_private):
            self._calls += 1
            if self._calls == 1:
                raise SlackApiError(
                    "rate limited", _RateLimitedResponse("rate_limited")
                )
            return super().conversations_create(name, is_private)

    creator = SlackChannelCreator(
        slack_client=FlakySlack(),
        duplicate_tracker=DuplicateTracker(redis_client=fake_redis, ttl_seconds=60),
        audit_logger=AuditLogger(service_name="slack-orchestrator", environment="dev"),
        response_team_user_ids=[],
    )

    channel_id = await creator.create_incident_channel(_incident())
    assert channel_id == "C0NEW"
    # Backoff happened via async sleep, and first default backoff is 2s (not 1s).
    assert sleeps == [2]


async def test_invalid_incident_id_rejected_by_model():
    with pytest.raises(Exception):
        IncidentEvent(
            incident_id="lowercase-bad",
            summary="x",
            priority="P1",
            severity="Low",
            detection_time="2026-05-21T14:32:00.123Z",
            webhook_event="jira:issue_created",
            jira_url="https://example/INC",
        )
