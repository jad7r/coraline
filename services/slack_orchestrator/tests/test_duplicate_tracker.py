"""DuplicateTracker tests backed by fakeredis (no live Redis)."""

import pytest

from services.slack_orchestrator.utils.duplicate_tracker import DuplicateTracker

pytestmark = pytest.mark.asyncio


async def test_unknown_incident_reports_absent(fake_redis):
    tracker = DuplicateTracker(redis_client=fake_redis)
    exists, channel_id = await tracker.channel_exists("INC-1")
    assert exists is False
    assert channel_id is None


async def test_mark_then_detect_duplicate(fake_redis):
    tracker = DuplicateTracker(redis_client=fake_redis, ttl_seconds=86400)
    await tracker.mark_channel_created("INC-42", "C0PROD42")

    exists, channel_id = await tracker.channel_exists("INC-42")
    assert exists is True
    assert channel_id == "C0PROD42"
    assert await tracker.get_channel_id("INC-42") == "C0PROD42"


async def test_clear_tracking_removes_key(fake_redis):
    tracker = DuplicateTracker(redis_client=fake_redis)
    await tracker.mark_channel_created("INC-9", "C0X")
    await tracker.clear_tracking("INC-9")

    exists, _ = await tracker.channel_exists("INC-9")
    assert exists is False


async def test_ttl_is_applied(fake_redis):
    tracker = DuplicateTracker(redis_client=fake_redis, ttl_seconds=123)
    await tracker.mark_channel_created("INC-7", "C0Y")
    ttl = await fake_redis.ttl("coreline:slack:channel:INC-7")
    assert 0 < ttl <= 123
