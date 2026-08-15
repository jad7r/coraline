#!/usr/bin/env python3
"""
Channel Creation Duplicate Prevention

Tracks created Slack channels in Redis to prevent duplicate channel creation
for the same incident (e.g., if Jira sends multiple webhook events).

Redis Key Pattern:
    coreline:slack:channel:{incident_id} → {channel_id}

TTL: 90 days (outlives typical incident lifecycle)

Example:
    Key: coreline:slack:channel:INC-42
    Value: C01234567  (Slack channel ID)
    TTL: 7776000 seconds
"""

import redis.asyncio as redis
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


class DuplicateTracker:
    """Tracks Slack channels to prevent duplicate creation."""

    KEY_PREFIX = "coreline:slack:channel:"
    TTL_SECONDS = 7776000  # 90 days

    def __init__(self, redis_client: redis.Redis, ttl_seconds: int = TTL_SECONDS):
        """
        Initialize duplicate tracker.

        Args:
            redis_client: Async Redis client
            ttl_seconds: TTL for tracking keys (default: 90 days)
        """
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds

    async def channel_exists(self, incident_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if channel already created for incident.

        Args:
            incident_id: Jira incident ID (e.g., INC-42)

        Returns:
            Tuple of (exists: bool, channel_id: str | None)

        Example:
            exists, channel_id = await tracker.channel_exists("INC-42")
            if exists:
                print(f"Channel {channel_id} already exists")
        """
        key = f"{self.KEY_PREFIX}{incident_id}"

        try:
            channel_id = await self.redis.get(key)

            if channel_id:
                logger.debug(
                    "duplicate_tracker.channel_exists",
                    incident_id=incident_id,
                    channel_id=channel_id,
                    msg="Channel already exists for incident"
                )
                return (True, channel_id.decode('utf-8') if isinstance(channel_id, bytes) else channel_id)

            return (False, None)

        except redis.RedisError as e:
            # Non-fatal - log warning and return False (allow channel creation)
            logger.warning(
                "duplicate_tracker.redis_error",
                incident_id=incident_id,
                error=str(e),
                msg="Redis error checking duplicate (allowing channel creation)"
            )
            return (False, None)

    async def mark_channel_created(self, incident_id: str, channel_id: str):
        """
        Mark channel as created for incident.

        Args:
            incident_id: Jira incident ID (e.g., INC-42)
            channel_id: Slack channel ID (e.g., C01234567)

        Raises:
            No exceptions raised - logs errors but does not fail
        """
        key = f"{self.KEY_PREFIX}{incident_id}"

        try:
            await self.redis.set(key, channel_id, ex=self.ttl_seconds)

            logger.info(
                "duplicate_tracker.marked_created",
                incident_id=incident_id,
                channel_id=channel_id,
                ttl_days=self.ttl_seconds // 86400,
                msg="Marked channel as created in Redis"
            )

        except redis.RedisError as e:
            # Non-fatal - log error but don't fail channel creation
            logger.error(
                "duplicate_tracker.mark_failed",
                incident_id=incident_id,
                channel_id=channel_id,
                error=str(e),
                msg="Failed to mark channel as created (non-fatal)"
            )

    async def get_channel_id(self, incident_id: str) -> Optional[str]:
        """
        Get Slack channel ID for incident.

        Args:
            incident_id: Jira incident ID

        Returns:
            Slack channel ID if exists, None otherwise
        """
        exists, channel_id = await self.channel_exists(incident_id)
        return channel_id if exists else None

    async def clear_tracking(self, incident_id: str):
        """
        Clear tracking for incident (for testing/cleanup).

        Args:
            incident_id: Jira incident ID
        """
        key = f"{self.KEY_PREFIX}{incident_id}"
        try:
            await self.redis.delete(key)
            logger.debug(
                "duplicate_tracker.cleared",
                incident_id=incident_id,
                msg="Cleared tracking for incident"
            )
        except redis.RedisError as e:
            logger.warning(
                "duplicate_tracker.clear_failed",
                incident_id=incident_id,
                error=str(e)
            )
