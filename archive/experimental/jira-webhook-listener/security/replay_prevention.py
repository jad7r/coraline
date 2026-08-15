#!/usr/bin/env python3
"""
Replay Attack Prevention for Jira Webhooks

Implements Security Guardrail G2.2: Replay Attack Prevention
Uses two-layer protection:
1. Timestamp freshness validation (max 5 minutes old)
2. Redis-based webhook ID tracking (24 hour TTL)

Security Features:
- Rejects webhooks older than configurable threshold (default: 5 minutes)
- Tracks processed webhook IDs in Redis to prevent duplicates
- Fail-open if Redis unavailable (availability > strict replay prevention)
- Comprehensive audit logging for security monitoring
"""

import redis.asyncio as redis
import structlog
from datetime import datetime, timezone
from typing import Optional

logger = structlog.get_logger(__name__)


class ReplayProtection:
    """Prevents replay attacks on Jira webhooks using timestamp + Redis tracking."""

    REDIS_KEY_PREFIX = "webhook:processed"
    DEFAULT_TTL_SECONDS = 86400  # 24 hours

    def __init__(self, redis_client: redis.Redis):
        """
        Initialize replay protection with Redis client.

        Args:
            redis_client: Async Redis client for webhook ID tracking
        """
        self.redis = redis_client
        logger.info(
            "replay_protection.initialized",
            msg="Replay protection initialized with Redis backend"
        )

    async def is_webhook_fresh(
        self,
        timestamp: datetime,
        max_age_seconds: int = 300
    ) -> tuple[bool, Optional[str]]:
        """
        Validate webhook timestamp is within acceptable age.

        Args:
            timestamp: Webhook timestamp (from payload)
            max_age_seconds: Maximum age in seconds (default: 300 = 5 minutes)

        Returns:
            Tuple of (is_fresh, error_message)
            - (True, None) if timestamp is fresh
            - (False, error_message) if too old

        Security Notes:
            - Default 5 minute window balances security vs clock skew tolerance
            - Uses UTC timestamps to avoid timezone issues
        """
        current_time = datetime.now(timezone.utc)

        # Ensure timestamp is timezone-aware
        if timestamp.tzinfo is None:
            # Assume UTC if timezone not specified
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        # Calculate age
        age_seconds = (current_time - timestamp).total_seconds()

        # Check if too old
        if age_seconds > max_age_seconds:
            logger.warning(
                "replay_protection.stale_webhook",
                age_seconds=int(age_seconds),
                max_age_seconds=max_age_seconds,
                webhook_timestamp=timestamp.isoformat(),
                msg="Webhook rejected: too old"
            )
            return (False, f"Webhook timestamp too old ({int(age_seconds)}s > {max_age_seconds}s)")

        # Check if from future (possible clock skew)
        if age_seconds < -60:  # Allow 60s clock skew into future
            logger.warning(
                "replay_protection.future_timestamp",
                age_seconds=int(age_seconds),
                webhook_timestamp=timestamp.isoformat(),
                msg="Webhook has future timestamp (possible clock skew)"
            )
            return (False, "Webhook timestamp is in the future")

        logger.debug(
            "replay_protection.timestamp_valid",
            age_seconds=int(age_seconds),
            msg="Webhook timestamp is fresh"
        )
        return (True, None)

    async def is_duplicate(self, webhook_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if webhook ID has been processed before.

        Args:
            webhook_id: Unique webhook identifier (from payload)

        Returns:
            Tuple of (is_duplicate, error_message)
            - (False, None) if webhook is new
            - (True, error_message) if already processed
            - (False, None) if Redis unavailable (fail-open)

        Error Handling:
            - If Redis connection fails: Logs error, returns (False, None)
            - Rationale: Availability > strict replay prevention for incident response
        """
        redis_key = f"{self.REDIS_KEY_PREFIX}:{webhook_id}"

        try:
            # Check if key exists in Redis
            exists = await self.redis.exists(redis_key)

            if exists:
                logger.warning(
                    "replay_protection.duplicate_detected",
                    webhook_id=webhook_id,
                    msg="Webhook rejected: duplicate ID detected"
                )
                return (True, f"Webhook ID already processed: {webhook_id}")

            logger.debug(
                "replay_protection.new_webhook",
                webhook_id=webhook_id,
                msg="Webhook ID is new (not a duplicate)"
            )
            return (False, None)

        except redis.RedisError as e:
            # Redis connection failed - fail-open
            logger.error(
                "replay_protection.redis_error",
                error=str(e),
                error_type=type(e).__name__,
                webhook_id=webhook_id,
                msg="Redis connection failed during duplicate check (failing open)"
            )
            # Return False (not duplicate) to accept webhook despite Redis failure
            return (False, None)

    async def mark_processed(
        self,
        webhook_id: str,
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Mark webhook as processed in Redis.

        Args:
            webhook_id: Unique webhook identifier
            ttl_seconds: Time-to-live in seconds (default: 24 hours)

        Returns:
            True if successfully marked, False if Redis error

        Error Handling:
            - If Redis fails: Logs error, returns False
            - Webhook still accepted (fail-open strategy)
        """
        if ttl_seconds is None:
            ttl_seconds = self.DEFAULT_TTL_SECONDS

        redis_key = f"{self.REDIS_KEY_PREFIX}:{webhook_id}"

        try:
            # Set key with TTL
            await self.redis.setex(
                name=redis_key,
                time=ttl_seconds,
                value="1"
            )

            logger.info(
                "replay_protection.marked_processed",
                webhook_id=webhook_id,
                ttl_seconds=ttl_seconds,
                msg="Webhook marked as processed in Redis"
            )
            return True

        except redis.RedisError as e:
            logger.error(
                "replay_protection.mark_failed",
                error=str(e),
                error_type=type(e).__name__,
                webhook_id=webhook_id,
                msg="Failed to mark webhook as processed (Redis error)"
            )
            return False

    async def validate_and_track(
        self,
        webhook_id: str,
        timestamp: datetime,
        max_age_seconds: int = 300
    ) -> tuple[bool, Optional[str]]:
        """
        Convenience method: Validate timestamp AND check for duplicates.

        Combines is_webhook_fresh() and is_duplicate() into single call.

        Args:
            webhook_id: Unique webhook identifier
            timestamp: Webhook timestamp
            max_age_seconds: Maximum acceptable age in seconds

        Returns:
            Tuple of (is_valid, error_message)
            - (True, None) if webhook passes all checks
            - (False, error_message) if any check fails

        Note:
            Does NOT mark as processed - call mark_processed() separately
            after successful webhook processing.
        """
        # Check timestamp freshness first (cheaper than Redis call)
        is_fresh, error = await self.is_webhook_fresh(timestamp, max_age_seconds)
        if not is_fresh:
            return (False, error)

        # Check for duplicate
        is_dup, error = await self.is_duplicate(webhook_id)
        if is_dup:
            return (False, error)

        return (True, None)


class ReplayAttackError(Exception):
    """Raised when replay attack is detected."""
    pass
