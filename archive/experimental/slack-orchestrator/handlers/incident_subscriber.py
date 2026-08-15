#!/usr/bin/env python3
"""
Redis Pub/Sub Incident Subscriber

Listens for incident creation events published by jira-webhook-listener
and triggers Slack channel creation.

Redis Channel: coreline:incident:created
Message Format: JSON-serialized IncidentEvent
"""

import asyncio
import json
import structlog
import redis.asyncio as redis
from typing import Callable, Awaitable
from pydantic import ValidationError

from models.incident_event import IncidentEvent

logger = structlog.get_logger(__name__)


class IncidentSubscriber:
    """Subscribes to incident creation events via Redis Pub/Sub."""

    def __init__(
        self,
        redis_client: redis.Redis,
        on_incident_callback: Callable[[IncidentEvent], Awaitable[str]],
        channel_name: str = "coreline:incident:created"
    ):
        """
        Initialize incident subscriber.

        Args:
            redis_client: Async Redis client
            on_incident_callback: Async callback function to handle incidents
            channel_name: Redis Pub/Sub channel name
        """
        self.redis = redis_client
        self.on_incident_callback = on_incident_callback
        self.channel_name = channel_name
        self.running = False

    async def start(self):
        """
        Start subscriber (blocking until stopped).

        Subscribes to Redis Pub/Sub channel and processes incoming incident events.
        Runs until stop() is called or task is cancelled.
        """
        self.running = True

        logger.info(
            "incident_subscriber.starting",
            channel=self.channel_name,
            msg="Starting Redis Pub/Sub subscriber"
        )

        pubsub = self.redis.pubsub()

        try:
            await pubsub.subscribe(self.channel_name)

            logger.info(
                "incident_subscriber.subscribed",
                channel=self.channel_name,
                msg="Subscribed to incident channel"
            )

            # Process messages until stopped
            while self.running:
                try:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0
                    )

                    if message and message['type'] == 'message':
                        await self._handle_message(message['data'])

                    # Small delay to prevent busy-wait
                    await asyncio.sleep(0.01)

                except asyncio.CancelledError:
                    logger.info("incident_subscriber.cancelled", msg="Subscriber task cancelled")
                    break

                except Exception as e:
                    logger.exception(
                        "incident_subscriber.loop_error",
                        error=str(e),
                        msg="Error in subscriber loop (continuing)"
                    )
                    # Continue processing (don't crash subscriber)
                    await asyncio.sleep(1)

        finally:
            # Clean up subscription
            try:
                await pubsub.unsubscribe(self.channel_name)
                await pubsub.close()
                logger.info(
                    "incident_subscriber.stopped",
                    channel=self.channel_name,
                    msg="Subscriber stopped and cleaned up"
                )
            except Exception as e:
                logger.error(
                    "incident_subscriber.cleanup_error",
                    error=str(e),
                    msg="Error during subscriber cleanup"
                )

    async def _handle_message(self, data: bytes):
        """
        Process incoming incident event.

        Args:
            data: Raw message data from Redis
        """
        try:
            # Decode and parse JSON
            message_str = data.decode('utf-8') if isinstance(data, bytes) else data
            incident_dict = json.loads(message_str)

            logger.debug(
                "incident_subscriber.message_received",
                incident_id=incident_dict.get('incident_id'),
                msg="Received incident event from Redis"
            )

            # Validate with Pydantic
            try:
                incident = IncidentEvent(**incident_dict)
            except ValidationError as e:
                logger.error(
                    "incident_subscriber.validation_error",
                    validation_errors=e.errors(),
                    raw_data=incident_dict,
                    msg="Invalid incident event schema (skipping)"
                )
                return

            logger.info(
                "incident_subscriber.incident_received",
                incident_id=incident.incident_id,
                priority=incident.priority,
                severity=incident.severity,
                msg="Valid incident event received"
            )

            # Trigger callback (channel creation)
            try:
                channel_id = await self.on_incident_callback(incident)

                logger.info(
                    "incident_subscriber.callback_success",
                    incident_id=incident.incident_id,
                    channel_id=channel_id,
                    msg="Incident callback completed successfully"
                )

            except Exception as e:
                logger.exception(
                    "incident_subscriber.callback_error",
                    incident_id=incident.incident_id,
                    error=str(e),
                    error_type=type(e).__name__,
                    msg="Error in incident callback (non-fatal, continuing)"
                )

        except json.JSONDecodeError as e:
            logger.error(
                "incident_subscriber.invalid_json",
                error=str(e),
                raw_data=data[:100] if len(data) > 100 else data,
                msg="Failed to parse incident event JSON (skipping)"
            )

        except Exception as e:
            logger.exception(
                "incident_subscriber.processing_error",
                error=str(e),
                error_type=type(e).__name__,
                msg="Unexpected error processing incident event"
            )

    def stop(self):
        """Stop subscriber gracefully."""
        logger.info("incident_subscriber.stopping", msg="Stopping subscriber")
        self.running = False
