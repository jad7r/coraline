#!/usr/bin/env python3
"""
Redis Pub/Sub PIR Subscriber

Listens for incident events published by jira-webhook-listener
and triggers automated PIR generation for resolved incidents.

Redis Channel: coreline:incident:created
Message Format: JSON-serialized IncidentEvent
"""

import asyncio
import json
import structlog
import redis.asyncio as redis
from typing import Callable, Awaitable
from pydantic import ValidationError

# Import IncidentEvent model
from services.brain_service.models.incident_event import IncidentEvent

logger = structlog.get_logger(__name__)


class PIRSubscriber:
    """Subscribes to incident events and triggers PIR generation for resolved incidents."""

    def __init__(
        self,
        redis_client: redis.Redis,
        on_pir_callback: Callable[[IncidentEvent], Awaitable[str]],
        channel_name: str = "coreline:incident:created"
    ):
        """
        Initialize PIR subscriber.

        Args:
            redis_client: Async Redis client
            on_pir_callback: Async callback function to generate PIR
            channel_name: Redis Pub/Sub channel name
        """
        self.redis = redis_client
        self.on_pir_callback = on_pir_callback
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
            "pir_subscriber.starting",
            channel=self.channel_name,
            msg="Starting Redis Pub/Sub subscriber for PIR generation"
        )

        pubsub = self.redis.pubsub()

        try:
            await pubsub.subscribe(self.channel_name)

            logger.info(
                "pir_subscriber.subscribed",
                channel=self.channel_name,
                msg="Subscribed to incident channel for PIR generation"
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
                    logger.info("pir_subscriber.cancelled", msg="Subscriber task cancelled")
                    break

                except Exception as e:
                    logger.exception(
                        "pir_subscriber.loop_error",
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
                    "pir_subscriber.stopped",
                    channel=self.channel_name,
                    msg="PIR subscriber stopped and cleaned up"
                )
            except Exception as e:
                logger.error(
                    "pir_subscriber.cleanup_error",
                    error=str(e),
                    msg="Error during PIR subscriber cleanup"
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
                "pir_subscriber.message_received",
                incident_id=incident_dict.get('incident_id'),
                msg="Received incident event from Redis"
            )

            # Validate with Pydantic
            try:
                incident = IncidentEvent(**incident_dict)
            except ValidationError as e:
                logger.error(
                    "pir_subscriber.validation_error",
                    validation_errors=e.errors(),
                    raw_data=incident_dict,
                    msg="Invalid incident event schema (skipping)"
                )
                return

            logger.info(
                "pir_subscriber.incident_received",
                incident_id=incident.incident_id,
                priority=incident.priority,
                severity=incident.severity,
                webhook_event=incident.webhook_event,
                msg="Valid incident event received for PIR evaluation"
            )

            # Trigger callback (PIR generation orchestrator)
            try:
                pir_path = await self.on_pir_callback(incident)

                if pir_path:
                    logger.info(
                        "pir_subscriber.callback_success",
                        incident_id=incident.incident_id,
                        pir_path=pir_path,
                        msg="PIR generation completed successfully"
                    )
                else:
                    logger.info(
                        "pir_subscriber.callback_skipped",
                        incident_id=incident.incident_id,
                        msg="PIR generation skipped (incident not yet resolved or already generated)"
                    )

            except Exception as e:
                logger.exception(
                    "pir_subscriber.callback_error",
                    incident_id=incident.incident_id,
                    error=str(e),
                    error_type=type(e).__name__,
                    msg="Error in PIR generation callback (non-fatal, continuing)"
                )

        except json.JSONDecodeError as e:
            logger.error(
                "pir_subscriber.invalid_json",
                error=str(e),
                raw_data=data[:100] if len(data) > 100 else data,
                msg="Failed to parse incident event JSON (skipping)"
            )

        except Exception as e:
            logger.exception(
                "pir_subscriber.processing_error",
                error=str(e),
                error_type=type(e).__name__,
                msg="Unexpected error processing incident event"
            )

    def stop(self):
        """Stop subscriber gracefully."""
        logger.info("pir_subscriber.stopping", msg="Stopping PIR subscriber")
        self.running = False
