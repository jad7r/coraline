#!/usr/bin/env python3
"""
PIR Generation Orchestrator

Coordinates the end-to-end PIR generation workflow:
1. Validate incident status (must be Resolved/Closed)
2. Lookup Slack channel from Redis
3. Assemble data from Jira and Slack
4. Generate PIR using Claude AI
5. Save PIR to filesystem
6. Publish completion event to Redis
7. Audit log everything
"""

import asyncio
import json
import structlog
import redis.asyncio as redis
from datetime import datetime
from pathlib import Path
from typing import Optional

# Import local models and utilities
from services.brain_service.models.incident_event import IncidentEvent
from services.brain_service.utils.duplicate_tracker import DuplicateTracker

# PIR generation components + AI provider boundary.
# These are vendored shims until the real brain/collectors modules land
# (see services/brain_service/_lib_shim.py and ADR-0003).
from services.brain_service._lib_shim import (
    JiraIncidentCollector,
    PIRDataAssembler,
    PIRGenerator,
    PIRProvider,
)

logger = structlog.get_logger(__name__)


class PIROrchestrator:
    """Orchestrates automated PIR generation for resolved incidents."""

    def __init__(
        self,
        redis_client: redis.Redis,
        pir_output_dir: Path,
        claude_model: str = "claude-sonnet-4-5",
        claude_max_tokens: int = 16000,
        claude_temperature: float = 0.3,
        generate_pir_on_status: list[str] = None,
        skip_pir_if_exists: bool = True,
        pir_completed_channel: str = "coreline:pir:completed",
        channel_tracking_ttl_seconds: int = 7776000,
        slack_message_limit: int = 1000,
        jira_server: str = "https://pantheon.atlassian.net",
        pir_provider: Optional[PIRProvider] = None
    ):
        """
        Initialize PIR orchestrator.

        Args:
            redis_client: Async Redis client
            pir_output_dir: Directory for generated PIR files
            claude_model: Claude model for PIR generation
            claude_max_tokens: Max tokens for Claude response
            claude_temperature: Sampling temperature for the provider (lower = more
                deterministic). Passed through to the AI provider.
            generate_pir_on_status: List of Jira statuses that trigger PIR generation
            skip_pir_if_exists: Skip generation if PIR file already exists
            pir_completed_channel: Redis channel for completion events
            channel_tracking_ttl_seconds: TTL for channel tracking in Redis
            slack_message_limit: Max Slack messages to fetch
            jira_server: Jira server URL
            pir_provider: AI provider for PIR generation (advisory, replaceable per
                ADR-0002 §2). If None, one is auto-selected: real Claude when an API
                key is configured, else an offline deterministic provider. Tests
                inject a fake here so no live LLM/network is required.
        """
        self.redis = redis_client
        self.pir_output_dir = Path(pir_output_dir)
        self.claude_model = claude_model
        self.claude_max_tokens = claude_max_tokens
        self.claude_temperature = claude_temperature
        self.generate_pir_on_status = generate_pir_on_status or ["Resolved", "Closed"]
        self.skip_pir_if_exists = skip_pir_if_exists
        self.pir_completed_channel = pir_completed_channel
        self.slack_message_limit = slack_message_limit
        self.jira_server = jira_server
        self.pir_provider = pir_provider

        # Initialize channel tracker
        self.channel_tracker = DuplicateTracker(
            redis_client=redis_client,
            ttl_seconds=channel_tracking_ttl_seconds
        )

        # Ensure output directory exists
        self.pir_output_dir.mkdir(parents=True, exist_ok=True)

    async def generate_pir_for_incident(self, incident: IncidentEvent) -> Optional[str]:
        """
        Generate PIR for incident if conditions are met.

        Args:
            incident: IncidentEvent from Redis Pub/Sub

        Returns:
            Path to generated PIR file, or None if skipped

        Raises:
            Exception: If PIR generation fails
        """
        incident_id = incident.incident_id

        logger.info(
            "pir_orchestrator.evaluating_incident",
            incident_id=incident_id,
            priority=incident.priority,
            severity=incident.severity,
            msg="Evaluating incident for PIR generation"
        )

        # Step 1: Check if incident status warrants PIR generation
        try:
            should_generate, status = await self._should_generate_pir(incident_id)
            if not should_generate:
                logger.info(
                    "pir_orchestrator.skipped_status",
                    incident_id=incident_id,
                    status=status,
                    required_statuses=self.generate_pir_on_status,
                    msg=f"Skipping PIR generation - incident status '{status}' not in {self.generate_pir_on_status}"
                )
                return None
        except Exception as e:
            logger.error(
                "pir_orchestrator.status_check_failed",
                incident_id=incident_id,
                error=str(e),
                msg="Failed to check incident status (skipping PIR generation)"
            )
            return None

        # Step 2: Check if a PIR already exists for this incident.
        # PIR filenames embed a generation timestamp, so we must match ANY prior
        # PIR for the incident by glob — not the (always-new) path we would write.
        if self.skip_pir_if_exists:
            existing = self._find_existing_pir(incident_id)
            if existing is not None:
                logger.info(
                    "pir_orchestrator.skipped_exists",
                    incident_id=incident_id,
                    pir_path=str(existing),
                    msg="Skipping PIR generation - file already exists"
                )
                return None

        # Compute the (timestamped) path we will write to for this run.
        pir_path = self._get_pir_path(incident_id)

        # Step 3: Lookup Slack channel from Redis
        try:
            channel_id = await self.channel_tracker.get_channel_id(incident_id)
            if not channel_id:
                logger.warning(
                    "pir_orchestrator.no_channel",
                    incident_id=incident_id,
                    msg="No Slack channel found in Redis - PIR may be incomplete"
                )
                # Continue anyway - PIR can be generated from Jira alone
        except Exception as e:
            logger.warning(
                "pir_orchestrator.channel_lookup_failed",
                incident_id=incident_id,
                error=str(e),
                msg="Failed to lookup Slack channel (continuing without Slack data)"
            )
            channel_id = None

        # Step 4: Generate PIR
        try:
            logger.info(
                "pir_orchestrator.generation_started",
                incident_id=incident_id,
                channel_id=channel_id,
                model=self.claude_model,
                msg="Starting PIR generation"
            )

            pir_content = await self._generate_pir(incident_id, channel_id)

            # Step 5: Save PIR to filesystem (offloaded — the write can block on a
            # slow/mounted volume and this runs on the shared event loop).
            await asyncio.to_thread(pir_path.write_text, pir_content, encoding="utf-8")

            logger.info(
                "pir_orchestrator.pir_saved",
                incident_id=incident_id,
                pir_path=str(pir_path),
                pir_length=len(pir_content),
                msg="PIR saved to filesystem"
            )

            # Step 6: Publish completion event to Redis
            await self._publish_completion_event(incident_id, str(pir_path))

            return str(pir_path)

        except Exception as e:
            logger.exception(
                "pir_orchestrator.generation_failed",
                incident_id=incident_id,
                error=str(e),
                error_type=type(e).__name__,
                msg="PIR generation failed"
            )
            raise

    async def _should_generate_pir(self, incident_id: str) -> tuple[bool, str]:
        """
        Check if incident status warrants PIR generation.

        Args:
            incident_id: Jira incident ID

        Returns:
            Tuple of (should_generate: bool, status: str)
        """
        # Fetch current status from Jira (sync call wrapped in async)
        def fetch_status():
            try:
                jira_collector = JiraIncidentCollector(server=self.jira_server)
                metadata = jira_collector.get_incident_metadata(incident_id)
                return metadata.get('status', 'Unknown')
            except Exception as e:
                logger.error(
                    "pir_orchestrator.jira_fetch_failed",
                    incident_id=incident_id,
                    error=str(e),
                    msg="Failed to fetch Jira metadata"
                )
                raise

        status = await asyncio.to_thread(fetch_status)

        should_generate = status in self.generate_pir_on_status
        return (should_generate, status)

    async def _generate_pir(self, incident_id: str, channel_id: Optional[str]) -> str:
        """
        Generate PIR using existing brain components.

        Args:
            incident_id: Jira incident ID
            channel_id: Slack channel ID (optional)

        Returns:
            Generated PIR markdown content
        """
        # Run PIR generation in thread pool (sync code)
        def generate():
            try:
                # Assemble the data packet. The assembler already emits the
                # "[No Slack channel found ...]" packet when channel_id is None,
                # so both paths share one code path (no duplicated packet format).
                assembler = PIRDataAssembler(jira_server=self.jira_server)
                data_packet = assembler.assemble(
                    incident_id=incident_id,
                    slack_channel_id=channel_id,
                    message_limit=self.slack_message_limit
                )

                # Generate PIR via the (replaceable, advisory) AI provider.
                generator = PIRGenerator(
                    model=self.claude_model,
                    provider=self.pir_provider,
                )
                pir = generator.generate(
                    data_packet=data_packet,
                    max_tokens=self.claude_max_tokens,
                    temperature=self.claude_temperature,
                )

                return pir

            except Exception as e:
                logger.error(
                    "pir_orchestrator.generation_error",
                    incident_id=incident_id,
                    error=str(e),
                    msg="Error during PIR generation"
                )
                raise

        return await asyncio.to_thread(generate)

    async def _publish_completion_event(self, incident_id: str, pir_path: str):
        """
        Publish PIR completion event to Redis.

        Args:
            incident_id: Jira incident ID
            pir_path: Path to generated PIR file
        """
        try:
            completion_event = {
                "incident_id": incident_id,
                "pir_path": pir_path,
                "generated_at": datetime.now().isoformat(),
                "model": self.claude_model
            }

            await self.redis.publish(
                self.pir_completed_channel,
                json.dumps(completion_event)
            )

            logger.info(
                "pir_orchestrator.published_completion",
                incident_id=incident_id,
                channel=self.pir_completed_channel,
                msg="Published PIR completion event to Redis"
            )

        except redis.RedisError as e:
            # Non-fatal - log error but don't fail PIR generation
            logger.error(
                "pir_orchestrator.publish_failed",
                incident_id=incident_id,
                error=str(e),
                msg="Failed to publish completion event (non-fatal)"
            )

    def _get_pir_path(self, incident_id: str) -> Path:
        """
        Get filesystem path for PIR file.

        Args:
            incident_id: Jira incident ID

        Returns:
            Path object for PIR file
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{incident_id}-{timestamp}.md"
        return self.pir_output_dir / filename

    def _find_existing_pir(self, incident_id: str) -> Optional[Path]:
        """Return an existing PIR file for the incident, if any.

        PIR filenames are ``{incident_id}-{timestamp}.md``; a duplicate/redelivered
        webhook must match a PIR written at a *different* timestamp, so we glob on
        the incident id rather than testing the (always-new) path for this run.

        Args:
            incident_id: Jira incident ID

        Returns:
            Path of an existing PIR, or None if none exists.
        """
        matches = sorted(self.pir_output_dir.glob(f"{incident_id}-*.md"))
        return matches[0] if matches else None
