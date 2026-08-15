#!/usr/bin/env python3
"""
Slack Channel Creator - Core Logic

Creates and configures Slack incident response channels with:
- Naming convention: sec-ops-inc-{year}-{number}
- Initial team member invitations
- Channel topic/description with incident metadata
- Pinned initial message with incident summary
"""

import asyncio
import structlog
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from typing import Optional
from datetime import datetime

from services.slack_orchestrator.utils.channel_naming import (
    generate_channel_name,
    generate_collision_suffix,
    ChannelNamingError,
)
from services.slack_orchestrator.utils.duplicate_tracker import DuplicateTracker
from services.slack_orchestrator.handlers.audit_logger import AuditLogger
from services.slack_orchestrator.models.incident_event import IncidentEvent

logger = structlog.get_logger(__name__)


class ChannelCreationError(Exception):
    """Raised when channel creation fails."""
    pass


class SlackChannelCreator:
    """Creates and configures Slack incident response channels."""

    MAX_RETRIES = 3
    RETRY_DELAY_BASE = 2  # seconds

    def __init__(
        self,
        slack_client: WebClient,
        duplicate_tracker: DuplicateTracker,
        audit_logger: AuditLogger,
        response_team_user_ids: list[str]
    ):
        """
        Initialize channel creator.

        Args:
            slack_client: Slack SDK WebClient
            duplicate_tracker: Redis-based duplicate prevention
            audit_logger: Audit event emitter
            response_team_user_ids: List of Slack user IDs to invite
        """
        self.slack = slack_client
        self.duplicate_tracker = duplicate_tracker
        self.audit_logger = audit_logger
        self.response_team_user_ids = response_team_user_ids

    async def create_incident_channel(self, incident: IncidentEvent) -> str:
        """
        Create Slack channel for security incident.

        Steps:
        1. Check duplicate (Redis tracking)
        2. Generate channel name (sec-ops-inc-{year}-{number})
        3. Create private channel (Slack API)
        4. Set topic (emoji + severity + IC)
        5. Set description (incident summary + Jira link)
        6. Invite response team
        7. Post initial message (rich formatting with Block Kit)
        8. Mark as created (Redis)
        9. Emit audit event

        Args:
            incident: Incident event from Redis Pub/Sub

        Returns:
            Slack channel ID (e.g., "C01234567")

        Raises:
            ChannelCreationError: If creation fails after retries
        """
        start_time = datetime.now()

        logger.info(
            "slack_creator.starting",
            incident_id=incident.incident_id,
            priority=incident.priority,
            severity=incident.severity,
            msg="Starting incident channel creation"
        )

        try:
            # Step 1: Check duplicate
            exists, existing_channel_id = await self.duplicate_tracker.channel_exists(
                incident.incident_id
            )

            if exists:
                logger.info(
                    "slack_creator.channel_exists",
                    incident_id=incident.incident_id,
                    channel_id=existing_channel_id,
                    msg="Channel already exists for incident (skipping creation)"
                )
                return existing_channel_id

            # Step 2: Generate channel name
            try:
                channel_name = generate_channel_name(incident.incident_id)
            except ChannelNamingError as e:
                raise ChannelCreationError(f"Invalid incident ID for channel naming: {e}")

            # Step 3: Create private channel
            channel_id = await self._create_channel_with_retry(channel_name, incident.incident_id)

            # Step 4: Set topic
            await self._set_channel_topic(channel_id, incident)

            # Step 5: Set description
            await self._set_channel_description(channel_id, incident)

            # Step 6: Invite response team
            await self._invite_team_members(channel_id, incident.incident_id)

            # Step 7: Post initial message
            await self._post_initial_message(channel_id, incident)

            # Step 8: Mark as created
            await self.duplicate_tracker.mark_channel_created(
                incident.incident_id,
                channel_id
            )

            # Step 9: Emit audit event
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            self.audit_logger.log_channel_created(
                incident_id=incident.incident_id,
                channel_id=channel_id,
                channel_name=channel_name,
                duration_ms=duration_ms,
                metadata={
                    "priority": incident.priority,
                    "severity": incident.severity,
                    "team_members_invited": len(self.response_team_user_ids),
                    "incident_commander": incident.incident_commander
                }
            )

            logger.info(
                "slack_creator.success",
                incident_id=incident.incident_id,
                channel_id=channel_id,
                channel_name=channel_name,
                duration_ms=duration_ms,
                msg="Incident channel created successfully"
            )

            return channel_id

        except Exception as e:
            # Log failure audit event
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            self.audit_logger.log_channel_creation_failed(
                incident_id=incident.incident_id,
                error_message=str(e),
                error_code=type(e).__name__,
                duration_ms=duration_ms
            )

            logger.exception(
                "slack_creator.failed",
                incident_id=incident.incident_id,
                error=str(e),
                duration_ms=duration_ms,
                msg="Failed to create incident channel"
            )

            raise

    async def _create_channel_with_retry(self, channel_name: str, incident_id: str) -> str:
        """
        Create Slack channel with retry logic for rate limits.

        Args:
            channel_name: Desired channel name
            incident_id: Incident ID (for logging)

        Returns:
            Slack channel ID

        Raises:
            ChannelCreationError: If creation fails after retries
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                logger.info(
                    "slack_creator.creating_channel",
                    incident_id=incident_id,
                    channel_name=channel_name,
                    attempt=attempt + 1,
                    msg="Creating Slack channel"
                )

                response = self.slack.conversations_create(
                    name=channel_name,
                    is_private=True  # Security incidents are confidential
                )

                channel_id = response['channel']['id']

                logger.info(
                    "slack_creator.channel_created",
                    channel_id=channel_id,
                    channel_name=channel_name,
                    msg="Slack channel created"
                )

                return channel_id

            except SlackApiError as e:
                error_code = e.response.get('error', 'unknown')

                # Handle name collision (rare but possible)
                if error_code == 'name_taken':
                    logger.warning(
                        "slack_creator.channel_name_collision",
                        channel_name=channel_name,
                        incident_id=incident_id,
                        msg="Channel name collision (appending timestamp)"
                    )

                    # Append a timestamp suffix and let the loop retry with the
                    # new name. `continue` (rather than an unguarded second
                    # create() here) keeps every retry inside the try/except so
                    # a follow-on Slack error is still wrapped and still counts
                    # against the retry budget.
                    collision_suffix = generate_collision_suffix()
                    channel_name = f"{channel_name}-{collision_suffix}"

                    if attempt < self.MAX_RETRIES - 1:
                        continue
                    raise ChannelCreationError(
                        f"Channel name collision unresolved after {self.MAX_RETRIES} attempts"
                    )

                # Handle rate limiting with exponential backoff
                elif error_code == 'rate_limited':
                    # Default backoff: 2s, 4s, 8s (RETRY_DELAY_BASE ** (attempt+1)).
                    retry_after = int(
                        e.response.headers.get(
                            'Retry-After', self.RETRY_DELAY_BASE ** (attempt + 1)
                        )
                    )

                    logger.warning(
                        "slack_creator.rate_limited",
                        retry_after=retry_after,
                        attempt=attempt + 1,
                        max_retries=self.MAX_RETRIES,
                        msg="Rate limited by Slack API (retrying)"
                    )

                    if attempt < self.MAX_RETRIES - 1:
                        # Async sleep so the single-worker event loop (health
                        # probes, subscriber) is not blocked during backoff.
                        await asyncio.sleep(retry_after)
                        continue
                    else:
                        raise ChannelCreationError(f"Rate limited after {self.MAX_RETRIES} retries")

                # Other Slack errors
                else:
                    raise ChannelCreationError(f"Slack API error: {error_code} - {e.response.get('error')}")

        raise ChannelCreationError(f"Failed to create channel after {self.MAX_RETRIES} retries")

    async def _set_channel_topic(self, channel_id: str, incident: IncidentEvent):
        """Set channel topic with incident metadata."""
        topic = f"🚨 {incident.severity} | {incident.incident_id} | IC: {incident.incident_commander or 'Unassigned'}"

        try:
            self.slack.conversations_setTopic(
                channel=channel_id,
                topic=topic[:250]  # Slack limit: 250 chars
            )
            logger.debug("slack_creator.topic_set", channel_id=channel_id)
        except SlackApiError as e:
            # Non-fatal - log but don't fail
            logger.warning(
                "slack_creator.topic_set_failed",
                channel_id=channel_id,
                error=str(e),
                msg="Failed to set channel topic (non-fatal)"
            )

    async def _set_channel_description(self, channel_id: str, incident: IncidentEvent):
        """Set channel description with incident details."""
        description = f"Incident response channel for {incident.incident_id}\nJira: {incident.jira_url}"

        try:
            self.slack.conversations_setPurpose(
                channel=channel_id,
                purpose=description[:250]  # Slack limit: 250 chars
            )
            logger.debug("slack_creator.description_set", channel_id=channel_id)
        except SlackApiError as e:
            # Non-fatal - log but don't fail
            logger.warning(
                "slack_creator.description_set_failed",
                channel_id=channel_id,
                error=str(e),
                msg="Failed to set channel description (non-fatal)"
            )

    async def _invite_team_members(self, channel_id: str, incident_id: str):
        """Invite incident response team to channel."""
        if not self.response_team_user_ids:
            logger.warning(
                "slack_creator.no_team_configured",
                channel_id=channel_id,
                msg="No response team user IDs configured (skipping invites)"
            )
            return

        try:
            # Slack API expects comma-separated user IDs
            user_ids = ",".join(self.response_team_user_ids)

            self.slack.conversations_invite(
                channel=channel_id,
                users=user_ids
            )

            logger.info(
                "slack_creator.team_invited",
                channel_id=channel_id,
                user_count=len(self.response_team_user_ids),
                msg="Response team invited to channel"
            )

        except SlackApiError as e:
            # Non-fatal - log error but don't fail channel creation
            # Team can manually join via Slack search
            logger.error(
                "slack_creator.invite_failed",
                channel_id=channel_id,
                error=str(e),
                error_code=e.response.get('error'),
                msg="Failed to invite team members (non-fatal, team can join manually)"
            )

    async def _post_initial_message(self, channel_id: str, incident: IncidentEvent):
        """Post initial incident summary message with Block Kit formatting."""
        # Build Block Kit message
        message_blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Security Incident: {incident.incident_id}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Priority:*\n{incident.priority}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{incident.severity}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Incident Commander:*\n{incident.incident_commander or 'Unassigned'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Detected:*\n<!date^{int(incident.detection_time.timestamp())}^{{date_short_pretty}} at {{time}}|{incident.detection_time.isoformat()}>"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Summary:*\n{incident.summary}"
                }
            }
        ]

        # Add affected systems if present
        if incident.affected_systems:
            message_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Affected Systems:*\n" + "\n".join(f"• {system}" for system in incident.affected_systems)
                }
            })

        # Add Jira button
        message_blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View in Jira"
                    },
                    "url": incident.jira_url,
                    "style": "primary"
                }
            ]
        })

        try:
            response = self.slack.chat_postMessage(
                channel=channel_id,
                blocks=message_blocks,
                text=f"Security Incident: {incident.incident_id} - {incident.summary}"
            )

            # Pin the initial message
            message_ts = response['ts']
            self.slack.pins_add(
                channel=channel_id,
                timestamp=message_ts
            )

            logger.info(
                "slack_creator.initial_message_posted",
                channel_id=channel_id,
                message_ts=message_ts,
                msg="Initial message posted and pinned"
            )

        except SlackApiError as e:
            # Non-fatal - log error but don't fail
            logger.error(
                "slack_creator.initial_message_failed",
                channel_id=channel_id,
                error=str(e),
                msg="Failed to post initial message (non-fatal)"
            )
