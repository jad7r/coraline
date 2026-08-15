#!/usr/bin/env python3
"""
Slack Channel Naming Convention

Generates Slack channel names from Jira incident IDs following pattern:
    sec-ops-inc-{year}-{number}

Examples:
    INC-42 → sec-ops-inc-2026-042
    INC-2026-001 → sec-ops-inc-2026-001
    INCIDENT-123 → sec-ops-inc-2026-123

Constraints:
    - Lowercase only (Slack requirement)
    - Alphanumeric + hyphens (Slack requirement)
    - Max 80 characters (Slack limit)
"""

import re
from datetime import datetime


class ChannelNamingError(Exception):
    """Raised when channel name generation fails."""
    pass


def generate_channel_name(incident_id: str, prefix: str = "sec-ops-inc") -> str:
    """
    Generate Slack channel name from Jira incident ID.

    Args:
        incident_id: Jira incident ID (e.g., INC-42, INC-2026-001)
        prefix: Channel name prefix (default: "sec-ops-inc")

    Returns:
        Slack channel name (e.g., sec-ops-inc-2026-042)

    Raises:
        ChannelNamingError: If incident ID format is invalid or name too long
    """
    # Validate incident ID format (must match ^[A-Z]+-\d+$)
    match = re.match(r'^[A-Z]+-(\d+)$', incident_id)
    if not match:
        raise ChannelNamingError(
            f"Invalid incident ID format: {incident_id} "
            f"(must match pattern ^[A-Z]+-\\d+$)"
        )

    # Extract numeric portion
    incident_number = match.group(1)

    # Get current year
    current_year = datetime.now().year

    # Zero-pad to 3 digits if needed (42 → 042, 1 → 001)
    # Don't truncate larger numbers (999999 → 999999)
    padded_number = incident_number.zfill(3)

    # Build channel name (lowercase required by Slack)
    channel_name = f"{prefix}-{current_year}-{padded_number}"

    # Validate Slack constraints
    if len(channel_name) > 80:
        raise ChannelNamingError(
            f"Channel name exceeds 80 character limit: {channel_name} "
            f"({len(channel_name)} chars)"
        )

    # Verify only allowed characters (alphanumeric + hyphens + underscores)
    if not re.match(r'^[a-z0-9_-]+$', channel_name):
        raise ChannelNamingError(
            f"Channel name contains invalid characters: {channel_name} "
            f"(only lowercase letters, numbers, hyphens, and underscores allowed)"
        )

    return channel_name


def extract_incident_number(incident_id: str) -> str:
    """
    Extract numeric portion from incident ID.

    Args:
        incident_id: Jira incident ID (e.g., INC-42)

    Returns:
        Numeric portion (e.g., "42")

    Raises:
        ChannelNamingError: If incident ID format is invalid
    """
    match = re.match(r'^[A-Z]+-(\d+)$', incident_id)
    if not match:
        raise ChannelNamingError(
            f"Invalid incident ID format: {incident_id}"
        )
    return match.group(1)


def generate_collision_suffix() -> str:
    """
    Generate timestamp suffix for handling channel name collisions.

    Returns:
        Timestamp suffix in format: MMDD-HHMM (e.g., "0521-1430")
    """
    return datetime.now().strftime("%m%d-%H%M")
