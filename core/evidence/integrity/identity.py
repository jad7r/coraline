"""
Identity and authorization context.

This module provides data structures for authenticated user context.
Actual Okta integration is out of scope - this is a stub interface.

In production, these objects would be populated by Okta authentication flows.
"""

from dataclasses import dataclass
from typing import Set, Optional


@dataclass(frozen=True)
class UserContext:
    """
    Authenticated user context.

    In production, this would be created after successful Okta authentication.
    Contains user identity and group membership for authorization decisions.

    Attributes:
        user_id: Unique user identifier (e.g., Okta user ID or email)
        email: User's email address
        groups: Set of group names the user belongs to
        display_name: Optional human-readable name
    """
    user_id: str
    email: str
    groups: Set[str]
    display_name: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate user context on creation."""
        if not self.user_id or not self.user_id.strip():
            raise ValueError("user_id cannot be empty")
        if not self.email or not self.email.strip():
            raise ValueError("email cannot be empty")

    def has_group(self, group_name: str) -> bool:
        """
        Check if user belongs to a specific group.

        Args:
            group_name: Name of the group to check

        Returns:
            True if user is a member, False otherwise
        """
        return group_name in self.groups

    def has_any_group(self, group_names: Set[str]) -> bool:
        """
        Check if user belongs to any of the specified groups.

        Args:
            group_names: Set of group names to check

        Returns:
            True if user belongs to at least one group, False otherwise
        """
        return bool(self.groups & group_names)

    def has_all_groups(self, group_names: Set[str]) -> bool:
        """
        Check if user belongs to all of the specified groups.

        Args:
            group_names: Set of group names to check

        Returns:
            True if user belongs to all groups, False otherwise
        """
        return group_names.issubset(self.groups)


def create_user_context(
    user_id: str,
    email: str,
    groups: Optional[Set[str]] = None,
    display_name: Optional[str] = None
) -> UserContext:
    """
    Create a user context object.

    In production, this would be called after Okta authentication
    with data from the Okta token/user info endpoint.

    Args:
        user_id: Unique user identifier
        email: User's email address
        groups: Set of group names (defaults to empty set)
        display_name: Optional display name

    Returns:
        UserContext object

    Raises:
        ValueError: If required fields are invalid
    """
    return UserContext(
        user_id=user_id,
        email=email,
        groups=groups or set(),
        display_name=display_name
    )
