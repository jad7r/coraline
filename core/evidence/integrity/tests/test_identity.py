"""
Tests for identity module.
"""

import unittest

from core.evidence.integrity.identity import UserContext, create_user_context


class TestIdentity(unittest.TestCase):
    """Test identity and user context."""

    def test_create_user_context(self):
        """Test creating a user context."""
        user_ctx = create_user_context(
            user_id="user123",
            email="user@example.com",
            groups={"admin", "editors"},
            display_name="Test User"
        )

        self.assertEqual(user_ctx.user_id, "user123")
        self.assertEqual(user_ctx.email, "user@example.com")
        self.assertEqual(user_ctx.groups, {"admin", "editors"})
        self.assertEqual(user_ctx.display_name, "Test User")

    def test_create_user_context_minimal(self):
        """Test creating user context with minimal fields."""
        user_ctx = create_user_context(
            user_id="user123",
            email="user@example.com"
        )

        self.assertEqual(user_ctx.user_id, "user123")
        self.assertEqual(user_ctx.email, "user@example.com")
        self.assertEqual(user_ctx.groups, set())
        self.assertIsNone(user_ctx.display_name)

    def test_has_group(self):
        """Test group membership check."""
        user_ctx = create_user_context(
            user_id="user123",
            email="user@example.com",
            groups={"admin", "editors"}
        )

        self.assertTrue(user_ctx.has_group("admin"))
        self.assertTrue(user_ctx.has_group("editors"))
        self.assertFalse(user_ctx.has_group("viewers"))

    def test_has_any_group(self):
        """Test any group membership check."""
        user_ctx = create_user_context(
            user_id="user123",
            email="user@example.com",
            groups={"admin", "editors"}
        )

        self.assertTrue(user_ctx.has_any_group({"admin", "viewers"}))
        self.assertTrue(user_ctx.has_any_group({"editors"}))
        self.assertFalse(user_ctx.has_any_group({"viewers", "guests"}))

    def test_has_all_groups(self):
        """Test all groups membership check."""
        user_ctx = create_user_context(
            user_id="user123",
            email="user@example.com",
            groups={"admin", "editors", "reviewers"}
        )

        self.assertTrue(user_ctx.has_all_groups({"admin", "editors"}))
        self.assertTrue(user_ctx.has_all_groups({"admin"}))
        self.assertFalse(user_ctx.has_all_groups({"admin", "viewers"}))

    def test_empty_user_id_fails(self):
        """Test that empty user_id raises error."""
        with self.assertRaises(ValueError):
            create_user_context(user_id="", email="user@example.com")

        with self.assertRaises(ValueError):
            create_user_context(user_id="   ", email="user@example.com")

    def test_empty_email_fails(self):
        """Test that empty email raises error."""
        with self.assertRaises(ValueError):
            create_user_context(user_id="user123", email="")

        with self.assertRaises(ValueError):
            create_user_context(user_id="user123", email="   ")

    def test_user_context_immutable(self):
        """Test that UserContext is immutable (frozen)."""
        user_ctx = create_user_context(
            user_id="user123",
            email="user@example.com"
        )

        # Should not be able to modify frozen dataclass
        with self.assertRaises(Exception):
            user_ctx.user_id = "different"


if __name__ == "__main__":
    unittest.main()
