"""Tests for evidence-bucket env resolution — Phase 1H Task 4. Red-first."""
import re
import unittest

from core.storage.config import (
    ENV_VAR,
    PROD_LOCKED_BUCKET,
    StorageConfigError,
    is_prod_locked_bucket,
    resolve_evidence_bucket,
)


class TestStorageConfig(unittest.TestCase):
    def test_resolves_set_bucket(self):
        self.assertEqual(resolve_evidence_bucket({ENV_VAR: "my-staging-bucket"}), "my-staging-bucket")

    def test_strips_whitespace(self):
        self.assertEqual(resolve_evidence_bucket({ENV_VAR: "  b  "}), "b")

    def test_unset_fails_loud_with_no_prod_default(self):
        # The critical guardrail: nothing silently writes to prod.
        with self.assertRaises(StorageConfigError):
            resolve_evidence_bucket({})

    def test_empty_fails_loud(self):
        with self.assertRaises(StorageConfigError):
            resolve_evidence_bucket({ENV_VAR: "   "})

    def test_error_message_names_the_env_var(self):
        with self.assertRaises(StorageConfigError) as cm:
            resolve_evidence_bucket({})
        self.assertIn(ENV_VAR, str(cm.exception))

    def test_prod_bucket_detection(self):
        self.assertTrue(is_prod_locked_bucket(PROD_LOCKED_BUCKET))
        self.assertTrue(is_prod_locked_bucket(f"  {PROD_LOCKED_BUCKET}  "))
        self.assertFalse(is_prod_locked_bucket("some-staging-bucket"))

    def test_prod_bucket_name_is_valid_gcs_name(self):
        # Guardrail: GCS bucket names are lowercase, 3-63 chars, [a-z0-9._-], and must
        # start/end alphanumeric. Catches an invalid name (e.g. an uppercase typo) at test
        # time rather than at `gcloud storage buckets create`.
        name = PROD_LOCKED_BUCKET
        self.assertEqual(name, name.lower(), "GCS bucket names must be lowercase")
        self.assertTrue(3 <= len(name) <= 63, "GCS bucket names are 3-63 chars")
        self.assertRegex(name, r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")


if __name__ == "__main__":
    unittest.main()
