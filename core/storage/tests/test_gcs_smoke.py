"""CI-gated real-GCS smoke test — Phase 1H Task 4.

SKIPPED by default. Enable ONLY against an UN-LOCKED staging bucket:

    CORELINE_GCS_SMOKE=1 CORELINE_EVIDENCE_BUCKET=<staging-bucket> \\
        python -m pytest core/storage/tests/test_gcs_smoke.py

Requires ``google-cloud-storage`` installed and ambient (Workload Identity / ADC)
credentials. Verifies the real keyless upload returns a generation (real API call shape).
Refuses to run against the production LOCKED bucket.
"""
import os
import unittest
import uuid
from datetime import datetime, timezone

_ENABLED = os.environ.get("CORELINE_GCS_SMOKE") == "1"


@unittest.skipUnless(
    _ENABLED,
    "GCS smoke test disabled — set CORELINE_GCS_SMOKE=1 + CORELINE_EVIDENCE_BUCKET "
    "(an UN-locked staging bucket) to run",
)
class TestGCSSmoke(unittest.TestCase):
    def test_keyless_upload_returns_generation(self):
        from core.storage.config import is_prod_locked_bucket, resolve_evidence_bucket
        from core.storage.gcs import GCSWormBackend

        bucket = resolve_evidence_bucket()
        self.assertFalse(
            is_prod_locked_bucket(bucket),
            "refusing to run the smoke test against the production LOCKED bucket",
        )
        backend = GCSWormBackend.keyless(bucket)
        name = f"smoke/coreline-{uuid.uuid4().hex}.json"
        receipt = backend.put_object(
            name, b'{"smoke":true}', stored_when=datetime.now(timezone.utc)
        )
        self.assertEqual(receipt.backend, "gcs")
        self.assertTrue(receipt.uri.startswith(f"gs://{bucket}/"))
        self.assertIsNotNone(receipt.generation)


if __name__ == "__main__":
    unittest.main()
