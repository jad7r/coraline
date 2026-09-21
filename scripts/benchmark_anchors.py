"""Disposable filesystem-anchor benchmark: python -m scripts.benchmark_anchors."""
import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from time import perf_counter

from core.evidence.integrity import signing
from core.incident.anchors import FilesystemAnchor, request_from_snapshot, verify_receipt


def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", type=int, default=100)
    args = parser.parse_args()
    if args.receipts < 1:
        parser.error("receipt count must be positive")
    key, public = signing.generate_signing_keypair()
    with tempfile.TemporaryDirectory(prefix="coreline-anchor-benchmark-") as temporary:
        provider = FilesystemAnchor(Path(temporary) / "anchor", "benchmark-anchor", public, key)
        previous_id = previous_digest = None
        receipts = []
        started = perf_counter()
        for sequence in range(1, args.receipts + 1):
            snapshot_id = "SNP-" + digest(f"snapshot-id-{sequence}")
            current_digest = digest(f"snapshot-envelope-{sequence}")
            request = {"schema_version": 1, "incident_id": "INC-BENCHMARK",
                       "snapshot_id": snapshot_id, "snapshot_digest": current_digest,
                       "state_digest": digest(f"state-{sequence}"),
                       "snapshot_signer_key_id": "SHA256:" + digest("snapshot-signer"),
                       "snapshot_sequence": sequence, "previous_snapshot_id": previous_id,
                       "previous_snapshot_digest": previous_digest}
            receipts.append(provider.anchor(request))
            previous_id, previous_digest = snapshot_id, current_digest
        create_seconds = perf_counter() - started
        started = perf_counter()
        for receipt in receipts:
            assert verify_receipt(receipt, public, anchor_id="benchmark-anchor",
                                  incident_id="INC-BENCHMARK")["valid"]
        verify_seconds = perf_counter() - started
        started = perf_counter(); expected = provider.get_expected_tip("INC-BENCHMARK")
        expected_seconds = perf_counter() - started
        started = perf_counter(); ledger = provider.verify_ledger("INC-BENCHMARK")
        ledger_seconds = perf_counter() - started
        assert ledger["valid"] and expected == receipts[-1]
        print(json.dumps({"receipts": args.receipts, "create_total_seconds": create_seconds,
                          "create_mean_ms": create_seconds * 1000 / args.receipts,
                          "verify_total_seconds": verify_seconds,
                          "verify_mean_ms": verify_seconds * 1000 / args.receipts,
                          "expected_tip_seconds": expected_seconds,
                          "full_ledger_seconds": ledger_seconds}, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
