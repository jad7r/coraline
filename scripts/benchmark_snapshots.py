"""Offline, disposable benchmark: python -m scripts.benchmark_snapshots --records 200."""
import argparse
import json
import tempfile
from pathlib import Path
from time import perf_counter

from core.evidence.integrity.signing import generate_signing_keypair
from core.incident import IncidentWorkspace
from core.incident.snapshots import SnapshotStore, inventory, canonical_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=200, help="Each of observations, claims, and actions.")
    parser.add_argument("--evidence", type=int, default=20)
    args = parser.parse_args()
    if args.records < 1 or args.evidence < 1:
        parser.error("counts must be positive")
    with tempfile.TemporaryDirectory(prefix="coreline-snapshot-benchmark-") as temporary:
        root = Path(temporary)
        ws = IncidentWorkspace.declare(root / "home", title="Synthetic benchmark", severity="SEV2", actor="benchmark")
        key, public = generate_signing_keypair()
        store = SnapshotStore(ws, public)
        store.create(key, "benchmark")
        started = perf_counter()
        for index in range(args.evidence):
            artifact = root / f"evidence-{index}.txt"
            artifact.write_text(f"synthetic evidence {index}\n" * 1000)
            ws.add_evidence(str(artifact), "benchmark", "benchmark")
        for index in range(args.records):
            observation = ws.add_observation(f"synthetic observation {index}", "benchmark")
            claim = ws.add_claim(f"synthetic claim {index}", "benchmark", [observation.observation_id])
            ws.create_action("contain", f"synthetic action {index}", "benchmark", claim_refs=[claim.claim_id])
        output = {"observations": args.records, "claims": args.records, "actions": args.records,
                  "evidence": args.evidence, "fixture_seconds": perf_counter() - started}
        started = perf_counter()
        captured = inventory(ws)
        output.update(inventory_seconds=perf_counter() - started, inventory_entries=captured["record_count"])
        started = perf_counter()
        assert ws.verify(include_snapshots=False)["ok"]
        output["base_verify_seconds"] = perf_counter() - started
        started = perf_counter()
        document = store.create(key, "benchmark")
        output.update(create_seconds=perf_counter() - started, snapshot_bytes=len(canonical_bytes(document)))
        ws.add_observation("third checkpoint", "benchmark")
        store.create(key, "benchmark")
        started = perf_counter()
        assert store.health()["valid"]
        output.update(three_checkpoint_health_seconds=perf_counter() - started, snapshots=3)
        print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
