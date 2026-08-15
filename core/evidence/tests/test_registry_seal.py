"""Tests for registry root-of-trust: root-signed registry sealing/verification (fail-closed).

Phase 1G1. Strict red-first. Real PyNaCl keys, no mocks; all Small tests (tempfiles only).
Convention: `root_*` keys are the registry authority; `signer_*` keys sign evidence.
"""
import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.evidence.integrity.signing import generate_signing_keypair
from core.evidence.manifest import build_manifest
from core.evidence.registry import (
    Outcome,
    RegistryError,
    TrustedSignerRegistry,
    load_signed_registry,
    save_registry,
    seal_registry,
    verify_against_registry,
    verify_registry_seal,
    verify_sealed_manifest_with_signed_registry,
)
from core.evidence.seal import seal_manifest, verify_sealed_manifest, write_seal

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


def _manifest(d):
    p = Path(d) / "a.log"
    p.write_bytes(b"hello evidence")
    return build_manifest("sec-ir-2026-07-06-test", [p], "alice@example.com", FIXED)


def _registry_with(signer_vk, signer="alice@example.com"):
    reg = TrustedSignerRegistry()
    reg.add_signer(signer, signer_vk, created_when=FIXED)
    return reg


# --------------------------------------------------------------------------- #
# Task 2: registry seal create / verify
# --------------------------------------------------------------------------- #
class TestRegistrySeal(unittest.TestCase):
    def test_valid_registry_seal_verifies(self):
        _, signer_vk = generate_signing_keypair()
        root_sk, root_vk = generate_signing_keypair()
        reg = _registry_with(signer_vk)
        rseal = seal_registry(reg, root_sk, signer="root@example.com", sealed_when=FIXED)
        ok, reason = verify_registry_seal(reg, rseal, root_vk)
        self.assertTrue(ok, reason)
        self.assertEqual(rseal["payload"]["subject"], "signer-registry")
        self.assertEqual(rseal["payload"]["content_hash"], reg.registry_hash())

    def test_added_entry_breaks_seal(self):
        _, signer_vk = generate_signing_keypair()
        _, other_vk = generate_signing_keypair()
        root_sk, root_vk = generate_signing_keypair()
        reg = _registry_with(signer_vk)
        rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
        reg.add_signer("mallory@evil.test", other_vk, created_when=FIXED)  # tamper
        ok, reason = verify_registry_seal(reg, rseal, root_vk)
        self.assertFalse(ok)
        self.assertIn("hash mismatch", reason)

    def test_flip_revoked_to_trusted_breaks_seal(self):
        _, signer_vk = generate_signing_keypair()
        root_sk, root_vk = generate_signing_keypair()
        reg = TrustedSignerRegistry()
        entry = reg.add_signer("bob@example.com", signer_vk, created_when=FIXED)
        reg.revoke(entry.key_fingerprint, revoked_when=FIXED)
        rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
        # Attacker un-revokes by re-adding the same key as trusted.
        reg.add_signer("bob@example.com", signer_vk, created_when=FIXED)
        ok, reason = verify_registry_seal(reg, rseal, root_vk)
        self.assertFalse(ok)
        self.assertIn("hash mismatch", reason)

    def test_non_root_key_rejected(self):
        _, signer_vk = generate_signing_keypair()
        root_sk, _ = generate_signing_keypair()
        _, wrong_root_vk = generate_signing_keypair()
        reg = _registry_with(signer_vk)
        rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
        ok, reason = verify_registry_seal(reg, rseal, wrong_root_vk)
        self.assertFalse(ok)
        self.assertIn("key fingerprint", reason)

    def test_manifest_seal_not_accepted_as_registry_seal(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            _, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            manifest_seal = seal_manifest(m, root_sk, signer="root", sealed_when=FIXED)
            ok, reason = verify_registry_seal(reg, manifest_seal, root_vk)
            self.assertFalse(ok)
            self.assertIn("subject", reason)

    def test_registry_seal_not_accepted_as_manifest_seal(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            _, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
            ok, reason = verify_sealed_manifest(m, rseal, root_vk)
            self.assertFalse(ok)
            self.assertIn("subject", reason)


# --------------------------------------------------------------------------- #
# Task 3: signed-registry load + end-to-end verification (fail-closed)
# --------------------------------------------------------------------------- #
def _persist_signed_registry(d, registry, root_sk):
    """Write registry + its root seal to disk; return (registry_path, seal_path)."""
    reg_path = Path(d) / "registry.json"
    seal_path = Path(d) / "registry.seal.json"
    save_registry(registry, reg_path)
    write_seal(seal_registry(registry, root_sk, signer="root@example.com", sealed_when=FIXED), seal_path)
    return reg_path, seal_path


class TestSignedRegistryLoad(unittest.TestCase):
    def test_load_signed_registry_valid(self):
        with tempfile.TemporaryDirectory() as d:
            _, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg_path, seal_path = _persist_signed_registry(d, reg, root_sk)
            loaded = load_signed_registry(reg_path, seal_path, root_vk)
            self.assertEqual(loaded.registry_hash(), reg.registry_hash())

    def test_missing_registry_seal_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            _, signer_vk = generate_signing_keypair()
            _, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg_path = Path(d) / "registry.json"
            save_registry(reg, reg_path)
            missing = Path(d) / "does-not-exist.seal.json"
            with self.assertRaises(RegistryError):
                load_signed_registry(reg_path, missing, root_vk)

    def test_tampered_registry_file_fails_to_load(self):
        # The G1 attack, on disk: flip revoked->trusted after sealing.
        with tempfile.TemporaryDirectory() as d:
            _, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = TrustedSignerRegistry()
            entry = reg.add_signer("bob@example.com", signer_vk, created_when=FIXED)
            reg.revoke(entry.key_fingerprint, revoked_when=FIXED)
            reg_path, seal_path = _persist_signed_registry(d, reg, root_sk)
            # Attacker edits the file to un-revoke.
            data = json.loads(reg_path.read_text())
            data["signers"][0]["status"] = "trusted"
            data["signers"][0]["revoked_at"] = None
            reg_path.write_text(json.dumps(data))
            with self.assertRaises(RegistryError):
                load_signed_registry(reg_path, seal_path, root_vk)

    def test_end_to_end_trusted_when_both_verify(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            signer_sk, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg_path, seal_path = _persist_signed_registry(d, reg, root_sk)
            manifest_seal = seal_manifest(m, signer_sk, signer="alice@example.com", sealed_when=FIXED)
            res = verify_sealed_manifest_with_signed_registry(
                m, manifest_seal, reg_path, seal_path, root_vk
            )
            self.assertIs(res.outcome, Outcome.TRUSTED, res.reason)
            self.assertEqual(res.signer, "alice@example.com")

    def test_registry_seal_failure_dominates_valid_manifest(self):
        # Manifest seal is perfectly valid, but the registry's root seal is broken by
        # tampering the registry file -> UNTRUSTED (registry not trusted) wins.
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            signer_sk, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg_path, seal_path = _persist_signed_registry(d, reg, root_sk)
            manifest_seal = seal_manifest(m, signer_sk, signer="alice@example.com", sealed_when=FIXED)
            # Tamper the registry file (add an attacker entry) — breaks the root seal.
            data = json.loads(reg_path.read_text())
            data["signers"][0]["signer"] = "attacker@evil.test"
            reg_path.write_text(json.dumps(data))
            res = verify_sealed_manifest_with_signed_registry(
                m, manifest_seal, reg_path, seal_path, root_vk
            )
            self.assertIs(res.outcome, Outcome.UNTRUSTED)
            self.assertIn("registry not trusted", res.reason)

    def test_malformed_registry_seal_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            signer_sk, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg_path = Path(d) / "registry.json"
            save_registry(reg, reg_path)
            bad_seal = Path(d) / "registry.seal.json"
            bad_seal.write_text("{ this is not valid json")
            manifest_seal = seal_manifest(m, signer_sk, signer="alice@example.com", sealed_when=FIXED)
            res = verify_sealed_manifest_with_signed_registry(
                m, manifest_seal, reg_path, bad_seal, root_vk
            )
            self.assertIs(res.outcome, Outcome.UNTRUSTED)
            with self.assertRaises(RegistryError):
                load_signed_registry(reg_path, bad_seal, root_vk)


# --------------------------------------------------------------------------- #
# Phase 1G2: rollback enforcement — min_sequence floor (verify side, fail-closed)
# --------------------------------------------------------------------------- #
class TestRegistryRollbackFloor(unittest.TestCase):
    def test_default_floor_preserves_behavior(self):
        # No floor passed (min_sequence=0) => existing behavior, sequence-0 registry ok.
        _, signer_vk = generate_signing_keypair()
        root_sk, root_vk = generate_signing_keypair()
        reg = _registry_with(signer_vk)  # sequence 0
        rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
        ok, reason = verify_registry_seal(reg, rseal, root_vk)
        self.assertTrue(ok, reason)

    def test_verify_registry_seal_accepts_at_or_above_floor(self):
        _, signer_vk = generate_signing_keypair()
        root_sk, root_vk = generate_signing_keypair()
        reg = _registry_with(signer_vk)
        reg.bump(5)
        rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
        ok_eq, r_eq = verify_registry_seal(reg, rseal, root_vk, min_sequence=5)
        self.assertTrue(ok_eq, r_eq)
        ok_gt, r_gt = verify_registry_seal(reg, rseal, root_vk, min_sequence=4)
        self.assertTrue(ok_gt, r_gt)

    def test_verify_registry_seal_rejects_below_floor(self):
        _, signer_vk = generate_signing_keypair()
        root_sk, root_vk = generate_signing_keypair()
        reg = _registry_with(signer_vk)
        reg.bump(1)
        rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
        ok, reason = verify_registry_seal(reg, rseal, root_vk, min_sequence=2)
        self.assertFalse(ok)
        self.assertIn("below floor", reason)

    def test_verify_against_registry_floor(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            signer_sk, signer_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg.bump(1)
            manifest_seal = seal_manifest(m, signer_sk, signer="alice@example.com", sealed_when=FIXED)
            ok = verify_against_registry(m, manifest_seal, reg, min_sequence=1)
            self.assertIs(ok.outcome, Outcome.TRUSTED, ok.reason)
            rej = verify_against_registry(m, manifest_seal, reg, min_sequence=2)
            self.assertIs(rej.outcome, Outcome.UNTRUSTED)
            self.assertIn("below floor", rej.reason)

    def test_load_signed_registry_rejects_below_floor(self):
        with tempfile.TemporaryDirectory() as d:
            _, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg.bump(1)
            reg_path, seal_path = _persist_signed_registry(d, reg, root_sk)
            with self.assertRaises(RegistryError):
                load_signed_registry(reg_path, seal_path, root_vk, min_sequence=2)
            loaded = load_signed_registry(reg_path, seal_path, root_vk, min_sequence=1)
            self.assertEqual(loaded.sequence, 1)

    def test_floor_rejects_sequence_zero_registry(self):
        # SC5-adjacent: a floor > 0 refuses a sequence-0 registry (no silent trust of a
        # registry that predates sequence tracking).
        with tempfile.TemporaryDirectory() as d:
            _, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)  # sequence 0
            reg_path, seal_path = _persist_signed_registry(d, reg, root_sk)
            with self.assertRaises(RegistryError):
                load_signed_registry(reg_path, seal_path, root_vk, min_sequence=1)

    def test_invalid_floor_fails_closed(self):
        # A misconfigured floor (non-int/negative) must fail closed, never raise out of a
        # "never raises" verifier and never silently coerce.
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            signer_sk, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg = _registry_with(signer_vk)
            reg.bump(1)
            rseal = seal_registry(reg, root_sk, signer="root", sealed_when=FIXED)
            manifest_seal = seal_manifest(m, signer_sk, signer="alice@example.com", sealed_when=FIXED)
            for bad in (None, -1, 2.5, True, "1"):
                ok, reason = verify_registry_seal(reg, rseal, root_vk, min_sequence=bad)
                self.assertFalse(ok, f"floor {bad!r} should fail closed")
                self.assertIn("floor", reason)
                res = verify_against_registry(m, manifest_seal, reg, min_sequence=bad)
                self.assertIs(res.outcome, Outcome.UNTRUSTED, f"floor {bad!r}")

    def test_rollback_replay_defeated_end_to_end(self):
        # SC3: an older, validly root-signed registry replayed against a raised floor is
        # rejected — its stale trust content cannot be resurrected without the root key.
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            signer_sk, signer_vk = generate_signing_keypair()
            root_sk, root_vk = generate_signing_keypair()
            reg1 = _registry_with(signer_vk)  # revision 1: alice trusted
            reg1.bump(1)
            reg_path, seal_path = _persist_signed_registry(d, reg1, root_sk)
            manifest_seal = seal_manifest(m, signer_sk, signer="alice@example.com", sealed_when=FIXED)
            # At the matching floor the (old) revision is trusted...
            good = verify_sealed_manifest_with_signed_registry(
                m, manifest_seal, reg_path, seal_path, root_vk, min_sequence=1
            )
            self.assertIs(good.outcome, Outcome.TRUSTED, good.reason)
            # ...but once the org has advanced to sequence 2, replaying revision 1 fails.
            replay = verify_sealed_manifest_with_signed_registry(
                m, manifest_seal, reg_path, seal_path, root_vk, min_sequence=2
            )
            self.assertIs(replay.outcome, Outcome.UNTRUSTED)
            self.assertIn("below floor", replay.reason)


if __name__ == "__main__":
    unittest.main()
