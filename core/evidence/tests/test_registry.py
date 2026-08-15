"""Tests for the trusted signer registry (fail-closed trust decisions)."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.evidence.integrity.signing import (
    encode_verify_key,
    generate_signing_keypair,
    key_fingerprint,
)
from core.evidence.manifest import build_manifest
from core.evidence.registry import (
    Outcome,
    RegistryError,
    TrustedSignerRegistry,
    load_registry,
    save_registry,
    verify_against_registry,
    verify_with_registry_file,
)
from core.evidence.seal import seal_manifest

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


def _manifest(d):
    p = Path(d) / "a.log"
    p.write_bytes(b"hello evidence")
    return build_manifest("sec-ir-2026-07-06-test", [p], "alice@example.com", FIXED)


class TestRegistry(unittest.TestCase):
    # -- the six required outcomes ----------------------------------------- #
    def test_trusted_signer_succeeds(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            reg = TrustedSignerRegistry()
            reg.add_signer("alice@example.com", vk, created_when=FIXED)
            seal = seal_manifest(m, sk, signer="alice@example.com", sealed_when=FIXED)
            res = verify_against_registry(m, seal, reg)
            self.assertTrue(res.trusted, res.reason)
            self.assertIs(res.outcome, Outcome.TRUSTED)
            self.assertEqual(res.signer, "alice@example.com")

    def test_unknown_signer_fails(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk_a, vk_a = generate_signing_keypair()
            sk_b, _ = generate_signing_keypair()  # b is not registered
            reg = TrustedSignerRegistry()
            reg.add_signer("alice", vk_a, created_when=FIXED)
            seal = seal_manifest(m, sk_b, signer="mallory", sealed_when=FIXED)
            res = verify_against_registry(m, seal, reg)
            self.assertIs(res.outcome, Outcome.UNKNOWN)
            self.assertFalse(res.trusted)

    def test_revoked_signer_fails(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            reg = TrustedSignerRegistry()
            entry = reg.add_signer("alice", vk, created_when=FIXED)
            reg.revoke(entry.key_fingerprint, revoked_when=FIXED)
            seal = seal_manifest(m, sk, signer="alice", sealed_when=FIXED)
            res = verify_against_registry(m, seal, reg)
            self.assertIs(res.outcome, Outcome.REVOKED)
            self.assertFalse(res.trusted)

    def test_fingerprint_mismatch_fails(self):
        # Entry indexed under A's fingerprint but storing B's key (a swapped-key tamper).
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk_a, vk_a = generate_signing_keypair()
            _, vk_b = generate_signing_keypair()
            entry = {
                "signer": "alice",
                "verify_key": encode_verify_key(vk_b),        # B's key ...
                "key_fingerprint": key_fingerprint(vk_a),     # ... but A's fingerprint
                "status": "trusted",
                "created_at": "2026-07-06T14:30:00Z",
                "revoked_at": None,
            }
            reg = TrustedSignerRegistry.from_dict({"version": "1", "signers": [entry]})
            seal = seal_manifest(m, sk_a, signer="alice", sealed_when=FIXED)  # payload fp = A
            res = verify_against_registry(m, seal, reg)
            self.assertIs(res.outcome, Outcome.UNTRUSTED)
            self.assertIn("fingerprint mismatch", res.reason)

    def test_tampered_registry_entry_fails_when_pinned(self):
        # Pin a known-good registry hash; any on-disk edit (even a consistent one) fails.
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            reg = TrustedSignerRegistry()
            reg.add_signer("alice", vk, created_when=FIXED)
            path = Path(d) / "registry.json"
            good_hash = save_registry(reg, path)
            seal = seal_manifest(m, sk, signer="alice", sealed_when=FIXED)

            # Pinned + untampered -> trusted
            self.assertIs(
                verify_with_registry_file(m, seal, path, expected_hash=good_hash).outcome,
                Outcome.TRUSTED,
            )
            # Tamper the file (rename the signer), reload pinned -> fail closed
            data = json.loads(path.read_text())
            data["signers"][0]["signer"] = "attacker"
            path.write_text(json.dumps(data))
            res = verify_with_registry_file(m, seal, path, expected_hash=good_hash)
            self.assertIs(res.outcome, Outcome.UNTRUSTED)
            self.assertIn("registry", res.reason.lower())

    def test_malformed_registry_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, _ = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="alice", sealed_when=FIXED)
            path = Path(d) / "registry.json"
            bad_registries = [
                "{ not valid json",
                '{"version":"1"}',                                  # missing 'signers'
                '{"version":"1","signers":"nope"}',                 # signers not a list
                '{"version":"1","signers":[{"signer":"a"}]}',       # entry missing fields
                '{"version":"1","signers":[{"signer":"a","verify_key":"!!not-base64!!",'
                '"key_fingerprint":"SHA256:x","status":"trusted","created_at":"t"}]}',
                '{"version":"1","signers":[{"signer":"a","verify_key":"AA==",'
                '"key_fingerprint":"SHA256:x","status":"bogus","created_at":"t"}]}',
            ]
            for text in bad_registries:
                path.write_text(text)
                res = verify_with_registry_file(m, seal, path)
                self.assertIs(res.outcome, Outcome.UNTRUSTED, text)  # never trusted, never crash
                with self.assertRaises(RegistryError):
                    load_registry(path)

    # -- determinism / persistence ----------------------------------------- #
    def test_deterministic_regardless_of_add_order(self):
        _, vk1 = generate_signing_keypair()
        _, vk2 = generate_signing_keypair()
        r1 = TrustedSignerRegistry()
        r1.add_signer("a", vk1, created_when=FIXED)
        r1.add_signer("b", vk2, created_when=FIXED)
        r2 = TrustedSignerRegistry()
        r2.add_signer("b", vk2, created_when=FIXED)
        r2.add_signer("a", vk1, created_when=FIXED)
        self.assertEqual(r1.to_json(), r2.to_json())
        self.assertEqual(r1.registry_hash(), r2.registry_hash())

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            _, vk = generate_signing_keypair()
            reg = TrustedSignerRegistry()
            reg.add_signer("alice", vk, created_when=FIXED)
            path = Path(d) / "registry.json"
            h = save_registry(reg, path)
            loaded = load_registry(path, expected_hash=h)
            self.assertEqual(loaded.to_json(), reg.to_json())
            self.assertEqual(loaded.registry_hash(), h)


# --------------------------------------------------------------------------- #
# Phase 1G2: monotonic sequence data model (anti-rollback authoring side)
# --------------------------------------------------------------------------- #
class TestRegistrySequence(unittest.TestCase):
    def test_sequence_defaults_to_zero_and_is_in_dict(self):
        reg = TrustedSignerRegistry()
        self.assertEqual(reg.sequence, 0)
        self.assertEqual(reg.to_dict()["sequence"], 0)

    def test_sequence_is_signed_content(self):
        # Changing the sequence must change registry_hash() so it is covered by the
        # root seal (SC1). Same signers, different sequence -> different hash.
        _, vk = generate_signing_keypair()
        reg = TrustedSignerRegistry()
        reg.add_signer("alice", vk, created_when=FIXED)
        h0 = reg.registry_hash()
        reg.bump(5)
        self.assertEqual(reg.to_dict()["sequence"], 5)
        self.assertNotEqual(reg.registry_hash(), h0)

    def test_bump_requires_strictly_increasing(self):
        reg = TrustedSignerRegistry()
        reg.bump(3)
        self.assertEqual(reg.sequence, 3)
        with self.assertRaises(RegistryError):
            reg.bump(3)  # equal is not strictly greater
        with self.assertRaises(RegistryError):
            reg.bump(2)  # lower
        self.assertEqual(reg.sequence, 3)  # unchanged after a rejected bump

    def test_bump_rejects_non_integer(self):
        reg = TrustedSignerRegistry()
        with self.assertRaises(RegistryError):
            reg.bump(True)  # bool is not a valid sequence
        with self.assertRaises(RegistryError):
            reg.bump("1")

    def test_mutations_do_not_auto_advance_sequence(self):
        # Accepted decision (open question 1): explicit bump() per signed revision;
        # add_signer/revoke never touch the sequence on their own.
        _, vk = generate_signing_keypair()
        reg = TrustedSignerRegistry()
        entry = reg.add_signer("alice", vk, created_when=FIXED)
        self.assertEqual(reg.sequence, 0)
        reg.revoke(entry.key_fingerprint, revoked_when=FIXED)
        self.assertEqual(reg.sequence, 0)

    def test_from_dict_defaults_sequence_zero_when_absent(self):
        # Backward-compatible parse: a legacy registry dict with no 'sequence' loads at 0.
        _, vk = generate_signing_keypair()
        reg = TrustedSignerRegistry()
        reg.add_signer("alice", vk, created_when=FIXED)
        d = reg.to_dict()
        del d["sequence"]
        loaded = TrustedSignerRegistry.from_dict(d)
        self.assertEqual(loaded.sequence, 0)

    def test_from_dict_roundtrips_sequence(self):
        _, vk = generate_signing_keypair()
        reg = TrustedSignerRegistry()
        reg.add_signer("alice", vk, created_when=FIXED)
        reg.bump(7)
        loaded = TrustedSignerRegistry.from_dict(reg.to_dict())
        self.assertEqual(loaded.sequence, 7)
        self.assertEqual(loaded.registry_hash(), reg.registry_hash())

    def test_from_dict_rejects_non_integer_sequence(self):
        with self.assertRaises(RegistryError):
            TrustedSignerRegistry.from_dict({"version": "1", "sequence": "5", "signers": []})
        with self.assertRaises(RegistryError):
            TrustedSignerRegistry.from_dict({"version": "1", "sequence": True, "signers": []})

    def test_from_dict_rejects_negative_sequence(self):
        with self.assertRaises(RegistryError):
            TrustedSignerRegistry.from_dict({"version": "1", "sequence": -1, "signers": []})

    def test_constructor_rejects_invalid_sequence(self):
        # The constructor validates like from_dict, so the negative/non-int invariant
        # holds at construction, not only on the load path.
        with self.assertRaises(RegistryError):
            TrustedSignerRegistry(sequence=-3)
        with self.assertRaises(RegistryError):
            TrustedSignerRegistry(sequence=True)
        with self.assertRaises(RegistryError):
            TrustedSignerRegistry(sequence="1")


if __name__ == "__main__":
    unittest.main()
