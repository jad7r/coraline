"""
Phase 1A move-verification.

Proves the cryptographic evidence subsystem was relocated cleanly: it is importable
and isolated under `core.evidence.integrity`, exposes its public API, and carries no
residual dependency on the legacy top-level `enclave` package.

These tests intentionally assert *structure*, not crypto behavior — the behavior is
covered by test_crypto / test_envelope / test_identity (lifted unchanged).
"""

import importlib
import unittest


MODULES = ("crypto", "envelope", "identity", "keystore", "signing")


class TestPackageLayout(unittest.TestCase):
    def test_canonical_imports(self):
        """Every module imports via the new canonical path."""
        for name in MODULES:
            importlib.import_module(f"core.evidence.integrity.{name}")

    def test_no_legacy_enclave_package(self):
        """The move must not rely on a top-level `enclave` package existing."""
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module("enclave")

    def test_public_symbols_present(self):
        """Public API survived the relocation (names taken from the real modules)."""
        crypto = importlib.import_module("core.evidence.integrity.crypto")
        for sym in ("generate_keypair", "generate_dek", "encrypt_content",
                    "decrypt_content", "seal_dek", "unseal_dek",
                    "encode_public_key", "decode_public_key",
                    "encode_private_key", "decode_private_key", "CryptoError"):
            self.assertTrue(hasattr(crypto, sym), f"crypto.{sym} missing after move")

        envelope = importlib.import_module("core.evidence.integrity.envelope")
        for sym in ("create_envelope", "open_envelope", "Envelope",
                    "Recipient", "EnvelopeError"):
            self.assertTrue(hasattr(envelope, sym), f"envelope.{sym} missing after move")

        identity = importlib.import_module("core.evidence.integrity.identity")
        for sym in ("UserContext", "create_user_context"):
            self.assertTrue(hasattr(identity, sym), f"identity.{sym} missing after move")

    def test_no_presentation_dependencies(self):
        """The crypto core must not import any presentation/publishing layer."""
        import sys
        for name in MODULES:
            importlib.import_module(f"core.evidence.integrity.{name}")
        forbidden = ("enclave_wp", "PySide6", "PyQt5", "PyQt6", "requests", "flask")
        loaded = set(sys.modules)
        for mod in forbidden:
            self.assertNotIn(mod, loaded,
                             f"crypto core unexpectedly pulled in '{mod}'")


if __name__ == "__main__":
    unittest.main()
