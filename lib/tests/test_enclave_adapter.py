"""Tests for lib.enclave_adapter.EnclaveAdapter — Ed25519 sign/verify + tamper detection."""
from __future__ import annotations

import pytest

from lib.enclave_adapter import ALGORITHM, EnclaveAdapter, EnclaveAdapterError, canonicalize


def make(fake_keyring):
    return EnclaveAdapter(key_id="test", keyring_backend=fake_keyring)


def test_sign_returns_expected_envelope_shape(fake_keyring):
    adapter = make(fake_keyring)
    env = adapter.sign({"hello": "world"})
    assert set(env) == {"signature", "public_key", "algorithm"}
    assert env["algorithm"] == ALGORITHM
    assert isinstance(env["signature"], str) and env["signature"]
    assert isinstance(env["public_key"], str) and env["public_key"]


def test_sign_then_verify_roundtrip_dict(fake_keyring):
    adapter = make(fake_keyring)
    payload = {"b": 2, "a": 1}
    env = adapter.sign(payload)
    assert EnclaveAdapter.verify(payload, env["signature"], env["public_key"]) is True


def test_sign_then_verify_roundtrip_bytes(fake_keyring):
    adapter = make(fake_keyring)
    payload = b"raw evidence bytes"
    env = adapter.sign(payload)
    assert EnclaveAdapter.verify(payload, env["signature"], env["public_key"]) is True


def test_tamper_one_byte_fails_verification(fake_keyring):
    adapter = make(fake_keyring)
    payload = {"indicator": "1.2.3.4", "verdict": "malicious"}
    env = adapter.sign(payload)

    # Mutate one byte of the signed payload -> must fail.
    tampered = dict(payload)
    tampered["verdict"] = "malicioux"  # single-char change
    assert EnclaveAdapter.verify(tampered, env["signature"], env["public_key"]) is False


def test_tamper_signature_fails(fake_keyring):
    adapter = make(fake_keyring)
    payload = {"x": 1}
    env = adapter.sign(payload)
    # Flip a character in the base64 signature.
    sig = env["signature"]
    bad = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert EnclaveAdapter.verify(payload, bad, env["public_key"]) is False


def test_wrong_public_key_fails(fake_keyring):
    a1 = EnclaveAdapter(key_id="k1", keyring_backend=fake_keyring)
    a2 = EnclaveAdapter(key_id="k2", keyring_backend=fake_keyring)
    env = a1.sign({"x": 1})
    other_pk = a2.public_key()
    assert EnclaveAdapter.verify({"x": 1}, env["signature"], other_pk) is False


def test_dict_key_order_does_not_affect_signature(fake_keyring):
    adapter = make(fake_keyring)
    env = adapter.sign({"a": 1, "b": 2})
    # Verify against a differently-ordered but equal dict.
    assert EnclaveAdapter.verify({"b": 2, "a": 1}, env["signature"], env["public_key"])


def test_key_is_generated_and_persisted_once(fake_keyring):
    adapter = make(fake_keyring)
    pk1 = adapter.public_key()
    pk2 = adapter.public_key()
    assert pk1 == pk2  # stable across calls
    # A fresh adapter with the same key_id reuses the stored key.
    pk3 = EnclaveAdapter(key_id="test", keyring_backend=fake_keyring).public_key()
    assert pk3 == pk1


def test_malformed_verify_inputs_fail_closed(fake_keyring):
    adapter = make(fake_keyring)
    env = adapter.sign({"x": 1})
    assert EnclaveAdapter.verify({"x": 1}, "!!!not-base64!!!", env["public_key"]) is False
    assert EnclaveAdapter.verify({"x": 1}, env["signature"], "not-a-key") is False


def test_empty_key_id_rejected(fake_keyring):
    with pytest.raises(EnclaveAdapterError):
        EnclaveAdapter(key_id="  ", keyring_backend=fake_keyring)


def test_canonicalize_rejects_bad_type():
    with pytest.raises(TypeError):
        canonicalize(12345)  # not bytes or dict
