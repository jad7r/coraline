# `core/evidence/integrity/` — cryptographic evidence subsystem (PyNaCl)

Platform-native, reusable, **presentation-free** cryptographic evidence handling.

## Provenance
Lifted verbatim in Phase 0 from `CORELINE_OLD_DESIGN/archive/secops-secure-enclave/enclave/`
(the prior "secure enclave"). The original is preserved in the fossil snapshot and in git
restore point `c54cd6d`. The WordPress client, portal, and portal GUI that used to sit
around this code were **deleted** — they were an alpha example presentation layer and are
explicitly out of scope (ADR-0002 §5).

## Modules
- `crypto.py` — PyNaCl primitives: X25519, XSalsa20-Poly1305 (authenticated encryption), SealedBox
- `envelope.py` — multi-recipient sealed-DEK envelope (bundle) format + serialization
- `identity.py` — user-context stub (Okta integration out of scope)
- `keystore.py` — private-key storage via OS keychain (pluggable)
- `signing.py` — **added Phase 1C:** Ed25519 detached sign/verify (fail-closed) + key
  fingerprints; used by `core.evidence.seal` to seal manifests
- `tests/` — `test_crypto.py`, `test_envelope.py`, `test_identity.py`, `test_signing.py`,
  `test_package_layout.py`

> Note: the original enclave's Ed25519 *directory* signing lived in the deleted WordPress
> GUI; `signing.py` is a fresh, presentation-free Ed25519 helper built on the same PyNaCl
> dependency.

## Intended responsibilities (target — see ADR-0002)
encrypted evidence bundles · SHA-256 integrity hashing · manifest generation ·
chain-of-custody metadata · key handling · local/offline first · future API/UI as a
separate consumer.

## Status — Phase 1A complete (imports reconciled, tests pass)
The legacy `enclave.*` imports were rewritten to `core.evidence.integrity.*`; the
subsystem now imports cleanly at this path and is isolated (no `enclave` package, no
presentation/HTTP deps). Verified by **30 passing tests**.

Run the tests from the repo root:

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r core/evidence/integrity/requirements.txt pytest
./.venv/bin/python -m pytest core/evidence/integrity/tests/ -q
```

Deps: see `requirements.txt` (PyNaCl, keyring — presentation-free).

**Deferrals (unchanged):** production deployment awaits a third-party crypto review (per
the subsystem's own docs). Baseline integrity features (SHA-256 hashing, manifest,
chain-of-custody) are **not** built yet — later Phase 1 work.

## Known follow-up
- `keystore.py` still stores keys under keyring service name `secops-secure-enclave`.
  Left unchanged in Phase 1A (it's a stored-data identifier, not an import); revisit when
  we decide the platform's canonical keyring namespace.
