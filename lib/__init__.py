"""
``lib`` — shared support layer for Coreline services (Unit 6, ADR-0003 follow-up).

This package was removed in an earlier restructure; the revived archived services
(``archive/experimental/grafana-webhook`` and friends) import it directly, e.g.::

    from lib.grafana_irm import GrafanaToCorelineSync
    from lib.storage import JSONLStorage

It is deliberately thin, deterministic, and offline-first:

- :mod:`lib.storage`        — append-only JSONL storage.
- :mod:`lib.grafana_irm`    — Grafana IRM webhook -> Coreline incident-action mapping (pure).
- :mod:`lib.vt_lookup`      — VirusTotal client (HTTP injectable; key from keychain/env).
- :mod:`lib.misp_client`    — MISP client (HTTP injectable; key from keychain/env).
- :mod:`lib.enclave_adapter`— Ed25519 signing over PyNaCl (reuses ``core.evidence.integrity``).

No module here writes system-of-record state, embeds a secret, or requires the network at
import time. Crypto reuses ``core/evidence/integrity`` rather than duplicating primitives.
"""

__all__ = [
    "storage",
    "grafana_irm",
    "vt_lookup",
    "misp_client",
    "enclave_adapter",
]
