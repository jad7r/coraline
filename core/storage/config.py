"""
Environment-scoped evidence-bucket resolution (Phase 1H Task 4).

Production evidence lives in a retention-**LOCKED** bucket (7-year). Tests/CI must NEVER
target it — a locked bucket accrues undeletable objects for the full retention period. The
bucket name is therefore resolved from the environment with **no production default**: an
unset value fails loud rather than silently writing to prod.

Bucket provisioning and the retention lock itself are **ops (Terraform) concerns** — this
module only *selects* a name and *guards* against accidental prod use.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

ENV_VAR = "CORELINE_EVIDENCE_BUCKET"
# Reference name of the production locked bucket — used only as a safety guard so tooling
# can refuse to run destructive/accruing operations (e.g. the smoke test) against it.
# NOTE: this is the BUCKET name (globally unique, lowercase), NOT the GCP project. The
# project is `coreline-audit` (where Google SecOps+ runs); the client picks the project up
# from its ambient (WIF/ADC) identity, so only the bucket name lives here.
PROD_LOCKED_BUCKET = "coreline-audit-ir-evidence"


class StorageConfigError(Exception):
    """Evidence bucket is not configured (fail-loud; there is no production default)."""


def resolve_evidence_bucket(env: Optional[Mapping[str, str]] = None) -> str:
    """Return the configured evidence bucket, or raise. Never defaults to prod."""
    env = os.environ if env is None else env
    bucket = (env.get(ENV_VAR) or "").strip()
    if not bucket:
        raise StorageConfigError(
            f"{ENV_VAR} is not set. Set it explicitly per environment — prod: the locked "
            f"{PROD_LOCKED_BUCKET!r} bucket; test/staging: an UN-locked bucket. No production "
            f"default exists; refusing to guess."
        )
    return bucket


def is_prod_locked_bucket(name: str) -> bool:
    """True if ``name`` is the production locked bucket (a safety guard for tooling).

    Guards the ONE known prod bucket name — not the general property "is retention-locked".
    A second locked bucket under a different name would not be caught here; the primary
    safety control is ``resolve_evidence_bucket`` failing loud with no prod default.
    """
    return name.strip() == PROD_LOCKED_BUCKET
