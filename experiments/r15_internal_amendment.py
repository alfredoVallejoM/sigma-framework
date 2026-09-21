"""Constants and invariants for the pre-execution R15 internal amendment.

Source-isolation note: this amendment is intentionally independent of the
post-freeze Wave 2/Wave 3A controllers and application-engineering tooling.
"""

from __future__ import annotations

from experiments.r141_protocol import R141_FREEZE_ID

AMENDMENT_ID = "sigma-v3-r15-internal-amendment-20260921-v1"
AMENDMENT_TAG = "sigma-v3-r15-internal-amendment-v1"

BASE_TAG = "sigma-v3-r14-freeze-v1"
BASE_SOURCE_COMMIT = "80214afde29b3596af83265e18c1e2926e14dd2f"
BASE_SOURCE_TREE = "ca1da75d6409f39a8a1f1b6fa4afea42830781e1"
BASE_CONFIG_MANIFEST_SHA256 = "a8b1b4c9d3a2218e284605a2be02165a2ae36d2a0a8f0aed3223a3b41d6d59e3"
BASE_PREREGISTRATION_SHA256 = "34b256560c74fde95a0d788894d4f27ff4b13b7eadba318321840cf5fe5a7c2a"
BASE_DEPENDENCY_LOCK_SHA256 = "80a64b9564aead53a5a0abe69adae7c431741948c9cd6eeab280544a5a3b3ba2"

AMENDED_ATTACKS = ("RED-04", "PARAM-02")
EXPECTED_RUN_UNITS = 11_392

# Seed derivation remains derive_confirmatory_seed_r141, hence the original
# freeze id/namespace and every RunKey remain unchanged.
FREEZE_ID = R141_FREEZE_ID


__all__ = [
    "AMENDED_ATTACKS",
    "AMENDMENT_ID",
    "AMENDMENT_TAG",
    "BASE_CONFIG_MANIFEST_SHA256",
    "BASE_DEPENDENCY_LOCK_SHA256",
    "BASE_PREREGISTRATION_SHA256",
    "BASE_SOURCE_COMMIT",
    "BASE_SOURCE_TREE",
    "BASE_TAG",
    "EXPECTED_RUN_UNITS",
    "FREEZE_ID",
]
