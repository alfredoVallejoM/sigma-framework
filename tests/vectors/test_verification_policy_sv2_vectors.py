from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import PolicySymlinkModeV1, VerificationPolicyV1

VECTOR_PATH = (
    Path(__file__).parents[2]
    / "specification"
    / "test-vectors"
    / "sigma-verification-policy-v1.json"
)


def _policies() -> dict[str, VerificationPolicyV1]:
    all_suites = (
        SuiteIdV3.REFERENCE_IAP_V3,
        SuiteIdV3.DEEP_V3,
        SuiteIdV3.DEEP_VECTOR_V3,
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        SuiteIdV3.DEEP_HISTORY_V3,
        SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
    )
    return {
        "default": VerificationPolicyV1(),
        "strict-history-audit": VerificationPolicyV1(
            allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
            require_history_feedback=True,
            require_message_binding=True,
            require_audit=True,
            max_input_bytes=1024,
            max_trajectory_rounds=64,
            allowed_artifact_metadata_profiles=(1,),
            symlink_mode=PolicySymlinkModeV1.REJECT,
        ),
        "weak-all-v3": VerificationPolicyV1(
            allowed_v3_suites=all_suites,
            require_history_feedback=False,
            allow_legacy_v22=True,
            require_message_binding=False,
            require_audit=False,
            allow_tree_only_artifacts=True,
            max_input_bytes=1 << 20,
            max_trajectory_rounds=1024,
            allowed_artifact_metadata_profiles=(1, 2),
            symlink_mode=PolicySymlinkModeV1.TEXT,
        ),
        "legacy-opt-in": VerificationPolicyV1(
            allowed_v3_suites=(),
            require_history_feedback=False,
            allow_legacy_v22=True,
            require_message_binding=True,
        ),
    }


def test_verification_policy_v1_kats():
    document = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert document["schema"] == "sigma-verification-policy-v1-kat"
    policies = _policies()
    assert {case["name"] for case in document["cases"]} == set(policies)

    for case in document["cases"]:
        policy = policies[case["name"]]
        wire = policy.to_bytes()
        assert VerificationPolicyV1.from_bytes(wire) == policy
        assert len(wire) == case["wire_bytes"]
        assert hashlib.sha256(wire).hexdigest() == case["policy_id_sha256"]
        assert policy.policy_id.hex() == case["policy_id_sha256"]
