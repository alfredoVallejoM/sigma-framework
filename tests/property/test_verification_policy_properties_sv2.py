from __future__ import annotations

import random

from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    PolicySymlinkModeV1,
    TrajectoryAuditModeV3,
    VerificationPolicyV1,
    audit_from_evaluation_v3,
    policy_is_stricter_or_equal_v1,
    verify_with_policy_v1,
)
from sigma.v3 import evaluate_v3

HISTORY_SUITES = (
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)
ALL_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    *HISTORY_SUITES,
)


def _audit(message: bytes, suite_id: SuiteIdV3):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=b"sv2-property",
        challenge=b"policy",
        application_context=b"tests/property/sv2",
    )
    return audit_from_evaluation_v3(
        evaluate_v3(context, BytesSource(message)),
        mode=TrajectoryAuditModeV3.COMPACT,
    )


def test_generated_policy_decisions_are_repeatable():
    rng = random.Random(0x53563250524F50)
    audit = _audit(b"repeatable", SuiteIdV3.REFERENCE_IAP_HISTORY_V3)

    for _ in range(200):
        allowed = tuple(
            sorted(
                (suite for suite in ALL_SUITES if rng.getrandbits(1)),
                key=int,
            )
        )
        policy = VerificationPolicyV1(
            allowed_v3_suites=allowed,
            require_history_feedback=bool(rng.getrandbits(1)),
            require_message_binding=bool(rng.getrandbits(1)),
            require_audit=bool(rng.getrandbits(1)),
            max_input_bytes=rng.choice((1, 64, 1024, 1 << 20)),
            max_trajectory_rounds=rng.choice((1, 8, 64, 1024)),
            symlink_mode=rng.choice(
                (PolicySymlinkModeV1.REJECT, PolicySymlinkModeV1.TEXT)
            ),
        )
        source = b"repeatable" if policy.require_message_binding else None
        assert verify_with_policy_v1(
            audit, policy=policy, source=source
        ) == verify_with_policy_v1(audit, policy=policy, source=source)


def test_generated_normalized_strict_accept_implies_weak_accept():
    rng = random.Random(0x5356324D4F4E4F)
    weak = VerificationPolicyV1(
        allowed_v3_suites=ALL_SUITES,
        require_history_feedback=False,
        allow_legacy_v22=True,
        require_message_binding=False,
        require_audit=False,
        allow_tree_only_artifacts=True,
        max_input_bytes=1 << 20,
        max_trajectory_rounds=1024,
        allowed_artifact_metadata_profiles=(1, 2),
        symlink_mode=PolicySymlinkModeV1.TEXT,
    )

    for index in range(100):
        suite = rng.choice(HISTORY_SUITES)
        message = f"monotone-{index}".encode()
        audit = _audit(message, suite)
        strict = VerificationPolicyV1(
            allowed_v3_suites=(suite,),
            require_history_feedback=True,
            require_message_binding=True,
            require_audit=True,
            max_input_bytes=1024,
            max_trajectory_rounds=64,
            allowed_artifact_metadata_profiles=(1,),
            symlink_mode=PolicySymlinkModeV1.REJECT,
        )
        assert policy_is_stricter_or_equal_v1(strict, weak)
        strict_result = verify_with_policy_v1(
            audit, policy=strict, source=message
        )
        weak_result = verify_with_policy_v1(
            audit, policy=weak, source=message
        )
        if strict_result.accepted:
            assert weak_result.accepted
