from __future__ import annotations

import random

from reference.dual_verification_v1 import verify_dual_sides
from sigma.artifact import (
    ArtifactProfileV1,
    create_artifact_v1,
    verify_artifact_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3, TrajectoryProfileIdV3
from sigma.trajectory import VerificationPolicyV1
from sigma.tree import build_tree
from sigma.v3 import evaluate_v3

SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _evaluation(message: bytes, suite: SuiteIdV3, case: int):
    salt = b"sa1-ref-" + case.to_bytes(2, "big")
    challenge = b"dual"
    app = b"tests/differential/sa1"
    context = SigmaContextV3.for_suite(
        suite,
        salt=salt,
        challenge=challenge,
        application_context=app,
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    return evaluation, salt, challenge, app


def test_product_dual_sides_match_independent_references():
    rng = random.Random(0x53413144494646)

    for case in range(180):
        suite = SUITES[case % len(SUITES)]
        message = rng.randbytes(rng.randrange(0, 2049))
        evaluation, salt, challenge, app = _evaluation(message, suite, case)
        digest = digest_from_evaluation_v3(evaluation)
        tree = build_tree(message)

        policy = VerificationPolicyV1(
            allowed_v3_suites=(suite,),
            require_history_feedback=(
                evaluation.context.trajectory_profile
                is TrajectoryProfileIdV3.HISTORY_FEEDBACK
            ),
            require_message_binding=True,
            require_tree_evidence=True,
            require_dual_evidence=True,
        )
        artifact = create_artifact_v1(
            ArtifactProfileV1.DUAL,
            tree_root=tree,
            trajectory_digest=digest,
        )
        product = verify_artifact_v1(message, artifact, policy=policy)
        ref_tree, ref_traj, ref_dual = verify_dual_sides(
            message,
            expected_tree_root_wire=tree.to_bytes(),
            expected_digest_wire=digest.to_bytes(),
            suite_id=int(suite),
            salt=salt,
            challenge=challenge,
            application_context=app,
        )
        assert product.tree.verified == ref_tree
        assert product.trajectory.verified == ref_traj
        assert product.dual_conjunction == ref_dual
        assert product.accepted == ref_dual

        if len(message) == 0:
            other = b""
        else:
            raw = bytearray(message)
            raw[case % len(raw)] ^= 1
            other = bytes(raw)
        other_eval, _, _, _ = _evaluation(other, suite, case)
        other_digest = digest_from_evaluation_v3(other_eval)
        other_tree = build_tree(other)

        tree_only_good = create_artifact_v1(
            ArtifactProfileV1.DUAL,
            tree_root=tree,
            trajectory_digest=other_digest,
        )
        product = verify_artifact_v1(message, tree_only_good, policy=policy)
        ref_tree, ref_traj, ref_dual = verify_dual_sides(
            message,
            expected_tree_root_wire=tree.to_bytes(),
            expected_digest_wire=other_digest.to_bytes(),
            suite_id=int(suite),
            salt=salt,
            challenge=challenge,
            application_context=app,
        )
        assert (product.tree.verified, product.trajectory.verified, product.dual_conjunction) == (
            ref_tree,
            ref_traj,
            ref_dual,
        )

        trajectory_only_good = create_artifact_v1(
            ArtifactProfileV1.DUAL,
            tree_root=other_tree,
            trajectory_digest=digest,
        )
        product = verify_artifact_v1(message, trajectory_only_good, policy=policy)
        ref_tree, ref_traj, ref_dual = verify_dual_sides(
            message,
            expected_tree_root_wire=other_tree.to_bytes(),
            expected_digest_wire=digest.to_bytes(),
            suite_id=int(suite),
            salt=salt,
            challenge=challenge,
            application_context=app,
        )
        assert (product.tree.verified, product.trajectory.verified, product.dual_conjunction) == (
            ref_tree,
            ref_traj,
            ref_dual,
        )
