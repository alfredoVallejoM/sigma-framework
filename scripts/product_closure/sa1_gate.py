"""Reproducible SA1 closure gate for dual artifact verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from reference.dual_verification_v1 import verify_dual_sides
from sigma.artifact import (
    ArtifactProfileV1,
    ArtifactSideStatusV1,
    ManifestTrajectoryModeV1,
    create_artifact_v1,
    verify_artifact_v1,
    verify_manifest_files_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3, TrajectoryProfileIdV3
from sigma.trajectory import VerificationPolicyV1
from sigma.tree import ManifestEntryKind, ManifestEntryV1, ManifestV1, build_tree
from sigma.v3 import evaluate_v3

MIN_DUAL_CASES = 300
MIN_POLICY_CASES = 200
MIN_MANIFEST_CASES = 100

SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _evaluation(message: bytes, suite: SuiteIdV3, case: int):
    salt = b"sa1-gate-" + case.to_bytes(4, "big")
    challenge = b"dual-verification"
    app = b"scripts/product_closure/sa1_gate"
    context = SigmaContextV3.for_suite(
        suite,
        salt=salt,
        challenge=challenge,
        application_context=app,
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    return evaluation, salt, challenge, app


def _policy_for(evaluation, *, dual: bool = True) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        allowed_v3_suites=(evaluation.context.suite_id,),
        require_history_feedback=(
            evaluation.context.trajectory_profile
            is TrajectoryProfileIdV3.HISTORY_FEEDBACK
        ),
        require_message_binding=True,
        require_tree_evidence=dual,
        require_dual_evidence=dual,
    )


def run_gate(
    *,
    dual_cases: int,
    policy_cases: int,
    manifest_cases: int,
) -> dict[str, object]:
    if dual_cases < MIN_DUAL_CASES:
        raise ValueError(f"SA1 requires at least {MIN_DUAL_CASES} dual cases")
    if policy_cases < MIN_POLICY_CASES:
        raise ValueError(f"SA1 requires at least {MIN_POLICY_CASES} policy cases")
    if manifest_cases < MIN_MANIFEST_CASES:
        raise ValueError(f"SA1 requires at least {MIN_MANIFEST_CASES} manifest cases")

    rng = random.Random(0x53413147415445)
    tree_stream = hashlib.sha256()
    trajectory_stream = hashlib.sha256()
    composition_stream = hashlib.sha256()
    failure_attribution = {
        "tree_only_failure": 0,
        "trajectory_only_failure": 0,
        "both_failure": 0,
    }

    for case in range(dual_cases):
        suite = SUITES[case % len(SUITES)]
        size = rng.randrange(1, 65)
        source = rng.randbytes(size)
        other = bytearray(source)
        other[case % size] ^= 1
        other_bytes = bytes(other)
        third = bytearray(source)
        third[(case * 7 + 1) % size] ^= 2
        if bytes(third) == other_bytes:
            third[(case * 11 + 2) % size] ^= 4
        third_bytes = bytes(third)

        evaluation, salt, challenge, app = _evaluation(source, suite, case)
        other_evaluation, _, _, _ = _evaluation(other_bytes, suite, case)
        third_evaluation, _, _, _ = _evaluation(third_bytes, suite, case)

        digest = digest_from_evaluation_v3(evaluation)
        other_digest = digest_from_evaluation_v3(other_evaluation)
        third_digest = digest_from_evaluation_v3(third_evaluation)
        tree = build_tree(source)
        other_tree = build_tree(other_bytes)

        policy = _policy_for(evaluation)
        artifacts = (
            (
                "valid",
                create_artifact_v1(
                    ArtifactProfileV1.DUAL,
                    tree_root=tree,
                    trajectory_digest=digest,
                ),
                (True, True),
            ),
            (
                "trajectory_only_failure",
                create_artifact_v1(
                    ArtifactProfileV1.DUAL,
                    tree_root=tree,
                    trajectory_digest=other_digest,
                ),
                (True, False),
            ),
            (
                "tree_only_failure",
                create_artifact_v1(
                    ArtifactProfileV1.DUAL,
                    tree_root=other_tree,
                    trajectory_digest=digest,
                ),
                (False, True),
            ),
            (
                "both_failure",
                create_artifact_v1(
                    ArtifactProfileV1.DUAL,
                    tree_root=other_tree,
                    trajectory_digest=third_digest,
                ),
                (False, False),
            ),
        )

        for label, artifact, expected_pair in artifacts:
            result = verify_artifact_v1(source, artifact, policy=policy)
            reference = verify_dual_sides(
                source,
                expected_tree_root_wire=artifact.tree_root.to_bytes(),
                expected_digest_wire=artifact.trajectory_digest.to_bytes(),
                suite_id=int(suite),
                salt=salt,
                challenge=challenge,
                application_context=app,
            )
            if (result.tree.verified, result.trajectory.verified) != expected_pair:
                raise AssertionError(f"SA1 side attribution drift: {label}")
            if (
                result.tree.verified,
                result.trajectory.verified,
                result.dual_conjunction,
            ) != reference:
                raise AssertionError(f"SA1 independent side divergence: {label}")
            if result.accepted != (expected_pair == (True, True)):
                raise AssertionError(f"SA1 composition law drift: {label}")
            if label != "valid":
                failure_attribution[label] += 1

            tree_stream.update(
                b"1" if result.tree.verified else b"0"
            )
            trajectory_stream.update(
                b"1" if result.trajectory.verified else b"0"
            )
            composition_stream.update(
                b"1" if result.accepted else b"0"
            )

    # Explicit artifact-profile policy integration.
    for case in range(policy_cases):
        message = b"policy-" + case.to_bytes(4, "big")
        evaluation, _, _, _ = _evaluation(
            message,
            SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
            10_000 + case,
        )
        digest = digest_from_evaluation_v3(evaluation)
        tree = build_tree(message)
        tree_artifact = create_artifact_v1(
            ArtifactProfileV1.TREE,
            tree_root=tree,
        )
        trajectory_artifact = create_artifact_v1(
            ArtifactProfileV1.TRAJECTORY,
            trajectory_digest=digest,
        )
        dual_artifact = create_artifact_v1(
            ArtifactProfileV1.DUAL,
            tree_root=tree,
            trajectory_digest=digest,
        )

        tree_policy = VerificationPolicyV1(
            allowed_v3_suites=(),
            require_history_feedback=False,
            require_tree_evidence=True,
            allow_tree_only_artifacts=True,
        )
        if not verify_artifact_v1(
            message, tree_artifact, policy=tree_policy
        ).accepted:
            raise AssertionError("SA1 explicit TREE policy failed")

        trajectory_policy = VerificationPolicyV1(
            allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
            require_history_feedback=True,
        )
        if not verify_artifact_v1(
            message, trajectory_artifact, policy=trajectory_policy
        ).accepted:
            raise AssertionError("SA1 explicit TRAJECTORY policy failed")

        dual_policy = VerificationPolicyV1(
            allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
            require_history_feedback=True,
            require_tree_evidence=True,
            require_dual_evidence=True,
        )
        if not verify_artifact_v1(
            message, dual_artifact, policy=dual_policy
        ).accepted:
            raise AssertionError("SA1 explicit DUAL policy failed")
        if verify_artifact_v1(
            message, tree_artifact, policy=dual_policy
        ).accepted:
            raise AssertionError("SA1 DUAL policy accepted TREE artifact")
        if verify_artifact_v1(
            message, trajectory_artifact, policy=dual_policy
        ).accepted:
            raise AssertionError("SA1 DUAL policy accepted TRAJECTORY artifact")

    # Mixed manifest criticality.
    declared_count = 0
    required_missing_count = 0
    for case in range(manifest_cases):
        tree_only_data = b"T" + case.to_bytes(4, "big")
        critical_data = b"C" + case.to_bytes(4, "big")
        critical_eval, _, _, _ = _evaluation(
            critical_data,
            SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
            20_000 + case,
        )
        critical_digest = digest_from_evaluation_v3(critical_eval)
        manifest = ManifestV1(
            (
                ManifestEntryV1(
                    "a.bin",
                    ManifestEntryKind.FILE,
                    len(tree_only_data),
                    build_tree(tree_only_data),
                ),
                ManifestEntryV1(
                    "b.bin",
                    ManifestEntryKind.FILE,
                    len(critical_data),
                    build_tree(critical_data),
                    critical_digest.to_bytes(),
                ),
            )
        )
        files = {"a.bin": tree_only_data, "b.bin": critical_data}
        declared = verify_manifest_files_v1(
            files,
            manifest,
            mode=ManifestTrajectoryModeV1.DECLARED,
        )
        if not declared.accepted:
            raise AssertionError("SA1 DECLARED mixed manifest failed")
        if (
            declared.files[0].trajectory.status
            is not ArtifactSideStatusV1.NOT_APPLICABLE
            or not declared.files[1].trajectory.verified
        ):
            raise AssertionError("SA1 manifest criticality attribution drift")
        declared_count += 1

        all_required = verify_manifest_files_v1(
            files,
            manifest,
            mode=ManifestTrajectoryModeV1.REQUIRE_ALL_FILES,
        )
        if all_required.accepted:
            raise AssertionError("SA1 REQUIRE_ALL_FILES accepted missing trajectory")
        required_missing_count += 1

        tree_only = verify_manifest_files_v1(
            files,
            manifest,
            mode=ManifestTrajectoryModeV1.TREE_ONLY,
        )
        if not tree_only.accepted:
            raise AssertionError("SA1 TREE_ONLY manifest mode failed")

    return {
        "schema": "sigma-sa1-dual-verification-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "dual_cases": dual_cases,
        "independent_side_cases": dual_cases * 4,
        "policy_cases": policy_cases,
        "manifest_cases": manifest_cases,
        "failure_attribution": failure_attribution,
        "manifest_declared_cases": declared_count,
        "manifest_require_all_missing_cases": required_missing_count,
        "tree_result_stream_sha256": tree_stream.hexdigest(),
        "trajectory_result_stream_sha256": trajectory_stream.hexdigest(),
        "composition_stream_sha256": composition_stream.hexdigest(),
        "dual_security_width_addition_claim": false,
        "tree_trajectory_claims_independent": true,
        "empirical_performance_claims": false,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dual-cases", type=int, default=MIN_DUAL_CASES)
    parser.add_argument("--policy-cases", type=int, default=MIN_POLICY_CASES)
    parser.add_argument("--manifest-cases", type=int, default=MIN_MANIFEST_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        dual_cases=args.dual_cases,
        policy_cases=args.policy_cases,
        manifest_cases=args.manifest_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
