from __future__ import annotations

from dataclasses import replace

import pytest

from sigma.artifact import (
    ArtifactPolicyCodeV1,
    ArtifactProfileV1,
    ArtifactSideCodeV1,
    ArtifactSideStatusV1,
    ManifestTrajectoryModeV1,
    create_artifact_v1,
    verify_artifact_v1,
    verify_manifest_files_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    TrajectoryAuditModeV3,
    VerificationCapabilitiesV1,
    VerificationDecisionKindV1,
    VerificationPolicyV1,
    audit_from_evaluation_v3,
)
from sigma.tree import ManifestEntryKind, ManifestEntryV1, ManifestV1, build_tree
from sigma.v3 import evaluate_v3


def _trajectory_parts(message: bytes, *, salt: bytes = b"sa1"):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=salt,
        challenge=b"dual-verification",
        application_context=b"tests/sa1",
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    return evaluation, digest_from_evaluation_v3(evaluation)


def _dual_policy(*, require_audit: bool = False) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
        require_history_feedback=True,
        require_message_binding=True,
        require_audit=require_audit,
        require_tree_evidence=True,
        require_dual_evidence=True,
    )


def _tree_policy() -> VerificationPolicyV1:
    return VerificationPolicyV1(
        allowed_v3_suites=(),
        require_history_feedback=False,
        require_message_binding=True,
        require_tree_evidence=True,
        allow_tree_only_artifacts=True,
    )


def test_tree_trajectory_and_dual_profiles_verify_under_explicit_policies():
    message = b"sa1-good"
    evaluation, digest = _trajectory_parts(message)
    tree = build_tree(message)
    audit = audit_from_evaluation_v3(
        evaluation, mode=TrajectoryAuditModeV3.COMPACT
    )

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
        trajectory_audit=audit,
    )

    tree_result = verify_artifact_v1(message, tree_artifact, policy=_tree_policy())
    assert tree_result.accepted
    assert tree_result.tree.verified
    assert tree_result.trajectory.status is ArtifactSideStatusV1.NOT_APPLICABLE

    trajectory_result = verify_artifact_v1(
        message,
        trajectory_artifact,
        policy=VerificationPolicyV1(
            allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
            require_history_feedback=True,
            require_message_binding=True,
        ),
    )
    assert trajectory_result.accepted
    assert trajectory_result.tree.status is ArtifactSideStatusV1.NOT_APPLICABLE
    assert trajectory_result.trajectory.verified

    dual_result = verify_artifact_v1(
        message,
        dual_artifact,
        policy=_dual_policy(require_audit=True),
    )
    assert dual_result.accepted
    assert dual_result.tree.verified
    assert dual_result.trajectory.verified
    assert dual_result.dual_conjunction is True


def test_dual_failure_attribution_preserves_each_side_independently():
    source = b"AAAA"
    other = b"BBBB"
    third = b"CCCC"
    _, source_digest = _trajectory_parts(source, salt=b"source")
    _, other_digest = _trajectory_parts(other, salt=b"source")
    policy = _dual_policy()

    tree_ok_traj_bad = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=build_tree(source),
        trajectory_digest=other_digest,
    )
    result = verify_artifact_v1(source, tree_ok_traj_bad, policy=policy)
    assert not result.accepted
    assert result.tree.verified
    assert result.trajectory.status is ArtifactSideStatusV1.FAILED
    assert result.trajectory.code is ArtifactSideCodeV1.TRAJECTORY_DIGEST_MISMATCH
    assert result.dual_conjunction is False
    assert "trajectory" in result.failure_sides

    tree_bad_traj_ok = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=build_tree(other),
        trajectory_digest=source_digest,
    )
    result = verify_artifact_v1(source, tree_bad_traj_ok, policy=policy)
    assert not result.accepted
    assert result.tree.status is ArtifactSideStatusV1.FAILED
    assert result.tree.code is ArtifactSideCodeV1.TREE_ROOT_MISMATCH
    assert result.trajectory.verified
    assert result.dual_conjunction is False
    assert "tree" in result.failure_sides

    _, third_digest = _trajectory_parts(third, salt=b"source")
    both_bad = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=build_tree(other),
        trajectory_digest=third_digest,
    )
    result = verify_artifact_v1(source, both_bad, policy=policy)
    assert not result.accepted
    assert not result.tree.verified
    assert not result.trajectory.verified
    assert result.dual_conjunction is False


def test_invalid_attached_audit_fails_trajectory_side_even_when_digest_matches():
    message = b"audit-side"
    evaluation, digest = _trajectory_parts(message)
    audit = audit_from_evaluation_v3(evaluation)
    first_state = bytearray(audit.states[0])
    first_state[0] ^= 1
    corrupted = replace(
        audit,
        states=(bytes(first_state), *audit.states[1:]),
    )
    artifact = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=build_tree(message),
        trajectory_digest=digest,
        trajectory_audit=corrupted,
    )
    result = verify_artifact_v1(message, artifact, policy=_dual_policy())
    assert result.tree.verified
    assert result.trajectory.status is ArtifactSideStatusV1.FAILED
    assert result.trajectory.code is ArtifactSideCodeV1.TRAJECTORY_AUDIT_MISMATCH
    assert not result.accepted


def test_policy_can_require_tree_trajectory_or_dual_without_running_disallowed_side():
    message = b"policy-profile"
    _, digest = _trajectory_parts(message)
    tree = build_tree(message)
    tree_artifact = create_artifact_v1(ArtifactProfileV1.TREE, tree_root=tree)
    trajectory_artifact = create_artifact_v1(
        ArtifactProfileV1.TRAJECTORY,
        trajectory_digest=digest,
    )
    dual_artifact = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=tree,
        trajectory_digest=digest,
    )

    default_tree = verify_artifact_v1(
        message,
        tree_artifact,
        policy=VerificationPolicyV1(),
    )
    assert not default_tree.accepted
    assert default_tree.policy.code is ArtifactPolicyCodeV1.TRAJECTORY_REQUIRED
    assert default_tree.tree.status is ArtifactSideStatusV1.NOT_RUN

    tree_required = VerificationPolicyV1(
        allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
        require_tree_evidence=True,
    )
    traj_rejected = verify_artifact_v1(
        message,
        trajectory_artifact,
        policy=tree_required,
    )
    assert traj_rejected.policy.code is ArtifactPolicyCodeV1.TREE_REQUIRED

    dual_required = _dual_policy()
    for artifact in (tree_artifact, trajectory_artifact):
        result = verify_artifact_v1(message, artifact, policy=dual_required)
        assert result.policy.code is ArtifactPolicyCodeV1.DUAL_REQUIRED
    assert verify_artifact_v1(
        message,
        dual_artifact,
        policy=dual_required,
    ).accepted


class _BombSource(CanonicalSource):
    def __init__(self, size: int) -> None:
        self._size = size
        self.iterated = False

    @property
    def byte_length(self) -> int:
        return self._size

    def iter_chunks(self, chunk_size: int):
        self.iterated = True
        raise AssertionError("expensive source replay reached")
        yield b""


def test_policy_short_circuits_before_expensive_source_replay():
    message = b"short-circuit"
    _, digest = _trajectory_parts(message)
    artifact = create_artifact_v1(
        ArtifactProfileV1.TRAJECTORY,
        trajectory_digest=digest,
    )
    source = _BombSource(len(message))
    result = verify_artifact_v1(
        source,
        artifact,
        policy=VerificationPolicyV1(require_tree_evidence=True),
    )
    assert result.policy.code is ArtifactPolicyCodeV1.TREE_REQUIRED
    assert result.trajectory.status is ArtifactSideStatusV1.NOT_RUN
    assert not source.iterated


def test_missing_source_is_inconclusive_and_sides_are_not_run():
    message = b"source-required"
    _, digest = _trajectory_parts(message)
    artifact = create_artifact_v1(
        ArtifactProfileV1.TRAJECTORY,
        trajectory_digest=digest,
    )
    result = verify_artifact_v1(
        None,
        artifact,
        policy=VerificationPolicyV1(
            allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
        ),
    )
    assert result.policy.kind is VerificationDecisionKindV1.INCONCLUSIVE
    assert result.policy.code is ArtifactPolicyCodeV1.SOURCE_REQUIRED
    assert result.trajectory.status is ArtifactSideStatusV1.NOT_RUN


def test_policy_signature_provenance_and_metadata_requirements_are_preserved():
    message = b"caps"
    _, digest = _trajectory_parts(message)
    artifact = create_artifact_v1(
        ArtifactProfileV1.TRAJECTORY,
        trajectory_digest=digest,
    )
    base = VerificationPolicyV1(
        allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
        require_signature=True,
        require_provenance=True,
    )
    missing = verify_artifact_v1(message, artifact, policy=base)
    assert missing.policy.code is ArtifactPolicyCodeV1.SIGNATURE_REQUIRED

    caps = VerificationCapabilitiesV1(
        has_signature=True,
        has_provenance=True,
        artifact_metadata_profile=1,
    )
    assert verify_artifact_v1(
        message,
        artifact,
        policy=base,
        capabilities=caps,
    ).accepted


def test_manifest_selective_trajectory_criticality_is_explicit():
    a = b"tree-only-file"
    b = b"trajectory-critical"
    _, digest_b = _trajectory_parts(b, salt=b"manifest-b")
    entries = (
        ManifestEntryV1(
            "a.bin",
            ManifestEntryKind.FILE,
            len(a),
            build_tree(a),
        ),
        ManifestEntryV1(
            "b.bin",
            ManifestEntryKind.FILE,
            len(b),
            build_tree(b),
            digest_b.to_bytes(),
        ),
    )
    manifest = ManifestV1(entries)
    files = {"a.bin": a, "b.bin": b}

    declared = verify_manifest_files_v1(
        files,
        manifest,
        mode=ManifestTrajectoryModeV1.DECLARED,
    )
    assert declared.accepted
    assert declared.files[0].trajectory.status is ArtifactSideStatusV1.NOT_APPLICABLE
    assert declared.files[1].trajectory.verified

    tree_only = verify_manifest_files_v1(
        files,
        manifest,
        mode=ManifestTrajectoryModeV1.TREE_ONLY,
    )
    assert tree_only.accepted
    assert all(
        item.trajectory.status is ArtifactSideStatusV1.NOT_APPLICABLE
        for item in tree_only.files
    )

    all_files = verify_manifest_files_v1(
        files,
        manifest,
        mode=ManifestTrajectoryModeV1.REQUIRE_ALL_FILES,
    )
    assert not all_files.accepted
    assert all_files.files[0].trajectory.code is ArtifactSideCodeV1.TRAJECTORY_EVIDENCE_MISSING
    assert all_files.files[1].trajectory.verified


def test_manifest_files_mapping_must_exactly_match_regular_files():
    data = b"x"
    manifest = ManifestV1(
        (
            ManifestEntryV1(
                "x.bin",
                ManifestEntryKind.FILE,
                1,
                build_tree(data),
            ),
        )
    )
    with pytest.raises(ValueError, match="exactly match"):
        verify_manifest_files_v1(
            {},
            manifest,
            mode=ManifestTrajectoryModeV1.TREE_ONLY,
        )
    with pytest.raises(ValueError, match="exactly match"):
        verify_manifest_files_v1(
            {"x.bin": data, "extra.bin": data},
            manifest,
            mode=ManifestTrajectoryModeV1.TREE_ONLY,
        )
