"""SA1 artifact verification with independent Tree and Trajectory side results."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum

from sigma.outputs.digest_v3 import SigmaDigestV3, digest_from_evaluation_v3
from sigma.rounds.evaluate_v3 import evaluate_v3
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.ids_v3 import TrajectoryProfileIdV3
from sigma.trajectory.audit_v3 import audit_from_evaluation_v3
from sigma.trajectory.policy_v1 import (
    PolicySymlinkModeV1,
    VerificationCapabilitiesV1,
    VerificationDecisionKindV1,
    VerificationPolicyV1,
)
from sigma.tree.core import TreeBuilder, build_tree
from sigma.tree.ids import ManifestEntryKind
from sigma.tree.manifest import ManifestEntryV1, ManifestV1
from sigma.tree.model import TreeRoot

from .ids import ArtifactProfileV1
from .record import SigmaArtifactV1

_MAX_U64 = (1 << 64) - 1


class ArtifactSideStatusV1(Enum):
    NOT_APPLICABLE = "not-applicable"
    NOT_RUN = "not-run"
    VERIFIED = "verified"
    FAILED = "failed"
    ERROR = "error"


class ArtifactSideCodeV1(Enum):
    OK = "ok"
    NOT_APPLICABLE = "not-applicable"
    POLICY_SHORT_CIRCUIT = "policy-short-circuit"
    SOURCE_REQUIRED = "source-required"
    SOURCE_LENGTH_MISMATCH = "source-length-mismatch"
    TREE_ROOT_MISMATCH = "tree-root-mismatch"
    TRAJECTORY_DIGEST_MISMATCH = "trajectory-digest-mismatch"
    TRAJECTORY_AUDIT_MISMATCH = "trajectory-audit-mismatch"
    TRAJECTORY_EVIDENCE_MISSING = "trajectory-evidence-missing"
    SOURCE_ERROR = "source-error"


class ArtifactPolicyCodeV1(Enum):
    OK = "ok"
    TREE_REQUIRED = "tree-required"
    TRAJECTORY_REQUIRED = "trajectory-required"
    DUAL_REQUIRED = "dual-required"
    AUDIT_REQUIRED = "audit-required"
    SUITE_NOT_ALLOWED = "suite-not-allowed"
    HISTORY_REQUIRED = "history-required"
    INPUT_TOO_LARGE = "input-too-large"
    ROUNDS_TOO_LARGE = "rounds-too-large"
    SIGNATURE_REQUIRED = "signature-required"
    PROVENANCE_REQUIRED = "provenance-required"
    METADATA_PROFILE_NOT_ALLOWED = "metadata-profile-not-allowed"
    SYMLINK_NOT_ALLOWED = "symlink-not-allowed"
    TREE_PROOF_SIZE_UNKNOWN = "tree-proof-size-unknown"
    TREE_PROOF_TOO_LARGE = "tree-proof-too-large"
    MEMORY_ESTIMATE_UNKNOWN = "memory-estimate-unknown"
    MEMORY_LIMIT_EXCEEDED = "memory-limit-exceeded"
    SOURCE_REQUIRED = "source-required"
    SIDE_VERIFICATION_FAILED = "side-verification-failed"


class ManifestTrajectoryModeV1(Enum):
    TREE_ONLY = "tree-only"
    DECLARED = "declared"
    REQUIRE_ALL_FILES = "require-all-files"


@dataclass(frozen=True)
class ArtifactSideResultV1:
    status: ArtifactSideStatusV1
    code: ArtifactSideCodeV1
    reason: str
    expected_wire: bytes | None = None
    actual_wire: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ArtifactSideStatusV1):
            raise TypeError("side status must be ArtifactSideStatusV1")
        if not isinstance(self.code, ArtifactSideCodeV1):
            raise TypeError("side code must be ArtifactSideCodeV1")
        if not isinstance(self.reason, str):
            raise TypeError("side reason must be str")
        for name, value in (
            ("expected_wire", self.expected_wire),
            ("actual_wire", self.actual_wire),
        ):
            if value is not None and not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes or None")

    @property
    def verified(self) -> bool:
        return self.status is ArtifactSideStatusV1.VERIFIED


@dataclass(frozen=True)
class ArtifactPolicyResultV1:
    kind: VerificationDecisionKindV1
    code: ArtifactPolicyCodeV1
    reason: str
    policy_id: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.kind, VerificationDecisionKindV1):
            raise TypeError("policy result kind must be VerificationDecisionKindV1")
        if not isinstance(self.code, ArtifactPolicyCodeV1):
            raise TypeError("policy result code must be ArtifactPolicyCodeV1")
        if not isinstance(self.reason, str):
            raise TypeError("policy result reason must be str")
        if not isinstance(self.policy_id, bytes) or len(self.policy_id) != 32:
            raise ValueError("policy result policy_id must contain 32 bytes")

    @property
    def accepted(self) -> bool:
        return self.kind is VerificationDecisionKindV1.ACCEPTED


@dataclass(frozen=True)
class ArtifactVerificationResultV1:
    artifact_id: bytes
    profile: ArtifactProfileV1
    tree: ArtifactSideResultV1
    trajectory: ArtifactSideResultV1
    policy: ArtifactPolicyResultV1

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_id, bytes) or len(self.artifact_id) != 32:
            raise ValueError("artifact_id must contain 32 bytes")
        if not isinstance(self.profile, ArtifactProfileV1):
            raise TypeError("profile must be ArtifactProfileV1")
        if not isinstance(self.tree, ArtifactSideResultV1):
            raise TypeError("tree result must be ArtifactSideResultV1")
        if not isinstance(self.trajectory, ArtifactSideResultV1):
            raise TypeError("trajectory result must be ArtifactSideResultV1")
        if not isinstance(self.policy, ArtifactPolicyResultV1):
            raise TypeError("policy result must be ArtifactPolicyResultV1")

    @property
    def dual_conjunction(self) -> bool | None:
        if self.profile is not ArtifactProfileV1.DUAL:
            return None
        return self.tree.verified and self.trajectory.verified

    @property
    def accepted(self) -> bool:
        if not self.policy.accepted:
            return False
        if self.profile is ArtifactProfileV1.TREE:
            return self.tree.verified
        if self.profile is ArtifactProfileV1.TRAJECTORY:
            return self.trajectory.verified
        return self.tree.verified and self.trajectory.verified

    @property
    def failure_sides(self) -> tuple[str, ...]:
        failures: list[str] = []
        if self.profile is not ArtifactProfileV1.TRAJECTORY and not self.tree.verified:
            failures.append("tree")
        if self.profile is not ArtifactProfileV1.TREE and not self.trajectory.verified:
            failures.append("trajectory")
        if not self.policy.accepted:
            failures.append("policy")
        return tuple(failures)


@dataclass(frozen=True)
class ManifestFileVerificationResultV1:
    path: str
    tree: ArtifactSideResultV1
    trajectory: ArtifactSideResultV1

    @property
    def accepted(self) -> bool:
        return self.tree.verified and (
            self.trajectory.verified
            or self.trajectory.status is ArtifactSideStatusV1.NOT_APPLICABLE
        )


@dataclass(frozen=True)
class ManifestVerificationResultV1:
    mode: ManifestTrajectoryModeV1
    files: tuple[ManifestFileVerificationResultV1, ...]

    @property
    def accepted(self) -> bool:
        return all(item.accepted for item in self.files)


def _side(
    status: ArtifactSideStatusV1,
    code: ArtifactSideCodeV1,
    reason: str,
    *,
    expected_wire: bytes | None = None,
    actual_wire: bytes | None = None,
) -> ArtifactSideResultV1:
    return ArtifactSideResultV1(
        status,
        code,
        reason,
        expected_wire,
        actual_wire,
    )


def _na(reason: str) -> ArtifactSideResultV1:
    return _side(
        ArtifactSideStatusV1.NOT_APPLICABLE,
        ArtifactSideCodeV1.NOT_APPLICABLE,
        reason,
    )


def _not_run(reason: str) -> ArtifactSideResultV1:
    return _side(
        ArtifactSideStatusV1.NOT_RUN,
        ArtifactSideCodeV1.POLICY_SHORT_CIRCUIT,
        reason,
    )


def _coerce_source(source: CanonicalSource | bytes | None) -> CanonicalSource | None:
    if source is None:
        return None
    if isinstance(source, bytes):
        return BytesSource(source)
    if isinstance(source, CanonicalSource):
        return source
    raise TypeError("source must be CanonicalSource, bytes, or None")


def _tree_verify(
    source: CanonicalSource,
    expected: TreeRoot,
) -> ArtifactSideResultV1:
    expected_wire = expected.to_bytes()
    try:
        if source.byte_length != expected.byte_length:
            return _side(
                ArtifactSideStatusV1.FAILED,
                ArtifactSideCodeV1.SOURCE_LENGTH_MISMATCH,
                "source byte length differs from TreeRoot",
                expected_wire=expected_wire,
            )
        builder = TreeBuilder(expected.profile)
        for chunk in source.iter_chunks(expected.profile.chunk_size):
            builder.update(chunk)
        actual = builder.finalize()
        actual_wire = actual.to_bytes()
        if hmac.compare_digest(actual_wire, expected_wire):
            return _side(
                ArtifactSideStatusV1.VERIFIED,
                ArtifactSideCodeV1.OK,
                "TreeRoot verified",
                expected_wire=expected_wire,
                actual_wire=actual_wire,
            )
        return _side(
            ArtifactSideStatusV1.FAILED,
            ArtifactSideCodeV1.TREE_ROOT_MISMATCH,
            "TreeRoot does not match source",
            expected_wire=expected_wire,
            actual_wire=actual_wire,
        )
    except Exception as exc:
        return _side(
            ArtifactSideStatusV1.ERROR,
            ArtifactSideCodeV1.SOURCE_ERROR,
            f"{type(exc).__name__}: {exc}",
            expected_wire=expected_wire,
        )


def _trajectory_verify(
    source: CanonicalSource,
    artifact: SigmaArtifactV1,
) -> ArtifactSideResultV1:
    expected = artifact.trajectory_digest
    if expected is None:
        return _side(
            ArtifactSideStatusV1.FAILED,
            ArtifactSideCodeV1.TRAJECTORY_EVIDENCE_MISSING,
            "artifact has no trajectory evidence",
        )
    expected_wire = expected.to_bytes()
    try:
        if source.byte_length != expected.header.cardinality.byte_length:
            return _side(
                ArtifactSideStatusV1.FAILED,
                ArtifactSideCodeV1.SOURCE_LENGTH_MISMATCH,
                "source byte length differs from SigmaDigestV3",
                expected_wire=expected_wire,
            )
        evaluation = evaluate_v3(expected.context, source)
        actual_digest = digest_from_evaluation_v3(evaluation)
        actual_wire = actual_digest.to_bytes()
        if not hmac.compare_digest(actual_wire, expected_wire):
            return _side(
                ArtifactSideStatusV1.FAILED,
                ArtifactSideCodeV1.TRAJECTORY_DIGEST_MISMATCH,
                "SigmaDigestV3 does not match source",
                expected_wire=expected_wire,
                actual_wire=actual_wire,
            )
        if artifact.trajectory_audit is not None:
            expected_audit = audit_from_evaluation_v3(
                evaluation,
                mode=artifact.trajectory_audit.mode,
            )
            if not hmac.compare_digest(
                expected_audit.to_bytes(),
                artifact.trajectory_audit.to_bytes(),
            ):
                return _side(
                    ArtifactSideStatusV1.FAILED,
                    ArtifactSideCodeV1.TRAJECTORY_AUDIT_MISMATCH,
                    "attached TrajectoryAuditV3 does not replay from source",
                    expected_wire=expected_wire,
                    actual_wire=actual_wire,
                )
        return _side(
            ArtifactSideStatusV1.VERIFIED,
            ArtifactSideCodeV1.OK,
            (
                "TrajectoryAuditV3 and SigmaDigestV3 verified"
                if artifact.trajectory_audit is not None
                else "SigmaDigestV3 verified"
            ),
            expected_wire=expected_wire,
            actual_wire=actual_wire,
        )
    except Exception as exc:
        return _side(
            ArtifactSideStatusV1.ERROR,
            ArtifactSideCodeV1.SOURCE_ERROR,
            f"{type(exc).__name__}: {exc}",
            expected_wire=expected_wire,
        )


def _policy_result(
    policy: VerificationPolicyV1,
    kind: VerificationDecisionKindV1,
    code: ArtifactPolicyCodeV1,
    reason: str,
) -> ArtifactPolicyResultV1:
    return ArtifactPolicyResultV1(kind, code, reason, policy.policy_id)


def _policy_preflight(
    artifact: SigmaArtifactV1,
    policy: VerificationPolicyV1,
    capabilities: VerificationCapabilitiesV1,
    source: CanonicalSource | None,
) -> ArtifactPolicyResultV1 | None:
    profile = artifact.profile
    has_tree = artifact.tree_root is not None
    has_trajectory = artifact.trajectory_digest is not None

    if policy.require_dual_evidence and profile is not ArtifactProfileV1.DUAL:
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.DUAL_REQUIRED,
            "policy requires a DUAL artifact",
        )
    if policy.require_tree_evidence and not has_tree:
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.TREE_REQUIRED,
            "policy requires Tree evidence",
        )
    if profile is ArtifactProfileV1.TREE:
        if not policy.allow_tree_only_artifacts:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.TRAJECTORY_REQUIRED,
                "policy does not allow Tree-only artifacts",
            )
        if policy.require_audit:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.AUDIT_REQUIRED,
                "policy requires trajectory audit evidence",
            )
    if has_trajectory:
        assert artifact.trajectory_digest is not None
        context = artifact.trajectory_digest.context
        if context.suite_id not in policy.allowed_v3_suites:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.SUITE_NOT_ALLOWED,
                "trajectory suite is not allowed",
            )
        if (
            policy.require_history_feedback
            and context.trajectory_profile
            is not TrajectoryProfileIdV3.HISTORY_FEEDBACK
        ):
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.HISTORY_REQUIRED,
                "policy requires history-feedback trajectory",
            )
        if policy.require_audit and artifact.trajectory_audit is None:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.AUDIT_REQUIRED,
                "policy requires TrajectoryAuditV3",
            )
        rounds = (
            artifact.trajectory_digest.header.parameters.target_round
            + artifact.trajectory_digest.header.parameters.state_count
            - 1
        )
        if rounds > policy.max_trajectory_rounds:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.ROUNDS_TOO_LARGE,
                "trajectory round count exceeds policy limit",
            )

    committed_size = (
        artifact.tree_root.byte_length
        if artifact.tree_root is not None
        else artifact.trajectory_digest.header.cardinality.byte_length
    )
    if committed_size > policy.max_input_bytes:
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.INPUT_TOO_LARGE,
            "artifact committed input size exceeds policy limit",
        )
    if source is None:
        return _policy_result(
            policy,
            VerificationDecisionKindV1.INCONCLUSIVE,
            ArtifactPolicyCodeV1.SOURCE_REQUIRED,
            "source is required for Artifact verification",
        )

    try:
        if source.byte_length > policy.max_input_bytes:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.INPUT_TOO_LARGE,
                "source exceeds policy input limit",
            )
    except Exception:
        # Side verification records the source error with side attribution.
        pass

    if policy.require_signature and not capabilities.has_signature:
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.SIGNATURE_REQUIRED,
            "policy requires signature evidence",
        )
    if policy.require_provenance and not capabilities.has_provenance:
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.PROVENANCE_REQUIRED,
            "policy requires provenance evidence",
        )
    if (
        capabilities.artifact_metadata_profile is not None
        and capabilities.artifact_metadata_profile
        not in policy.allowed_artifact_metadata_profiles
    ):
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.METADATA_PROFILE_NOT_ALLOWED,
            "artifact metadata profile is not allowed",
        )
    if (
        capabilities.contains_symlink
        and policy.symlink_mode is PolicySymlinkModeV1.REJECT
    ):
        return _policy_result(
            policy,
            VerificationDecisionKindV1.REJECTED,
            ArtifactPolicyCodeV1.SYMLINK_NOT_ALLOWED,
            "policy rejects symlink-bearing artifacts",
        )
    if has_tree and policy.max_tree_proof_bytes < _MAX_U64:
        if capabilities.tree_proof_bytes is None:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.INCONCLUSIVE,
                ArtifactPolicyCodeV1.TREE_PROOF_SIZE_UNKNOWN,
                "tree proof size is required to decide policy",
            )
        if capabilities.tree_proof_bytes > policy.max_tree_proof_bytes:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.TREE_PROOF_TOO_LARGE,
                "tree proof exceeds policy limit",
            )
    if policy.max_memory_bytes < _MAX_U64:
        if capabilities.estimated_working_memory_bytes is None:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.INCONCLUSIVE,
                ArtifactPolicyCodeV1.MEMORY_ESTIMATE_UNKNOWN,
                "working-memory estimate is required to decide policy",
            )
        if capabilities.estimated_working_memory_bytes > policy.max_memory_bytes:
            return _policy_result(
                policy,
                VerificationDecisionKindV1.REJECTED,
                ArtifactPolicyCodeV1.MEMORY_LIMIT_EXCEEDED,
                "working-memory estimate exceeds policy limit",
            )
    return None


def verify_artifact_v1(
    source: CanonicalSource | bytes | None,
    artifact: SigmaArtifactV1,
    *,
    policy: VerificationPolicyV1 | None = None,
    capabilities: VerificationCapabilitiesV1 = field(
        default_factory=VerificationCapabilitiesV1
    ),
) -> ArtifactVerificationResultV1:
    """Verify SA0 primary evidence with independent side attribution."""

    if not isinstance(artifact, SigmaArtifactV1):
        raise TypeError("artifact must be SigmaArtifactV1")
    selected = policy if policy is not None else VerificationPolicyV1()
    if not isinstance(selected, VerificationPolicyV1):
        raise TypeError("policy must be VerificationPolicyV1")
    if not isinstance(capabilities, VerificationCapabilitiesV1):
        raise TypeError("capabilities must be VerificationCapabilitiesV1")
    canonical_source = _coerce_source(source)

    preflight = _policy_preflight(
        artifact,
        selected,
        capabilities,
        canonical_source,
    )
    if preflight is not None:
        return ArtifactVerificationResultV1(
            artifact.artifact_id,
            artifact.profile,
            (
                _na("artifact has no Tree evidence")
                if artifact.tree_root is None
                else _not_run("verification short-circuited by policy")
            ),
            (
                _na("artifact has no Trajectory evidence")
                if artifact.trajectory_digest is None
                else _not_run("verification short-circuited by policy")
            ),
            preflight,
        )

    assert canonical_source is not None
    tree_result = (
        _na("artifact has no Tree evidence")
        if artifact.tree_root is None
        else _tree_verify(canonical_source, artifact.tree_root)
    )
    trajectory_result = (
        _na("artifact has no Trajectory evidence")
        if artifact.trajectory_digest is None
        else _trajectory_verify(canonical_source, artifact)
    )

    side_ok = (
        tree_result.verified
        if artifact.profile is ArtifactProfileV1.TREE
        else (
            trajectory_result.verified
            if artifact.profile is ArtifactProfileV1.TRAJECTORY
            else tree_result.verified and trajectory_result.verified
        )
    )
    policy_result = _policy_result(
        selected,
        (
            VerificationDecisionKindV1.ACCEPTED
            if side_ok
            else VerificationDecisionKindV1.REJECTED
        ),
        (
            ArtifactPolicyCodeV1.OK
            if side_ok
            else ArtifactPolicyCodeV1.SIDE_VERIFICATION_FAILED
        ),
        (
            "artifact satisfies policy and all required sides verified"
            if side_ok
            else "one or more required verification sides failed"
        ),
    )
    return ArtifactVerificationResultV1(
        artifact.artifact_id,
        artifact.profile,
        tree_result,
        trajectory_result,
        policy_result,
    )


def verify_manifest_files_v1(
    files: Mapping[str, bytes],
    manifest: ManifestV1,
    *,
    mode: ManifestTrajectoryModeV1,
) -> ManifestVerificationResultV1:
    """Verify regular-file entries with an explicit trajectory criticality mode."""

    if not isinstance(files, Mapping):
        raise TypeError("files must be a mapping")
    if not isinstance(manifest, ManifestV1):
        raise TypeError("manifest must be ManifestV1")
    if not isinstance(mode, ManifestTrajectoryModeV1):
        raise TypeError("mode must be ManifestTrajectoryModeV1")

    entries = tuple(
        entry for entry in manifest.entries if entry.kind is ManifestEntryKind.FILE
    )
    expected_paths = tuple(entry.path for entry in entries)
    if set(files) != set(expected_paths):
        raise ValueError("files mapping must exactly match regular-file manifest paths")
    if any(not isinstance(files[path], bytes) for path in expected_paths):
        raise TypeError("manifest file values must be bytes")

    results: list[ManifestFileVerificationResultV1] = []
    for entry in entries:
        data = files[entry.path]
        actual_tree = build_tree(data)
        tree_ok = hmac.compare_digest(
            actual_tree.to_bytes(),
            entry.tree_root.to_bytes(),
        )
        tree_result = _side(
            (
                ArtifactSideStatusV1.VERIFIED
                if tree_ok
                else ArtifactSideStatusV1.FAILED
            ),
            (
                ArtifactSideCodeV1.OK
                if tree_ok
                else ArtifactSideCodeV1.TREE_ROOT_MISMATCH
            ),
            "manifest TreeRoot verified" if tree_ok else "manifest TreeRoot mismatch",
            expected_wire=entry.tree_root.to_bytes(),
            actual_wire=actual_tree.to_bytes(),
        )

        require_trajectory = (
            mode is ManifestTrajectoryModeV1.REQUIRE_ALL_FILES
            or (
                mode is ManifestTrajectoryModeV1.DECLARED
                and entry.trajectory_digest is not None
            )
        )
        if not require_trajectory:
            trajectory_result = _na(
                "trajectory verification not required by manifest policy"
            )
        elif entry.trajectory_digest is None:
            trajectory_result = _side(
                ArtifactSideStatusV1.FAILED,
                ArtifactSideCodeV1.TRAJECTORY_EVIDENCE_MISSING,
                "manifest policy requires trajectory evidence for this file",
            )
        else:
            expected_digest = SigmaDigestV3.from_bytes(entry.trajectory_digest)
            source = BytesSource(data)
            try:
                evaluation = evaluate_v3(expected_digest.context, source)
                actual_digest = digest_from_evaluation_v3(evaluation)
                ok = hmac.compare_digest(
                    actual_digest.to_bytes(),
                    expected_digest.to_bytes(),
                )
                trajectory_result = _side(
                    (
                        ArtifactSideStatusV1.VERIFIED
                        if ok
                        else ArtifactSideStatusV1.FAILED
                    ),
                    (
                        ArtifactSideCodeV1.OK
                        if ok
                        else ArtifactSideCodeV1.TRAJECTORY_DIGEST_MISMATCH
                    ),
                    (
                        "manifest trajectory digest verified"
                        if ok
                        else "manifest trajectory digest mismatch"
                    ),
                    expected_wire=expected_digest.to_bytes(),
                    actual_wire=actual_digest.to_bytes(),
                )
            except Exception as exc:
                trajectory_result = _side(
                    ArtifactSideStatusV1.ERROR,
                    ArtifactSideCodeV1.SOURCE_ERROR,
                    f"{type(exc).__name__}: {exc}",
                    expected_wire=entry.trajectory_digest,
                )
        results.append(
            ManifestFileVerificationResultV1(
                entry.path,
                tree_result,
                trajectory_result,
            )
        )
    return ManifestVerificationResultV1(mode, tuple(results))


__all__ = [
    "ArtifactPolicyCodeV1",
    "ArtifactPolicyResultV1",
    "ArtifactSideCodeV1",
    "ArtifactSideResultV1",
    "ArtifactSideStatusV1",
    "ArtifactVerificationResultV1",
    "ManifestFileVerificationResultV1",
    "ManifestTrajectoryModeV1",
    "ManifestVerificationResultV1",
    "verify_artifact_v1",
    "verify_manifest_files_v1",
]
