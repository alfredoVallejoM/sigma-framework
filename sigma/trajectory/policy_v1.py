"""Canonical VerificationPolicy V1 for trajectory/product verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum, IntEnum

from sigma.outputs.digest import SigmaDigestV2
from sigma.outputs.digest_v3 import SigmaDigestV3, verify_full_v3
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.encoding import (
    DecodeError,
    decode_tlv,
    decode_u16_sequence,
    decode_uint,
    encode_tlv,
    encode_u16_sequence,
    encode_uint,
)
from sigma.spec.ids import DIGEST_MAGIC
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3, TrajectoryProfileIdV3
from sigma.trajectory.audit_v3 import (
    TrajectoryAuditV3,
    verify_trajectory_audit_full_v3,
    verify_trajectory_audit_structure_v3,
)
from sigma.v2 import verify_full as verify_full_v22

_POLICY_MAGIC = b"SIGPOLY1"
_POLICY_VERSION = 1
_MAX_POLICY_BODY = 1 << 20
_MAX_U64 = (1 << 64) - 1
_V3_DIGEST_MAGIC = b"SIGMA3DG"
_AUDIT_MAGIC = b"SIG3AUD0"

_DEFAULT_ALLOWED_SUITES = (
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


class VerificationDecisionKindV1(Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


class VerificationDecisionCodeV1(Enum):
    OK = "ok"
    MALFORMED_EVIDENCE = "malformed-evidence"
    UNSUPPORTED_EVIDENCE = "unsupported-evidence"
    SUITE_NOT_ALLOWED = "suite-not-allowed"
    HISTORY_REQUIRED = "history-required"
    LEGACY_DISABLED = "legacy-disabled"
    INPUT_TOO_LARGE = "input-too-large"
    INPUT_SIZE_UNKNOWN = "input-size-unknown"
    ROUNDS_TOO_LARGE = "rounds-too-large"
    AUDIT_REQUIRED = "audit-required"
    TREE_REQUIRED = "tree-required"
    DUAL_REQUIRED = "dual-required"
    SIGNATURE_REQUIRED = "signature-required"
    PROVENANCE_REQUIRED = "provenance-required"
    TREE_PROOF_TOO_LARGE = "tree-proof-too-large"
    TREE_PROOF_SIZE_UNKNOWN = "tree-proof-size-unknown"
    METADATA_PROFILE_NOT_ALLOWED = "metadata-profile-not-allowed"
    SYMLINK_NOT_ALLOWED = "symlink-not-allowed"
    MEMORY_LIMIT_EXCEEDED = "memory-limit-exceeded"
    MEMORY_ESTIMATE_UNKNOWN = "memory-estimate-unknown"
    SOURCE_REQUIRED = "source-required"
    SOURCE_TYPE_UNSUPPORTED = "source-type-unsupported"
    VERIFICATION_FAILED = "verification-failed"


class VerificationEvidenceKindV1(Enum):
    V3_DIGEST = "v3-digest"
    TRAJECTORY_AUDIT = "trajectory-audit"
    LEGACY_V22 = "legacy-v2.2"


class PolicySymlinkModeV1(IntEnum):
    REJECT = 1
    TEXT = 2


class _PolicyField(IntEnum):
    ALLOWED_V3_SUITES = 1
    REQUIRE_HISTORY = 2
    ALLOW_LEGACY_V22 = 3
    REQUIRE_MESSAGE_BINDING = 4
    REQUIRE_AUDIT = 5
    REQUIRE_TREE = 6
    REQUIRE_DUAL = 7
    REQUIRE_SIGNATURE = 8
    REQUIRE_PROVENANCE = 9
    ALLOW_TREE_ONLY = 10
    MAX_INPUT_BYTES = 11
    MAX_TRAJECTORY_ROUNDS = 12
    MAX_TREE_PROOF_BYTES = 13
    MAX_MEMORY_BYTES = 14
    ALLOWED_METADATA_PROFILES = 15
    SYMLINK_MODE = 16


def _bool_bytes(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise TypeError("policy boolean must be bool")
    return encode_uint(1 if value else 0, 1)


def _decode_bool(data: bytes) -> bool:
    value = decode_uint(data, 1)
    if value not in (0, 1):
        raise DecodeError("policy boolean must be 0 or 1")
    return bool(value)


def _policy_record(fields) -> bytes:
    body = encode_tlv(fields)
    if len(body) > _MAX_POLICY_BODY:
        raise ValueError("verification policy body is too large")
    return (
        _POLICY_MAGIC
        + encode_uint(_POLICY_VERSION, 2)
        + encode_uint(len(body), 4)
        + body
    )


def _decode_policy_record(data: bytes) -> dict[int, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("verification policy encoding must be bytes")
    if len(data) < 14 or data[:8] != _POLICY_MAGIC:
        raise DecodeError("invalid verification policy magic")
    if decode_uint(data[8:10], 2) != _POLICY_VERSION:
        raise DecodeError("unsupported verification policy version")
    length = decode_uint(data[10:14], 4)
    if length > _MAX_POLICY_BODY or len(data) != 14 + length:
        raise DecodeError("verification policy length mismatch")
    fields = decode_tlv(
        data[14:],
        allowed_tags=frozenset(int(field) for field in _PolicyField),
    )
    if set(fields) != {int(field) for field in _PolicyField}:
        raise DecodeError("verification policy is missing fields")
    return fields


@dataclass(frozen=True)
class VerificationPolicyV1:
    allowed_v3_suites: tuple[SuiteIdV3, ...] = _DEFAULT_ALLOWED_SUITES
    require_history_feedback: bool = True
    allow_legacy_v22: bool = False
    require_message_binding: bool = True
    require_audit: bool = False
    require_tree_evidence: bool = False
    require_dual_evidence: bool = False
    require_signature: bool = False
    require_provenance: bool = False
    allow_tree_only_artifacts: bool = False
    max_input_bytes: int = 1 << 30
    max_trajectory_rounds: int = 64
    max_tree_proof_bytes: int = _MAX_U64
    max_memory_bytes: int = _MAX_U64
    allowed_artifact_metadata_profiles: tuple[int, ...] = (1,)
    symlink_mode: PolicySymlinkModeV1 = PolicySymlinkModeV1.REJECT

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_v3_suites, tuple):
            raise TypeError("allowed_v3_suites must be tuple")
        if any(not isinstance(value, SuiteIdV3) for value in self.allowed_v3_suites):
            raise TypeError("allowed_v3_suites must contain SuiteIdV3")
        if tuple(sorted(set(self.allowed_v3_suites), key=int)) != self.allowed_v3_suites:
            raise ValueError("allowed_v3_suites must be sorted and unique")
        for name in (
            "require_history_feedback",
            "allow_legacy_v22",
            "require_message_binding",
            "require_audit",
            "require_tree_evidence",
            "require_dual_evidence",
            "require_signature",
            "require_provenance",
            "allow_tree_only_artifacts",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")
        if self.require_dual_evidence and not self.require_tree_evidence:
            raise ValueError("require_dual_evidence implies require_tree_evidence")
        for name, maximum in (
            ("max_input_bytes", _MAX_U64),
            ("max_trajectory_rounds", 1_000_064),
            ("max_tree_proof_bytes", _MAX_U64),
            ("max_memory_bytes", _MAX_U64),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not 0 <= value <= maximum:
                raise ValueError(f"{name} is out of range")
        if not isinstance(self.allowed_artifact_metadata_profiles, tuple):
            raise TypeError("allowed_artifact_metadata_profiles must be tuple")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF
            for value in self.allowed_artifact_metadata_profiles
        ):
            raise ValueError("metadata profile IDs must be u16 integers")
        if tuple(sorted(set(self.allowed_artifact_metadata_profiles))) != (
            self.allowed_artifact_metadata_profiles
        ):
            raise ValueError("metadata profile IDs must be sorted and unique")
        if not isinstance(self.symlink_mode, PolicySymlinkModeV1):
            raise TypeError("symlink_mode must be PolicySymlinkModeV1")

    def to_bytes(self) -> bytes:
        return _policy_record(
            (
                (
                    _PolicyField.ALLOWED_V3_SUITES,
                    encode_u16_sequence(self.allowed_v3_suites),
                ),
                (_PolicyField.REQUIRE_HISTORY, _bool_bytes(self.require_history_feedback)),
                (_PolicyField.ALLOW_LEGACY_V22, _bool_bytes(self.allow_legacy_v22)),
                (
                    _PolicyField.REQUIRE_MESSAGE_BINDING,
                    _bool_bytes(self.require_message_binding),
                ),
                (_PolicyField.REQUIRE_AUDIT, _bool_bytes(self.require_audit)),
                (_PolicyField.REQUIRE_TREE, _bool_bytes(self.require_tree_evidence)),
                (_PolicyField.REQUIRE_DUAL, _bool_bytes(self.require_dual_evidence)),
                (_PolicyField.REQUIRE_SIGNATURE, _bool_bytes(self.require_signature)),
                (_PolicyField.REQUIRE_PROVENANCE, _bool_bytes(self.require_provenance)),
                (_PolicyField.ALLOW_TREE_ONLY, _bool_bytes(self.allow_tree_only_artifacts)),
                (_PolicyField.MAX_INPUT_BYTES, encode_uint(self.max_input_bytes, 8)),
                (
                    _PolicyField.MAX_TRAJECTORY_ROUNDS,
                    encode_uint(self.max_trajectory_rounds, 8),
                ),
                (
                    _PolicyField.MAX_TREE_PROOF_BYTES,
                    encode_uint(self.max_tree_proof_bytes, 8),
                ),
                (_PolicyField.MAX_MEMORY_BYTES, encode_uint(self.max_memory_bytes, 8)),
                (
                    _PolicyField.ALLOWED_METADATA_PROFILES,
                    encode_u16_sequence(self.allowed_artifact_metadata_profiles),
                ),
                (_PolicyField.SYMLINK_MODE, encode_uint(self.symlink_mode, 2)),
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VerificationPolicyV1":
        fields = _decode_policy_record(data)
        try:
            suites = tuple(
                SuiteIdV3(value)
                for value in decode_u16_sequence(
                    fields[_PolicyField.ALLOWED_V3_SUITES]
                )
            )
            return cls(
                allowed_v3_suites=suites,
                require_history_feedback=_decode_bool(fields[_PolicyField.REQUIRE_HISTORY]),
                allow_legacy_v22=_decode_bool(fields[_PolicyField.ALLOW_LEGACY_V22]),
                require_message_binding=_decode_bool(
                    fields[_PolicyField.REQUIRE_MESSAGE_BINDING]
                ),
                require_audit=_decode_bool(fields[_PolicyField.REQUIRE_AUDIT]),
                require_tree_evidence=_decode_bool(fields[_PolicyField.REQUIRE_TREE]),
                require_dual_evidence=_decode_bool(fields[_PolicyField.REQUIRE_DUAL]),
                require_signature=_decode_bool(fields[_PolicyField.REQUIRE_SIGNATURE]),
                require_provenance=_decode_bool(fields[_PolicyField.REQUIRE_PROVENANCE]),
                allow_tree_only_artifacts=_decode_bool(fields[_PolicyField.ALLOW_TREE_ONLY]),
                max_input_bytes=decode_uint(fields[_PolicyField.MAX_INPUT_BYTES], 8),
                max_trajectory_rounds=decode_uint(
                    fields[_PolicyField.MAX_TRAJECTORY_ROUNDS], 8
                ),
                max_tree_proof_bytes=decode_uint(
                    fields[_PolicyField.MAX_TREE_PROOF_BYTES], 8
                ),
                max_memory_bytes=decode_uint(fields[_PolicyField.MAX_MEMORY_BYTES], 8),
                allowed_artifact_metadata_profiles=decode_u16_sequence(
                    fields[_PolicyField.ALLOWED_METADATA_PROFILES]
                ),
                symlink_mode=PolicySymlinkModeV1(
                    decode_uint(fields[_PolicyField.SYMLINK_MODE], 2)
                ),
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid VerificationPolicyV1") from exc

    @property
    def policy_id(self) -> bytes:
        """Stable content ID; this is not a new security-width claim."""
        return hashlib.sha256(self.to_bytes()).digest()


@dataclass(frozen=True)
class VerificationCapabilitiesV1:
    has_tree_evidence: bool = False
    has_signature: bool = False
    has_provenance: bool = False
    tree_proof_bytes: int | None = None
    artifact_metadata_profile: int | None = None
    contains_symlink: bool = False
    estimated_working_memory_bytes: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "has_tree_evidence",
            "has_signature",
            "has_provenance",
            "contains_symlink",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")
        for name in ("tree_proof_bytes", "estimated_working_memory_bytes"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative int or None")
        if self.artifact_metadata_profile is not None and (
            isinstance(self.artifact_metadata_profile, bool)
            or not isinstance(self.artifact_metadata_profile, int)
            or not 0 <= self.artifact_metadata_profile <= 0xFFFF
        ):
            raise ValueError("artifact_metadata_profile must be u16 or None")


@dataclass(frozen=True)
class ParsedVerificationEvidenceV1:
    kind: VerificationEvidenceKindV1
    value: SigmaDigestV3 | TrajectoryAuditV3 | SigmaDigestV2
    canonical_bytes: bytes


@dataclass(frozen=True)
class VerificationDecisionV1:
    kind: VerificationDecisionKindV1
    code: VerificationDecisionCodeV1
    reason: str
    policy_id: bytes
    evidence_id: bytes | None
    evidence_kind: VerificationEvidenceKindV1 | None
    structure_valid: bool | None = None
    message_binding_verified: bool | None = None

    @property
    def accepted(self) -> bool:
        return self.kind is VerificationDecisionKindV1.ACCEPTED


def parse_verification_evidence_v1(data: bytes) -> ParsedVerificationEvidenceV1:
    if not isinstance(data, bytes):
        raise TypeError("verification evidence must be bytes")
    if data.startswith(_AUDIT_MAGIC):
        value = TrajectoryAuditV3.from_bytes(data)
        return ParsedVerificationEvidenceV1(
            VerificationEvidenceKindV1.TRAJECTORY_AUDIT,
            value,
            value.to_bytes(),
        )
    if data.startswith(_V3_DIGEST_MAGIC):
        value = SigmaDigestV3.from_bytes(data)
        return ParsedVerificationEvidenceV1(
            VerificationEvidenceKindV1.V3_DIGEST,
            value,
            value.to_bytes(),
        )
    if data.startswith(DIGEST_MAGIC):
        value = SigmaDigestV2.from_bytes(data)
        return ParsedVerificationEvidenceV1(
            VerificationEvidenceKindV1.LEGACY_V22,
            value,
            value.to_bytes(),
        )
    raise LookupError("unsupported verification evidence magic")


def _decision(
    policy: VerificationPolicyV1,
    parsed: ParsedVerificationEvidenceV1 | None,
    kind: VerificationDecisionKindV1,
    code: VerificationDecisionCodeV1,
    reason: str,
    *,
    structure_valid: bool | None = None,
    message_binding_verified: bool | None = None,
) -> VerificationDecisionV1:
    return VerificationDecisionV1(
        kind,
        code,
        reason,
        policy.policy_id,
        hashlib.sha256(parsed.canonical_bytes).digest() if parsed is not None else None,
        parsed.kind if parsed is not None else None,
        structure_valid,
        message_binding_verified,
    )


def _capability_decision(
    policy: VerificationPolicyV1,
    parsed: ParsedVerificationEvidenceV1,
    capabilities: VerificationCapabilitiesV1,
) -> VerificationDecisionV1 | None:
    if policy.require_tree_evidence and not capabilities.has_tree_evidence:
        code = (
            VerificationDecisionCodeV1.DUAL_REQUIRED
            if policy.require_dual_evidence
            else VerificationDecisionCodeV1.TREE_REQUIRED
        )
        return _decision(
            policy,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            code,
            "policy requires Tree evidence that is not present",
        )
    if policy.require_signature and not capabilities.has_signature:
        return _decision(
            policy,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.SIGNATURE_REQUIRED,
            "policy requires a signature",
        )
    if policy.require_provenance and not capabilities.has_provenance:
        return _decision(
            policy,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.PROVENANCE_REQUIRED,
            "policy requires provenance evidence",
        )
    if capabilities.artifact_metadata_profile is not None and (
        capabilities.artifact_metadata_profile
        not in policy.allowed_artifact_metadata_profiles
    ):
        return _decision(
            policy,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.METADATA_PROFILE_NOT_ALLOWED,
            "artifact metadata profile is not allowed",
        )
    if capabilities.contains_symlink and policy.symlink_mode is PolicySymlinkModeV1.REJECT:
        return _decision(
            policy,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.SYMLINK_NOT_ALLOWED,
            "policy rejects artifacts containing symlinks",
        )
    if capabilities.has_tree_evidence and policy.max_tree_proof_bytes < _MAX_U64:
        if capabilities.tree_proof_bytes is None:
            return _decision(
                policy,
                parsed,
                VerificationDecisionKindV1.INCONCLUSIVE,
                VerificationDecisionCodeV1.TREE_PROOF_SIZE_UNKNOWN,
                "tree proof size is required to decide policy",
            )
        if capabilities.tree_proof_bytes > policy.max_tree_proof_bytes:
            return _decision(
                policy,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.TREE_PROOF_TOO_LARGE,
                "tree proof exceeds policy limit",
            )
    if policy.max_memory_bytes < _MAX_U64:
        if capabilities.estimated_working_memory_bytes is None:
            return _decision(
                policy,
                parsed,
                VerificationDecisionKindV1.INCONCLUSIVE,
                VerificationDecisionCodeV1.MEMORY_ESTIMATE_UNKNOWN,
                "working-memory estimate is required to decide policy",
            )
        if capabilities.estimated_working_memory_bytes > policy.max_memory_bytes:
            return _decision(
                policy,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.MEMORY_LIMIT_EXCEEDED,
                "estimated working memory exceeds policy limit",
            )
    return None


def _source_size(source: CanonicalSource | bytes | None) -> int | None:
    if source is None:
        return None
    if isinstance(source, bytes):
        return len(source)
    if isinstance(source, CanonicalSource):
        return source.byte_length
    raise TypeError("source must be CanonicalSource, bytes, or None")


def _v3_context_and_size(
    parsed: ParsedVerificationEvidenceV1,
) -> tuple[SigmaContextV3, int, int]:
    if parsed.kind is VerificationEvidenceKindV1.TRAJECTORY_AUDIT:
        assert isinstance(parsed.value, TrajectoryAuditV3)
        digest = parsed.value.digest
    else:
        assert isinstance(parsed.value, SigmaDigestV3)
        digest = parsed.value
    context = digest.context
    size = digest.header.cardinality.byte_length
    rounds = digest.header.parameters.target_round + digest.header.parameters.state_count - 1
    return context, size, rounds


def verify_with_policy_v1(
    evidence: bytes | ParsedVerificationEvidenceV1 | SigmaDigestV3 | TrajectoryAuditV3 | SigmaDigestV2,
    *,
    policy: VerificationPolicyV1 | None = None,
    source: CanonicalSource | bytes | None = None,
    capabilities: VerificationCapabilitiesV1 | None = None,
) -> VerificationDecisionV1:
    selected = policy if policy is not None else VerificationPolicyV1()
    if not isinstance(selected, VerificationPolicyV1):
        raise TypeError("policy must be VerificationPolicyV1")
    caps = capabilities if capabilities is not None else VerificationCapabilitiesV1()
    if not isinstance(caps, VerificationCapabilitiesV1):
        raise TypeError("capabilities must be VerificationCapabilitiesV1")

    if isinstance(evidence, ParsedVerificationEvidenceV1):
        parsed = evidence
    elif isinstance(evidence, bytes):
        try:
            parsed = parse_verification_evidence_v1(evidence)
        except LookupError:
            return _decision(
                selected,
                None,
                VerificationDecisionKindV1.UNSUPPORTED,
                VerificationDecisionCodeV1.UNSUPPORTED_EVIDENCE,
                "evidence magic/profile is unsupported",
            )
        except (DecodeError, TypeError, ValueError):
            return _decision(
                selected,
                None,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.MALFORMED_EVIDENCE,
                "known evidence type is malformed",
            )
    elif isinstance(evidence, TrajectoryAuditV3):
        parsed = ParsedVerificationEvidenceV1(
            VerificationEvidenceKindV1.TRAJECTORY_AUDIT,
            evidence,
            evidence.to_bytes(),
        )
    elif isinstance(evidence, SigmaDigestV3):
        parsed = ParsedVerificationEvidenceV1(
            VerificationEvidenceKindV1.V3_DIGEST,
            evidence,
            evidence.to_bytes(),
        )
    elif isinstance(evidence, SigmaDigestV2):
        parsed = ParsedVerificationEvidenceV1(
            VerificationEvidenceKindV1.LEGACY_V22,
            evidence,
            evidence.to_bytes(),
        )
    else:
        return _decision(
            selected,
            None,
            VerificationDecisionKindV1.UNSUPPORTED,
            VerificationDecisionCodeV1.UNSUPPORTED_EVIDENCE,
            "evidence object type is unsupported",
        )

    capability_failure = _capability_decision(selected, parsed, caps)
    if capability_failure is not None:
        return capability_failure

    if parsed.kind is VerificationEvidenceKindV1.LEGACY_V22:
        if not selected.allow_legacy_v22:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.LEGACY_DISABLED,
                "legacy v2.2 requires explicit policy opt-in",
            )
        if selected.require_history_feedback:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.HISTORY_REQUIRED,
                "legacy v2.2 cannot satisfy history-feedback requirement",
            )
        if selected.require_audit:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.AUDIT_REQUIRED,
                "legacy v2.2 cannot satisfy trajectory-audit requirement",
            )
        source_size = _source_size(source)
        if source_size is None and selected.max_input_bytes < _MAX_U64:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.INCONCLUSIVE,
                VerificationDecisionCodeV1.INPUT_SIZE_UNKNOWN,
                "legacy input size is unknown",
            )
        if source_size is not None and source_size > selected.max_input_bytes:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.INPUT_TOO_LARGE,
                "input exceeds policy byte limit",
            )
        if not selected.require_message_binding:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.ACCEPTED,
                VerificationDecisionCodeV1.OK,
                "legacy evidence is structurally valid and policy permits no source binding",
                structure_valid=True,
                message_binding_verified=False,
            )
        if source is None:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.INCONCLUSIVE,
                VerificationDecisionCodeV1.SOURCE_REQUIRED,
                "source is required for message-binding verification",
                structure_valid=True,
            )
        if not isinstance(source, bytes):
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.UNSUPPORTED,
                VerificationDecisionCodeV1.SOURCE_TYPE_UNSUPPORTED,
                "legacy v2.2 verification requires bytes source",
                structure_valid=True,
            )
        assert isinstance(parsed.value, SigmaDigestV2)
        valid = verify_full_v22(source, parsed.value)
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.ACCEPTED if valid else VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.OK if valid else VerificationDecisionCodeV1.VERIFICATION_FAILED,
            "legacy v2.2 verification succeeded" if valid else "legacy v2.2 verification failed",
            structure_valid=True,
            message_binding_verified=valid,
        )

    context, committed_size, rounds = _v3_context_and_size(parsed)
    if context.suite_id not in selected.allowed_v3_suites:
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.SUITE_NOT_ALLOWED,
            "v3 suite is not allowed by policy",
        )
    if (
        selected.require_history_feedback
        and context.trajectory_profile is not TrajectoryProfileIdV3.HISTORY_FEEDBACK
    ):
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.HISTORY_REQUIRED,
            "policy requires history-feedback trajectory",
        )
    if committed_size > selected.max_input_bytes:
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.INPUT_TOO_LARGE,
            "committed input size exceeds policy limit",
        )
    if rounds > selected.max_trajectory_rounds:
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.ROUNDS_TOO_LARGE,
            "trajectory round count exceeds policy limit",
        )
    if (
        selected.require_audit
        and parsed.kind is not VerificationEvidenceKindV1.TRAJECTORY_AUDIT
    ):
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.AUDIT_REQUIRED,
            "policy requires TrajectoryAuditV3 evidence",
        )

    if parsed.kind is VerificationEvidenceKindV1.TRAJECTORY_AUDIT:
        assert isinstance(parsed.value, TrajectoryAuditV3)
        structural = verify_trajectory_audit_structure_v3(parsed.value)
        if not structural:
            return _decision(
                selected,
                parsed,
                VerificationDecisionKindV1.REJECTED,
                VerificationDecisionCodeV1.VERIFICATION_FAILED,
                "trajectory audit structural replay failed",
                structure_valid=False,
                message_binding_verified=False,
            )
    else:
        structural = True

    if not selected.require_message_binding:
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.ACCEPTED,
            VerificationDecisionCodeV1.OK,
            "evidence satisfies structural and policy checks",
            structure_valid=structural,
            message_binding_verified=False,
        )

    if source is None:
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.INCONCLUSIVE,
            VerificationDecisionCodeV1.SOURCE_REQUIRED,
            "source is required for message-binding verification",
            structure_valid=structural,
        )

    if isinstance(source, bytes):
        source_v3: CanonicalSource = BytesSource(source)
    elif isinstance(source, CanonicalSource):
        source_v3 = source
    else:
        raise TypeError("source must be CanonicalSource, bytes, or None")

    if source_v3.byte_length > selected.max_input_bytes:
        return _decision(
            selected,
            parsed,
            VerificationDecisionKindV1.REJECTED,
            VerificationDecisionCodeV1.INPUT_TOO_LARGE,
            "source exceeds policy byte limit",
            structure_valid=structural,
        )

    if parsed.kind is VerificationEvidenceKindV1.TRAJECTORY_AUDIT:
        assert isinstance(parsed.value, TrajectoryAuditV3)
        valid = verify_trajectory_audit_full_v3(source_v3, parsed.value)
    else:
        assert isinstance(parsed.value, SigmaDigestV3)
        valid = verify_full_v3(source_v3, parsed.value)

    return _decision(
        selected,
        parsed,
        VerificationDecisionKindV1.ACCEPTED if valid else VerificationDecisionKindV1.REJECTED,
        VerificationDecisionCodeV1.OK if valid else VerificationDecisionCodeV1.VERIFICATION_FAILED,
        "verification succeeded" if valid else "message-binding verification failed",
        structure_valid=structural,
        message_binding_verified=valid,
    )


def policy_is_stricter_or_equal_v1(
    strict: VerificationPolicyV1,
    weak: VerificationPolicyV1,
) -> bool:
    if not isinstance(strict, VerificationPolicyV1) or not isinstance(
        weak, VerificationPolicyV1
    ):
        raise TypeError("strict and weak must be VerificationPolicyV1")
    return (
        set(strict.allowed_v3_suites).issubset(weak.allowed_v3_suites)
        and (not weak.require_history_feedback or strict.require_history_feedback)
        and (not strict.allow_legacy_v22 or weak.allow_legacy_v22)
        and (not weak.require_message_binding or strict.require_message_binding)
        and (not weak.require_audit or strict.require_audit)
        and (not weak.require_tree_evidence or strict.require_tree_evidence)
        and (not weak.require_dual_evidence or strict.require_dual_evidence)
        and (not weak.require_signature or strict.require_signature)
        and (not weak.require_provenance or strict.require_provenance)
        and (strict.allow_tree_only_artifacts <= weak.allow_tree_only_artifacts)
        and strict.max_input_bytes <= weak.max_input_bytes
        and strict.max_trajectory_rounds <= weak.max_trajectory_rounds
        and strict.max_tree_proof_bytes <= weak.max_tree_proof_bytes
        and strict.max_memory_bytes <= weak.max_memory_bytes
        and set(strict.allowed_artifact_metadata_profiles).issubset(
            weak.allowed_artifact_metadata_profiles
        )
        and int(strict.symlink_mode) <= int(weak.symlink_mode)
    )


__all__ = [
    "ParsedVerificationEvidenceV1",
    "PolicySymlinkModeV1",
    "VerificationCapabilitiesV1",
    "VerificationDecisionCodeV1",
    "VerificationDecisionKindV1",
    "VerificationDecisionV1",
    "VerificationEvidenceKindV1",
    "VerificationPolicyV1",
    "parse_verification_evidence_v1",
    "policy_is_stricter_or_equal_v1",
    "verify_with_policy_v1",
]
