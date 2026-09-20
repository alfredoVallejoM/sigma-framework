"""Canonical Sigma v3 evidence and deliberately separated verification APIs."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import IntEnum

from sigma.binding import (
    PersistentBinding,
    PublicTrajectoryHeader,
    TrajectoryWindow,
    derive_length_signature_v3,
    derive_trajectory_parameters,
)
from sigma.crypto.primitives import domain_tag_v3
from sigma.rounds.deep_v3 import (
    DeepEvaluationV3,
    DeepVectorEvaluationV3,
    evaluate_deep_v3,
    evaluate_deep_vector_v3,
)
from sigma.rounds.wide_once_v3 import WideOnceEvaluationV3, evaluate_wide_once_v3
from sigma.sources import CanonicalSource
from sigma.spec.codec_v3 import decode_record, encode_record, validate_record_prefix
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, encode_uint
from sigma.spec.ids_v3 import (
    DomainIdV3,
    OutputProfileIdV3,
    RoundProfileIdV3,
    SuiteIdV3,
)

_DIGEST_MAGIC = b"SIGMA3DG"
_AUDIT_MAGIC = b"SIGMA3EA"


class _DigestField(IntEnum):
    PROFILE = 1
    DOMAIN = 2
    CONTEXT = 3
    HEADER = 4
    WINDOW = 5


class _AuditField(IntEnum):
    SUITE = 1
    PROFILE = 2
    DOMAIN = 3
    DIGEST = 4
    BINDING = 5


@dataclass(frozen=True)
class SigmaDigestV3:
    context: SigmaContextV3
    header: PublicTrajectoryHeader
    window: TrajectoryWindow

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV3):
            raise TypeError("context must be SigmaContextV3")
        if not isinstance(self.header, PublicTrajectoryHeader):
            raise TypeError("header must be PublicTrajectoryHeader")
        if not isinstance(self.window, TrajectoryWindow):
            raise TypeError("window must be TrajectoryWindow")
        if self.context.output_profile is not OutputProfileIdV3.IMPLICIT_J:
            raise ValueError("SigmaDigestV3 requires IMPLICIT_J context")
        if self.header.anchor.suite_id != self.context.suite_id:
            raise ValueError("header and context suites differ")
        expected_length_signature = derive_length_signature_v3(
            self.context,
            self.header.cardinality,
        )
        if self.header.length_signature != expected_length_signature:
            raise ValueError("header length signature does not match context")
        if self.header.parameters != self.window.parameters:
            raise ValueError("header and window parameters differ")
        if any(len(state) != self.context.state_size for state in self.window.states):
            raise ValueError("window state size does not match context")

    def to_bytes(self) -> bytes:
        return encode_record(
            _DIGEST_MAGIC,
            (
                (_DigestField.PROFILE, encode_uint(OutputProfileIdV3.IMPLICIT_J, 2)),
                (_DigestField.DOMAIN, domain_tag_v3(DomainIdV3.EVIDENCE)),
                (_DigestField.CONTEXT, self.context.to_bytes()),
                (_DigestField.HEADER, self.header.to_bytes()),
                (_DigestField.WINDOW, self.window.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SigmaDigestV3:
        validate_record_prefix(
            data,
            magic=_DIGEST_MAGIC,
            expected_fields=(
                (
                    int(_DigestField.PROFILE),
                    encode_uint(OutputProfileIdV3.IMPLICIT_J, 2),
                ),
                (
                    int(_DigestField.DOMAIN),
                    domain_tag_v3(DomainIdV3.EVIDENCE),
                ),
            ),
        )
        fields = decode_record(
            data,
            magic=_DIGEST_MAGIC,
            allowed_tags=frozenset(int(field) for field in _DigestField),
        )
        try:
            if fields[_DigestField.PROFILE] != encode_uint(OutputProfileIdV3.IMPLICIT_J, 2):
                raise ValueError("unexpected output profile")
            if fields[_DigestField.DOMAIN] != domain_tag_v3(DomainIdV3.EVIDENCE):
                raise ValueError("unexpected evidence domain")
            return cls(
                SigmaContextV3.from_bytes(fields[_DigestField.CONTEXT]),
                PublicTrajectoryHeader.from_bytes(fields[_DigestField.HEADER]),
                TrajectoryWindow.from_bytes(fields[_DigestField.WINDOW]),
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 digest") from exc


@dataclass(frozen=True)
class ExplicitAuditEvidenceV3:
    """Separate audit envelope; never confused with the IMPLICIT_J digest."""

    digest: SigmaDigestV3
    binding: PersistentBinding

    def __post_init__(self) -> None:
        if not isinstance(self.digest, SigmaDigestV3):
            raise TypeError("digest must be SigmaDigestV3")
        if not isinstance(self.binding, PersistentBinding):
            raise TypeError("binding must be PersistentBinding")
        header = self.digest.header
        if (
            header.anchor != self.binding.anchor
            or header.cardinality != self.binding.cardinality
            or header.length_signature != self.binding.length_signature
        ):
            raise ValueError("explicit binding does not match public header")
        if (
            derive_trajectory_parameters(self.digest.context, self.binding)
            != self.digest.header.parameters
        ):
            raise ValueError("explicit binding derives different trajectory parameters")

    def to_bytes(self) -> bytes:
        return encode_record(
            _AUDIT_MAGIC,
            (
                (_AuditField.SUITE, encode_uint(SuiteIdV3.EXPLICIT_AUDIT_V3, 2)),
                (_AuditField.PROFILE, encode_uint(OutputProfileIdV3.EXPLICIT_BINDING, 2)),
                (
                    _AuditField.DOMAIN,
                    domain_tag_v3(DomainIdV3.EXPLICIT_EVIDENCE),
                ),
                (_AuditField.DIGEST, self.digest.to_bytes()),
                (_AuditField.BINDING, self.binding.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> ExplicitAuditEvidenceV3:
        validate_record_prefix(
            data,
            magic=_AUDIT_MAGIC,
            expected_fields=(
                (
                    int(_AuditField.SUITE),
                    encode_uint(SuiteIdV3.EXPLICIT_AUDIT_V3, 2),
                ),
                (
                    int(_AuditField.PROFILE),
                    encode_uint(OutputProfileIdV3.EXPLICIT_BINDING, 2),
                ),
                (
                    int(_AuditField.DOMAIN),
                    domain_tag_v3(DomainIdV3.EXPLICIT_EVIDENCE),
                ),
            ),
        )
        fields = decode_record(
            data,
            magic=_AUDIT_MAGIC,
            allowed_tags=frozenset(int(field) for field in _AuditField),
        )
        try:
            if fields[_AuditField.SUITE] != encode_uint(SuiteIdV3.EXPLICIT_AUDIT_V3, 2):
                raise ValueError("unexpected explicit audit suite")
            if fields[_AuditField.PROFILE] != encode_uint(OutputProfileIdV3.EXPLICIT_BINDING, 2):
                raise ValueError("unexpected audit profile")
            if fields[_AuditField.DOMAIN] != domain_tag_v3(DomainIdV3.EXPLICIT_EVIDENCE):
                raise ValueError("unexpected evidence domain")
            return cls(
                SigmaDigestV3.from_bytes(fields[_AuditField.DIGEST]),
                PersistentBinding.from_bytes(fields[_AuditField.BINDING]),
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid explicit audit evidence") from exc


@dataclass(frozen=True)
class StructureVerificationV3:
    evidence: SigmaDigestV3
    structure_valid: bool = True
    message_binding_verified: bool = False


EvaluationV3 = WideOnceEvaluationV3 | DeepEvaluationV3 | DeepVectorEvaluationV3


def digest_from_evaluation_v3(evaluation: EvaluationV3) -> SigmaDigestV3:
    if not isinstance(evaluation, (WideOnceEvaluationV3, DeepEvaluationV3, DeepVectorEvaluationV3)):
        raise TypeError("evaluation must be a Sigma v3 evaluation")
    return SigmaDigestV3(evaluation.context, evaluation.header, evaluation.window)


def verify_structure_v3(data: bytes) -> StructureVerificationV3:
    """Parse syntax only; this never makes a message-binding claim."""

    return StructureVerificationV3(SigmaDigestV3.from_bytes(data))


def verify_prepared_v3(evaluation: EvaluationV3, evidence: SigmaDigestV3) -> bool:
    expected = digest_from_evaluation_v3(evaluation).to_bytes()
    return hmac.compare_digest(expected, evidence.to_bytes())


def _evaluate_for_context_v3(context: SigmaContextV3, source: CanonicalSource) -> EvaluationV3:
    if context.round_profile is RoundProfileIdV3.WIDE_ONCE:
        return evaluate_wide_once_v3(context, source)
    if context.round_profile is RoundProfileIdV3.DEEP:
        return evaluate_deep_v3(context, source)
    if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        return evaluate_deep_vector_v3(context, source)
    raise ValueError("unsupported Sigma v3 round profile")  # pragma: no cover


def verify_full_v3(source: CanonicalSource, evidence: SigmaDigestV3) -> bool:
    """Recompute binding and the complete public window from canonical bytes."""

    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")
    if not isinstance(evidence, SigmaDigestV3):
        raise TypeError("evidence must be SigmaDigestV3")
    evaluation = _evaluate_for_context_v3(evidence.context, source)
    return verify_prepared_v3(evaluation, evidence)


def verify_explicit_full_v3(source: CanonicalSource, evidence: ExplicitAuditEvidenceV3) -> bool:
    """Verify both public trajectory and the explicitly published internal binding."""

    if not isinstance(evidence, ExplicitAuditEvidenceV3):
        raise TypeError("evidence must be ExplicitAuditEvidenceV3")
    evaluation = _evaluate_for_context_v3(evidence.digest.context, source)
    return hmac.compare_digest(
        evaluation.prepared.binding.to_bytes(), evidence.binding.to_bytes()
    ) and verify_prepared_v3(evaluation, evidence.digest)
