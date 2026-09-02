"""Typed evidence retained by wide anchor profiles."""

from dataclasses import dataclass
from typing import Optional, Tuple, Union

from sigma.spec.context import SigmaContextV2, validate_registered_context
from sigma.spec.encoding import (
    DecodeError,
    decode_tlv,
    decode_uint,
    domain_tag,
    encode_tlv,
    encode_uint,
)
from sigma.spec.ids import (
    EVIDENCE_MAGIC,
    EVIDENCE_VERSION,
    AlgorithmId,
    AnchorProfileId,
    DomainId,
    EvidenceType,
    SuiteId,
)
from sigma.suites.registry import get_suite
from sigma.validation import require_int

_EVIDENCE_HEADER_SIZE = len(EVIDENCE_MAGIC) + 10


def _encode_components(algorithms: Tuple[AlgorithmId, ...], roots: Tuple[bytes, ...]) -> bytes:
    return encode_uint(len(roots), 2) + b"".join(
        encode_uint(algorithm, 2) + encode_uint(len(root), 2) + root
        for algorithm, root in zip(algorithms, roots, strict=True)
    )


def _decode_components(data: bytes) -> tuple[Tuple[AlgorithmId, ...], Tuple[bytes, ...]]:
    if len(data) < 2:
        raise DecodeError("truncated evidence component count")
    count = decode_uint(data[:2], 2)
    offset = 2
    algorithms = []
    roots = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise DecodeError("truncated evidence component header")
        try:
            algorithm = AlgorithmId(decode_uint(data[offset : offset + 2], 2))
        except ValueError as exc:
            raise DecodeError(f"unknown evidence algorithm: {exc}") from exc
        length = decode_uint(data[offset + 2 : offset + 4], 2)
        offset += 4
        end = offset + length
        if end > len(data):
            raise DecodeError("truncated evidence component")
        algorithms.append(algorithm)
        roots.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise DecodeError("trailing bytes in evidence components")
    return tuple(algorithms), tuple(roots)


def _envelope(
    evidence_type: EvidenceType,
    suite_id: SuiteId,
    fields: Tuple[Tuple[int, bytes], ...],
) -> bytes:
    body = encode_tlv(fields)
    return (
        EVIDENCE_MAGIC
        + encode_uint(EVIDENCE_VERSION, 2)
        + encode_uint(evidence_type, 2)
        + encode_uint(suite_id, 2)
        + encode_uint(len(body), 4)
        + body
    )


@dataclass(frozen=True)
class AnchorEvidence:
    algorithms: Tuple[AlgorithmId, ...]
    roots: Tuple[bytes, ...]
    message_length: int
    suite_id: Optional[SuiteId] = None

    def __post_init__(self) -> None:
        if not self.algorithms or len(self.algorithms) != len(self.roots):
            raise ValueError("anchor algorithms and roots must be non-empty and aligned")
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("anchor algorithms must be unique")
        if not all(isinstance(item, AlgorithmId) for item in self.algorithms):
            raise TypeError("anchor algorithms must be AlgorithmId values")
        if not all(isinstance(root, bytes) and root for root in self.roots):
            raise TypeError("anchor roots must be non-empty bytes")
        require_int("message_length", self.message_length, minimum=0, maximum=(1 << 64) - 1)
        if self.suite_id is not None:
            if not isinstance(self.suite_id, SuiteId):
                raise TypeError("suite_id must be SuiteId or None")
            suite = get_suite(self.suite_id)
            if self.algorithms != suite.branches:
                raise ValueError("anchor algorithms do not match the evidence suite")
            if any(len(root) != suite.anchor_component_size for root in self.roots):
                raise ValueError("anchor root length does not match the evidence suite")

    @property
    def evidence_version(self) -> int:
        return get_suite(self.suite_id).evidence_version if self.suite_id is not None else 1

    @property
    def evidence_type(self) -> EvidenceType:
        return EvidenceType.WIDE_ROOTS

    @property
    def physical_width_bits(self) -> int:
        return sum(len(root) for root in self.roots) * 8

    def to_bytes(self) -> bytes:
        if self.evidence_version == EVIDENCE_VERSION:
            assert self.suite_id is not None
            return _envelope(
                self.evidence_type,
                self.suite_id,
                (
                    (1, encode_uint(self.message_length, 8)),
                    (2, _encode_components(self.algorithms, self.roots)),
                ),
            )
        parts = [domain_tag(DomainId.ANCHOR_EVIDENCE), encode_uint(len(self.roots), 2)]
        for algorithm, root in zip(self.algorithms, self.roots, strict=False):
            parts.extend((encode_uint(algorithm, 2), encode_uint(len(root), 2), root))
        parts.append(encode_uint(self.message_length, 8))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, context: SigmaContextV2) -> "AnchorEvidence":
        evidence = parse_evidence(data, context)
        if not isinstance(evidence, cls):
            raise DecodeError("evidence type is not WIDE_ROOTS")
        return evidence


@dataclass(frozen=True)
class CrossWideEvidence:
    algorithms: Tuple[AlgorithmId, ...]
    roots: Tuple[bytes, ...]
    cross_roots: Tuple[bytes, ...]
    message_length: int
    suite_id: Optional[SuiteId] = None

    def __post_init__(self) -> None:
        if not self.algorithms or len(self.algorithms) != len(self.roots):
            raise ValueError("cross anchor algorithms and roots must be aligned")
        if len(self.cross_roots) != len(self.roots):
            raise ValueError("cross anchor must retain one connection per root")
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("cross anchor algorithms must be unique")
        if not all(isinstance(item, AlgorithmId) for item in self.algorithms):
            raise TypeError("cross anchor algorithms must be AlgorithmId values")
        if not all(isinstance(root, bytes) and root for root in self.roots + self.cross_roots):
            raise TypeError("cross anchor components must be non-empty bytes")
        require_int("message_length", self.message_length, minimum=0, maximum=(1 << 64) - 1)
        if self.suite_id is not None:
            if not isinstance(self.suite_id, SuiteId):
                raise TypeError("suite_id must be SuiteId or None")
            suite = get_suite(self.suite_id)
            if self.algorithms != suite.branches:
                raise ValueError("cross algorithms do not match the evidence suite")
            if any(
                len(root) != suite.anchor_component_size for root in self.roots + self.cross_roots
            ):
                raise ValueError("cross component length does not match the evidence suite")

    @property
    def evidence_version(self) -> int:
        return get_suite(self.suite_id).evidence_version if self.suite_id is not None else 1

    @property
    def evidence_type(self) -> EvidenceType:
        return EvidenceType.CROSS_WIDE

    @property
    def physical_width_bits(self) -> int:
        return sum(len(root) for root in self.roots + self.cross_roots) * 8

    def to_bytes(self) -> bytes:
        if self.evidence_version == EVIDENCE_VERSION:
            assert self.suite_id is not None
            return _envelope(
                self.evidence_type,
                self.suite_id,
                (
                    (1, encode_uint(self.message_length, 8)),
                    (2, _encode_components(self.algorithms, self.roots)),
                    (3, _encode_components(self.algorithms, self.cross_roots)),
                ),
            )
        parts = [
            domain_tag(DomainId.ANCHOR_EVIDENCE),
            encode_uint(3, 2),
            encode_uint(len(self.roots), 2),
        ]
        for algorithm, root in zip(self.algorithms, self.roots, strict=False):
            parts.extend((encode_uint(algorithm, 2), encode_uint(len(root), 2), root))
        parts.append(encode_uint(len(self.cross_roots), 2))
        for algorithm, root in zip(self.algorithms, self.cross_roots, strict=False):
            parts.extend((encode_uint(algorithm, 2), encode_uint(len(root), 2), root))
        parts.append(encode_uint(self.message_length, 8))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, context: SigmaContextV2) -> "CrossWideEvidence":
        evidence = parse_evidence(data, context)
        if not isinstance(evidence, cls):
            raise DecodeError("evidence type is not CROSS_WIDE")
        return evidence


def parse_evidence(
    data: bytes, context: SigmaContextV2
) -> Union[AnchorEvidence, CrossWideEvidence]:
    """Parse a self-describing v2-2 evidence envelope for a registered context."""

    if not isinstance(data, bytes):
        raise TypeError("evidence encoding must be bytes")
    validate_registered_context(context)
    suite = get_suite(context.suite_id)
    if suite.evidence_version != EVIDENCE_VERSION:
        raise DecodeError("legacy v2-1 evidence is internal and not self-describing")
    if len(data) < _EVIDENCE_HEADER_SIZE or not data.startswith(EVIDENCE_MAGIC):
        raise DecodeError("invalid or truncated evidence magic")
    offset = len(EVIDENCE_MAGIC)
    version = decode_uint(data[offset : offset + 2], 2)
    if version != EVIDENCE_VERSION:
        raise DecodeError(f"unsupported evidence version: {version}")
    try:
        evidence_type = EvidenceType(decode_uint(data[offset + 2 : offset + 4], 2))
        suite_id = SuiteId(decode_uint(data[offset + 4 : offset + 6], 2))
    except ValueError as exc:
        raise DecodeError(f"unknown evidence identifier: {exc}") from exc
    if suite_id != context.suite_id:
        raise DecodeError("evidence suite does not match context")
    body_length = decode_uint(data[offset + 6 : offset + 10], 4)
    if body_length != len(data) - _EVIDENCE_HEADER_SIZE:
        raise DecodeError("evidence length mismatch or trailing bytes")
    allowed = frozenset({1, 2, 3} if evidence_type is EvidenceType.CROSS_WIDE else {1, 2})
    fields = decode_tlv(data[_EVIDENCE_HEADER_SIZE:], allowed_tags=allowed)
    if set(fields) != set(allowed):
        raise DecodeError("missing evidence fields")
    if len(fields[1]) != 8:
        raise DecodeError("evidence message length must contain 8 bytes")
    message_length = decode_uint(fields[1], 8)
    algorithms, roots = _decode_components(fields[2])
    try:
        if evidence_type is EvidenceType.WIDE_ROOTS:
            if context.anchor_profile is AnchorProfileId.CROSS_WIDE:
                raise ValueError("WIDE_ROOTS evidence cannot satisfy CrossWide")
            return AnchorEvidence(algorithms, roots, message_length, suite_id)
        cross_algorithms, cross_roots = _decode_components(fields[3])
        if context.anchor_profile is not AnchorProfileId.CROSS_WIDE:
            raise ValueError("CROSS_WIDE evidence requires a CrossWide context")
        if cross_algorithms != algorithms:
            raise ValueError("cross component algorithms differ from roots")
        return CrossWideEvidence(algorithms, roots, cross_roots, message_length, suite_id)
    except (TypeError, ValueError) as exc:
        raise DecodeError(f"invalid evidence: {exc}") from exc
