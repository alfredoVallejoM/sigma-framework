"""PX4 versioned HTTP request framing and bounded streaming body reader."""

from __future__ import annotations

import io
import json
import struct
from dataclasses import dataclass
from typing import BinaryIO

from sigma.sources import IncrementalSpoolSource, SourceLimitError
from sigma.trajectory import VerificationCapabilitiesV1, VerificationPolicyV1

from .runtime import (
    CancellableSourceV1,
    GatewayCancellationTokenV1,
    GatewayCancelledError,
    GatewayError,
    GatewayErrorCodeV1,
    GatewayLimitsV1,
    GatewayMetadataTooLargeError,
    GatewayRequestTooLargeError,
    GatewaySourceTooLargeError,
    GatewayTimeoutError,
    canonical_json_bytes,
)

ARTIFACT_VERIFY_MEDIA_TYPE = "application/vnd.sigma.gateway.artifact-verify.v1"
POLICY_EVALUATE_MEDIA_TYPE = "application/vnd.sigma.gateway.policy-evaluate.v1"
BATCH_VERIFY_MEDIA_TYPE = "application/vnd.sigma.gateway.batch-verify.v1"
INCLUSION_VERIFY_MEDIA_TYPE = "application/vnd.sigma.gateway.inclusion-verify.v1"
RANGE_VERIFY_MEDIA_TYPE = "application/vnd.sigma.gateway.range-verify.v1"
ARTIFACT_WIRE_MEDIA_TYPE = "application/vnd.sigma.artifact.v1"
BATCH_RESULT_MEDIA_TYPE = "application/vnd.sigma.batch-result.v1"

_ARTIFACT_VERIFY_MAGIC = b"SIGGWAV1"
_POLICY_EVALUATE_MAGIC = b"SIGGWPE1"
_BATCH_VERIFY_MAGIC = b"SIGGWBV1"
_INCLUSION_VERIFY_MAGIC = b"SIGGWPI1"
_RANGE_VERIFY_MAGIC = b"SIGGWPR1"
_PROTOCOL_VERSION = 1
_FLAG_SOURCE_PRESENT = 0x0001
_ALLOWED_FLAGS = _FLAG_SOURCE_PRESENT

_ARTIFACT_HEADER = struct.Struct(">8sHH32sIIIQ")
_POLICY_HEADER = struct.Struct(">8sHHHIIIQ")
_BATCH_HEADER = struct.Struct(">8sHH")
_BATCH_ITEM_HEADER = struct.Struct(">HHIIIQ")
_INCLUSION_HEADER = struct.Struct(">8sHII")
_RANGE_HEADER = struct.Struct(">8sHIQ")


class GatewayFramingError(GatewayError):
    code = GatewayErrorCodeV1.BAD_REQUEST
    safe_message = "malformed gateway request framing"


def _require_magic_version(
    magic: bytes,
    expected_magic: bytes,
    version: int,
) -> None:
    if magic != expected_magic or version != _PROTOCOL_VERSION:
        raise GatewayFramingError()


def _validate_flags(flags: int) -> bool:
    if flags & ~_ALLOWED_FLAGS:
        raise GatewayFramingError()
    return bool(flags & _FLAG_SOURCE_PRESENT)


def _capabilities_object(value: VerificationCapabilitiesV1) -> dict[str, object]:
    return {
        "artifact_metadata_profile": value.artifact_metadata_profile,
        "contains_symlink": value.contains_symlink,
        "estimated_working_memory_bytes": value.estimated_working_memory_bytes,
        "has_provenance": value.has_provenance,
        "has_signature": value.has_signature,
        "has_tree_evidence": value.has_tree_evidence,
        "tree_proof_bytes": value.tree_proof_bytes,
    }


def encode_capabilities_v1(value: VerificationCapabilitiesV1) -> bytes:
    if not isinstance(value, VerificationCapabilitiesV1):
        raise TypeError("value must be VerificationCapabilitiesV1")
    return canonical_json_bytes(_capabilities_object(value))


def decode_capabilities_v1(payload: bytes) -> VerificationCapabilitiesV1:
    if not isinstance(payload, bytes):
        raise TypeError("capabilities payload must be bytes")
    if not payload:
        return VerificationCapabilitiesV1()
    try:
        raw = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayFramingError() from exc
    if not isinstance(raw, dict):
        raise GatewayFramingError()
    expected = {
        "artifact_metadata_profile",
        "contains_symlink",
        "estimated_working_memory_bytes",
        "has_provenance",
        "has_signature",
        "has_tree_evidence",
        "tree_proof_bytes",
    }
    if set(raw) != expected or canonical_json_bytes(raw) != payload:
        raise GatewayFramingError()
    try:
        value = VerificationCapabilitiesV1(
            has_tree_evidence=raw["has_tree_evidence"],
            has_signature=raw["has_signature"],
            has_provenance=raw["has_provenance"],
            tree_proof_bytes=raw["tree_proof_bytes"],
            artifact_metadata_profile=raw["artifact_metadata_profile"],
            contains_symlink=raw["contains_symlink"],
            estimated_working_memory_bytes=raw["estimated_working_memory_bytes"],
        )
    except (TypeError, ValueError) as exc:
        raise GatewayFramingError() from exc
    if encode_capabilities_v1(value) != payload:
        raise GatewayFramingError()
    return value


class GatewayBodyReaderV1:
    """Exact Content-Length reader that never reads past the declared request."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        content_length: int,
        limits: GatewayLimitsV1,
        token: GatewayCancellationTokenV1,
    ) -> None:
        if not callable(getattr(stream, "read", None)):
            raise TypeError("stream must provide read(size)")
        if (
            isinstance(content_length, bool)
            or not isinstance(content_length, int)
            or content_length < 0
        ):
            raise ValueError("content_length must be non-negative int")
        if not isinstance(limits, GatewayLimitsV1):
            raise TypeError("limits must be GatewayLimitsV1")
        if not isinstance(token, GatewayCancellationTokenV1):
            raise TypeError("token must be GatewayCancellationTokenV1")
        if content_length > limits.max_request_bytes:
            raise GatewayRequestTooLargeError()
        self.stream = stream
        self.content_length = content_length
        self.limits = limits
        self.token = token
        self.bytes_read = 0

    def _stream_read(self, length: int) -> bytes:
        try:
            chunk = self.stream.read(length)
        except TimeoutError as exc:
            raise GatewayTimeoutError() from exc
        except (OSError, ConnectionError) as exc:
            raise GatewayCancelledError() from exc
        if not isinstance(chunk, bytes):
            raise GatewayFramingError()
        return chunk

    @property
    def remaining(self) -> int:
        return self.content_length - self.bytes_read

    def read_exact(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("length must be non-negative int")
        if length > self.remaining:
            raise GatewayFramingError()
        output = bytearray()
        while len(output) < length:
            self.token.check()
            request = min(
                length - len(output),
                self.limits.read_chunk_bytes,
            )
            chunk = self._stream_read(request)
            if not isinstance(chunk, bytes):
                raise GatewayFramingError()
            if not chunk:
                raise GatewayFramingError()
            if len(chunk) > request:
                raise GatewayFramingError()
            output.extend(chunk)
            self.bytes_read += len(chunk)
        self.token.check()
        return bytes(output)

    def read_metadata(self, length: int) -> bytes:
        if length > self.limits.max_metadata_bytes:
            raise GatewayMetadataTooLargeError()
        return self.read_exact(length)

    def discard_exact(self, length: int) -> None:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("length must be non-negative int")
        if length > self.remaining:
            raise GatewayFramingError()
        remaining = length
        while remaining:
            self.token.check()
            request = min(remaining, self.limits.read_chunk_bytes)
            chunk = self.stream.read(request)
            if not isinstance(chunk, bytes) or not chunk or len(chunk) > request:
                raise GatewayFramingError()
            self.bytes_read += len(chunk)
            remaining -= len(chunk)
        self.token.check()

    def spool_source(
        self,
        length: int,
        *,
        effective_max_source_bytes: int | None = None,
    ) -> CancellableSourceV1:
        limit = self.limits.max_source_bytes
        if effective_max_source_bytes is not None:
            if (
                isinstance(effective_max_source_bytes, bool)
                or not isinstance(effective_max_source_bytes, int)
                or effective_max_source_bytes < 0
            ):
                raise ValueError("effective_max_source_bytes must be non-negative")
            limit = min(limit, effective_max_source_bytes)
        if length > limit:
            raise GatewaySourceTooLargeError()
        if length > self.remaining:
            raise GatewayFramingError()

        memory_limit = min(
            self.limits.max_memory_spool_bytes,
            max(1, limit),
        )
        source = IncrementalSpoolSource(
            max_memory_bytes=memory_limit,
            max_spool_bytes=limit,
        )
        try:
            remaining = length
            while remaining:
                self.token.check()
                request = min(
                    remaining,
                    self.limits.read_chunk_bytes,
                )
                chunk = self.stream.read(request)
                if not isinstance(chunk, bytes) or not chunk or len(chunk) > request:
                    raise GatewayFramingError()
                self.bytes_read += len(chunk)
                remaining -= len(chunk)
                source.update(chunk)
            source.finalize()
            self.token.check()
            return CancellableSourceV1(source, self.token)
        except SourceLimitError as exc:
            source.close()
            raise GatewaySourceTooLargeError() from exc
        except BaseException:
            source.close()
            raise

    def require_consumed(self) -> None:
        if self.remaining != 0:
            raise GatewayFramingError()


@dataclass(frozen=True)
class ArtifactVerifyMetadataV1:
    artifact_id: bytes
    artifact_wire: bytes
    policy: VerificationPolicyV1
    capabilities: VerificationCapabilitiesV1
    source_present: bool
    source_length: int


@dataclass(frozen=True)
class PolicyEvaluateMetadataV1:
    artifact_identity: bytes
    evidence_wire: bytes
    policy: VerificationPolicyV1
    capabilities: VerificationCapabilitiesV1
    source_present: bool
    source_length: int


@dataclass(frozen=True)
class BatchVerifyItemMetadataV1:
    artifact_identity: bytes
    evidence_wire: bytes
    policy: VerificationPolicyV1
    capabilities: VerificationCapabilitiesV1
    source_present: bool
    source_length: int


@dataclass(frozen=True)
class InclusionVerifyHeadV1:
    proof_wire: bytes
    leaf_length: int


@dataclass(frozen=True)
class InclusionVerifyMetadataV1:
    proof_wire: bytes
    leaf: bytes


@dataclass(frozen=True)
class RangeVerifyHeadV1:
    proof_wire: bytes
    value_length: int


@dataclass(frozen=True)
class RangeVerifyMetadataV1:
    proof_wire: bytes
    range_bytes: bytes


def _decode_policy(payload: bytes) -> VerificationPolicyV1:
    if not payload:
        return VerificationPolicyV1()
    try:
        policy = VerificationPolicyV1.from_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise GatewayError(
            code=GatewayErrorCodeV1.MALFORMED_POLICY,
            safe_message="verification policy is malformed",
        ) from exc
    if policy.to_bytes() != payload:
        raise GatewayError(
            code=GatewayErrorCodeV1.MALFORMED_POLICY,
            safe_message="verification policy is non-canonical",
        )
    return policy


def read_artifact_verify_metadata_v1(
    reader: GatewayBodyReaderV1,
) -> ArtifactVerifyMetadataV1:
    header = reader.read_exact(_ARTIFACT_HEADER.size)
    (
        magic,
        version,
        flags,
        artifact_id,
        artifact_length,
        policy_length,
        capabilities_length,
        source_length,
    ) = _ARTIFACT_HEADER.unpack(header)
    _require_magic_version(magic, _ARTIFACT_VERIFY_MAGIC, version)
    source_present = _validate_flags(flags)
    if len(artifact_id) != 32:
        raise GatewayFramingError()
    if not source_present and source_length != 0:
        raise GatewayFramingError()
    metadata_total = artifact_length + policy_length + capabilities_length
    if metadata_total > reader.limits.max_metadata_bytes:
        raise GatewayMetadataTooLargeError()
    artifact_wire = reader.read_metadata(artifact_length)
    policy_wire = reader.read_metadata(policy_length)
    capabilities_wire = reader.read_metadata(capabilities_length)
    if source_length > reader.limits.max_source_bytes:
        raise GatewaySourceTooLargeError()
    if source_length != reader.remaining:
        raise GatewayFramingError()
    return ArtifactVerifyMetadataV1(
        artifact_id,
        artifact_wire,
        _decode_policy(policy_wire),
        decode_capabilities_v1(capabilities_wire),
        source_present,
        source_length,
    )


def read_policy_evaluate_metadata_v1(
    reader: GatewayBodyReaderV1,
) -> PolicyEvaluateMetadataV1:
    header = reader.read_exact(_POLICY_HEADER.size)
    (
        magic,
        version,
        flags,
        identity_length,
        evidence_length,
        policy_length,
        capabilities_length,
        source_length,
    ) = _POLICY_HEADER.unpack(header)
    _require_magic_version(magic, _POLICY_EVALUATE_MAGIC, version)
    source_present = _validate_flags(flags)
    if not 1 <= identity_length <= 255:
        raise GatewayFramingError()
    if not source_present and source_length != 0:
        raise GatewayFramingError()
    metadata_total = (
        identity_length
        + evidence_length
        + policy_length
        + capabilities_length
    )
    if metadata_total > reader.limits.max_metadata_bytes:
        raise GatewayMetadataTooLargeError()
    identity = reader.read_metadata(identity_length)
    evidence = reader.read_metadata(evidence_length)
    policy_wire = reader.read_metadata(policy_length)
    capabilities_wire = reader.read_metadata(capabilities_length)
    if source_length > reader.limits.max_source_bytes:
        raise GatewaySourceTooLargeError()
    if source_length != reader.remaining:
        raise GatewayFramingError()
    return PolicyEvaluateMetadataV1(
        identity,
        evidence,
        _decode_policy(policy_wire),
        decode_capabilities_v1(capabilities_wire),
        source_present,
        source_length,
    )


def read_batch_header_v1(reader: GatewayBodyReaderV1) -> int:
    raw = reader.read_exact(_BATCH_HEADER.size)
    magic, version, item_count = _BATCH_HEADER.unpack(raw)
    _require_magic_version(magic, _BATCH_VERIFY_MAGIC, version)
    if not 1 <= item_count <= reader.limits.max_batch_items:
        raise GatewayError(
            status=413,
            code=GatewayErrorCodeV1.REQUEST_TOO_LARGE,
            safe_message="batch item count exceeds gateway limit",
        )
    return item_count


def read_batch_item_metadata_v1(
    reader: GatewayBodyReaderV1,
) -> BatchVerifyItemMetadataV1:
    raw = reader.read_exact(_BATCH_ITEM_HEADER.size)
    (
        flags,
        identity_length,
        evidence_length,
        policy_length,
        capabilities_length,
        source_length,
    ) = _BATCH_ITEM_HEADER.unpack(raw)
    source_present = _validate_flags(flags)
    if not 1 <= identity_length <= 255:
        raise GatewayFramingError()
    if not source_present and source_length != 0:
        raise GatewayFramingError()
    metadata_total = (
        identity_length
        + evidence_length
        + policy_length
        + capabilities_length
    )
    if metadata_total > reader.limits.max_metadata_bytes:
        raise GatewayMetadataTooLargeError()
    identity = reader.read_metadata(identity_length)
    evidence = reader.read_metadata(evidence_length)
    policy_wire = reader.read_metadata(policy_length)
    capabilities_wire = reader.read_metadata(capabilities_length)
    if source_length > reader.limits.max_source_bytes:
        raise GatewaySourceTooLargeError()
    if source_length > reader.remaining:
        raise GatewayFramingError()
    return BatchVerifyItemMetadataV1(
        identity,
        evidence,
        _decode_policy(policy_wire),
        decode_capabilities_v1(capabilities_wire),
        source_present,
        source_length,
    )


def read_inclusion_verify_head_v1(
    reader: GatewayBodyReaderV1,
) -> InclusionVerifyHeadV1:
    raw = reader.read_exact(_INCLUSION_HEADER.size)
    magic, version, proof_length, leaf_length = _INCLUSION_HEADER.unpack(raw)
    _require_magic_version(magic, _INCLUSION_VERIFY_MAGIC, version)
    if proof_length > reader.limits.max_metadata_bytes:
        raise GatewayMetadataTooLargeError()
    if leaf_length > reader.limits.max_proof_value_bytes:
        raise GatewaySourceTooLargeError()
    proof = reader.read_metadata(proof_length)
    if leaf_length != reader.remaining:
        raise GatewayFramingError()
    return InclusionVerifyHeadV1(proof, leaf_length)


def read_inclusion_verify_v1(
    reader: GatewayBodyReaderV1,
) -> InclusionVerifyMetadataV1:
    head = read_inclusion_verify_head_v1(reader)
    leaf = reader.read_exact(head.leaf_length)
    reader.require_consumed()
    return InclusionVerifyMetadataV1(head.proof_wire, leaf)


def read_range_verify_head_v1(
    reader: GatewayBodyReaderV1,
) -> RangeVerifyHeadV1:
    raw = reader.read_exact(_RANGE_HEADER.size)
    magic, version, proof_length, value_length = _RANGE_HEADER.unpack(raw)
    _require_magic_version(magic, _RANGE_VERIFY_MAGIC, version)
    if proof_length > reader.limits.max_metadata_bytes:
        raise GatewayMetadataTooLargeError()
    if value_length > reader.limits.max_proof_value_bytes:
        raise GatewaySourceTooLargeError()
    proof = reader.read_metadata(proof_length)
    if value_length != reader.remaining:
        raise GatewayFramingError()
    return RangeVerifyHeadV1(proof, value_length)


def read_range_verify_v1(
    reader: GatewayBodyReaderV1,
) -> RangeVerifyMetadataV1:
    head = read_range_verify_head_v1(reader)
    value = reader.read_exact(head.value_length)
    reader.require_consumed()
    return RangeVerifyMetadataV1(head.proof_wire, value)


def encode_artifact_verify_request_v1(
    *,
    artifact_id: bytes,
    artifact_wire: bytes = b"",
    policy: VerificationPolicyV1 | None = None,
    capabilities: VerificationCapabilitiesV1 | None = None,
    source: bytes | None = None,
) -> bytes:
    if not isinstance(artifact_id, bytes) or len(artifact_id) != 32:
        raise ValueError("artifact_id must contain exactly 32 bytes")
    if not isinstance(artifact_wire, bytes):
        raise TypeError("artifact_wire must be bytes")
    selected = VerificationPolicyV1() if policy is None else policy
    caps = VerificationCapabilitiesV1() if capabilities is None else capabilities
    policy_wire = selected.to_bytes()
    caps_wire = encode_capabilities_v1(caps)
    source_wire = b"" if source is None else source
    if not isinstance(source_wire, bytes):
        raise TypeError("source must be bytes or None")
    flags = 0 if source is None else _FLAG_SOURCE_PRESENT
    return (
        _ARTIFACT_HEADER.pack(
            _ARTIFACT_VERIFY_MAGIC,
            _PROTOCOL_VERSION,
            flags,
            artifact_id,
            len(artifact_wire),
            len(policy_wire),
            len(caps_wire),
            len(source_wire),
        )
        + artifact_wire
        + policy_wire
        + caps_wire
        + source_wire
    )


def encode_policy_evaluate_request_v1(
    *,
    artifact_identity: bytes,
    evidence_wire: bytes,
    policy: VerificationPolicyV1 | None = None,
    capabilities: VerificationCapabilitiesV1 | None = None,
    source: bytes | None = None,
) -> bytes:
    if not isinstance(artifact_identity, bytes) or not 1 <= len(artifact_identity) <= 255:
        raise ValueError("artifact_identity length must be 1..255")
    if not isinstance(evidence_wire, bytes):
        raise TypeError("evidence_wire must be bytes")
    selected = VerificationPolicyV1() if policy is None else policy
    caps = VerificationCapabilitiesV1() if capabilities is None else capabilities
    policy_wire = selected.to_bytes()
    caps_wire = encode_capabilities_v1(caps)
    source_wire = b"" if source is None else source
    if not isinstance(source_wire, bytes):
        raise TypeError("source must be bytes or None")
    flags = 0 if source is None else _FLAG_SOURCE_PRESENT
    return (
        _POLICY_HEADER.pack(
            _POLICY_EVALUATE_MAGIC,
            _PROTOCOL_VERSION,
            flags,
            len(artifact_identity),
            len(evidence_wire),
            len(policy_wire),
            len(caps_wire),
            len(source_wire),
        )
        + artifact_identity
        + evidence_wire
        + policy_wire
        + caps_wire
        + source_wire
    )


def encode_batch_verify_request_v1(
    items: tuple[
        tuple[
            bytes,
            bytes,
            VerificationPolicyV1,
            VerificationCapabilitiesV1,
            bytes | None,
        ],
        ...,
    ],
) -> bytes:
    if not isinstance(items, tuple) or not items:
        raise ValueError("batch items must be non-empty tuple")
    out = bytearray(_BATCH_HEADER.pack(_BATCH_VERIFY_MAGIC, _PROTOCOL_VERSION, len(items)))
    for identity, evidence, policy, caps, source in items:
        if not isinstance(identity, bytes) or not 1 <= len(identity) <= 255:
            raise ValueError("batch artifact_identity length must be 1..255")
        if not isinstance(evidence, bytes):
            raise TypeError("batch evidence must be bytes")
        if not isinstance(policy, VerificationPolicyV1):
            raise TypeError("batch policy must be VerificationPolicyV1")
        if not isinstance(caps, VerificationCapabilitiesV1):
            raise TypeError("batch capabilities must be VerificationCapabilitiesV1")
        policy_wire = policy.to_bytes()
        caps_wire = encode_capabilities_v1(caps)
        source_wire = b"" if source is None else source
        if not isinstance(source_wire, bytes):
            raise TypeError("batch source must be bytes or None")
        flags = 0 if source is None else _FLAG_SOURCE_PRESENT
        out.extend(
            _BATCH_ITEM_HEADER.pack(
                flags,
                len(identity),
                len(evidence),
                len(policy_wire),
                len(caps_wire),
                len(source_wire),
            )
        )
        out.extend(identity)
        out.extend(evidence)
        out.extend(policy_wire)
        out.extend(caps_wire)
        out.extend(source_wire)
    return bytes(out)


def encode_inclusion_verify_request_v1(proof_wire: bytes, leaf: bytes) -> bytes:
    if not isinstance(proof_wire, bytes) or not isinstance(leaf, bytes):
        raise TypeError("proof_wire and leaf must be bytes")
    return (
        _INCLUSION_HEADER.pack(
            _INCLUSION_VERIFY_MAGIC,
            _PROTOCOL_VERSION,
            len(proof_wire),
            len(leaf),
        )
        + proof_wire
        + leaf
    )


def encode_range_verify_request_v1(proof_wire: bytes, value: bytes) -> bytes:
    if not isinstance(proof_wire, bytes) or not isinstance(value, bytes):
        raise TypeError("proof_wire and value must be bytes")
    return (
        _RANGE_HEADER.pack(
            _RANGE_VERIFY_MAGIC,
            _PROTOCOL_VERSION,
            len(proof_wire),
            len(value),
        )
        + proof_wire
        + value
    )


def body_reader_from_bytes_v1(
    payload: bytes,
    *,
    limits: GatewayLimitsV1 | None = None,
    token: GatewayCancellationTokenV1 | None = None,
) -> GatewayBodyReaderV1:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    selected_limits = GatewayLimitsV1() if limits is None else limits
    selected_token = (
        GatewayCancellationTokenV1(
            timeout_seconds=selected_limits.request_timeout_seconds
        )
        if token is None
        else token
    )
    return GatewayBodyReaderV1(
        io.BytesIO(payload),
        content_length=len(payload),
        limits=selected_limits,
        token=selected_token,
    )


__all__ = [
    "ARTIFACT_VERIFY_MEDIA_TYPE",
    "ARTIFACT_WIRE_MEDIA_TYPE",
    "BATCH_RESULT_MEDIA_TYPE",
    "BATCH_VERIFY_MEDIA_TYPE",
    "INCLUSION_VERIFY_MEDIA_TYPE",
    "POLICY_EVALUATE_MEDIA_TYPE",
    "RANGE_VERIFY_MEDIA_TYPE",
    "ArtifactVerifyMetadataV1",
    "BatchVerifyItemMetadataV1",
    "GatewayBodyReaderV1",
    "GatewayFramingError",
    "InclusionVerifyHeadV1",
    "InclusionVerifyMetadataV1",
    "PolicyEvaluateMetadataV1",
    "RangeVerifyHeadV1",
    "RangeVerifyMetadataV1",
    "body_reader_from_bytes_v1",
    "decode_capabilities_v1",
    "encode_artifact_verify_request_v1",
    "encode_batch_verify_request_v1",
    "encode_capabilities_v1",
    "encode_inclusion_verify_request_v1",
    "encode_policy_evaluate_request_v1",
    "encode_range_verify_request_v1",
    "read_artifact_verify_metadata_v1",
    "read_batch_header_v1",
    "read_batch_item_metadata_v1",
    "read_inclusion_verify_head_v1",
    "read_inclusion_verify_v1",
    "read_policy_evaluate_metadata_v1",
    "read_range_verify_head_v1",
    "read_range_verify_v1",
]
