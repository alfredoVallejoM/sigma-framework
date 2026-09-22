"""Canonical Sigma Artifact V1 record codec."""

from __future__ import annotations

from collections.abc import Iterable

from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint

from .ids import ARTIFACT_WIRE_VERSION, MAX_ARTIFACT_RECORD_BODY


class ArtifactDecodeError(DecodeError):
    """Raised for malformed Sigma Artifact V1 records."""


def record(magic: bytes, fields: Iterable[tuple[int, bytes]]) -> bytes:
    if not isinstance(magic, bytes) or len(magic) != 8:
        raise ValueError("artifact record magic must be exactly 8 bytes")
    body = encode_tlv(fields)
    if len(body) > MAX_ARTIFACT_RECORD_BODY:
        raise ValueError("artifact record body is too large")
    return (
        magic
        + encode_uint(ARTIFACT_WIRE_VERSION, 2)
        + encode_uint(len(body), 4)
        + body
    )


def parse_record(
    data: bytes,
    *,
    magic: bytes,
    allowed: frozenset[int],
    required: frozenset[int] | None = None,
) -> dict[int, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("artifact record must be bytes")
    if len(data) < 14 or data[:8] != magic:
        raise ArtifactDecodeError("invalid artifact record magic")
    if decode_uint(data[8:10], 2) != ARTIFACT_WIRE_VERSION:
        raise ArtifactDecodeError("unsupported artifact record version")
    body_length = decode_uint(data[10:14], 4)
    if body_length > MAX_ARTIFACT_RECORD_BODY or len(data) != 14 + body_length:
        raise ArtifactDecodeError("artifact record length mismatch")
    fields = decode_tlv(data[14:], allowed_tags=allowed)
    expected = allowed if required is None else required
    if set(fields) != set(expected):
        raise ArtifactDecodeError("missing artifact record field")
    return fields


def encode_id_sequence(values: tuple[bytes, ...], *, max_items: int) -> bytes:
    if not isinstance(values, tuple):
        raise TypeError("artifact ID sequence must be tuple")
    if len(values) > max_items:
        raise ValueError("artifact ID sequence has too many items")
    out = bytearray(encode_uint(len(values), 2))
    for value in values:
        if not isinstance(value, bytes) or len(value) != 32:
            raise ValueError("artifact IDs must be 32 bytes")
        out.extend(value)
    return bytes(out)


def decode_id_sequence(data: bytes, *, max_items: int) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) < 2:
        raise ArtifactDecodeError("truncated artifact ID sequence")
    count = decode_uint(data[:2], 2)
    if count > max_items or len(data) != 2 + count * 32:
        raise ArtifactDecodeError("artifact ID sequence length mismatch")
    return tuple(data[i : i + 32] for i in range(2, len(data), 32))


__all__ = [
    "ArtifactDecodeError",
    "decode_id_sequence",
    "encode_id_sequence",
    "parse_record",
    "record",
]
