"""Canonical codecs for small, typed Sigma v3 records."""

from __future__ import annotations

from collections.abc import Iterable

from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint

RECORD_VERSION = 3
MAX_SEQUENCE_ITEMS = 64
MAX_SEQUENCE_ITEM_LENGTH = 1 << 16
MAX_RECORD_BODY_LENGTH = 1 << 20


def validate_record_prefix(
    data: bytes,
    *,
    magic: bytes,
    expected_fields: tuple[tuple[int, bytes], ...],
) -> None:
    """Reject fixed record discriminators before copying or decoding its body."""

    if not isinstance(data, bytes):
        raise DecodeError("record must be bytes")
    if not isinstance(magic, bytes) or len(magic) != 8:
        raise ValueError("record magic must be exactly 8 bytes")
    if len(data) < 14 or data[:8] != magic:
        raise DecodeError("invalid record magic or truncated header")
    if decode_uint(data[8:10], 2) != RECORD_VERSION:
        raise DecodeError("unsupported record version")
    body_length = decode_uint(data[10:14], 4)
    if body_length > MAX_RECORD_BODY_LENGTH:
        raise DecodeError("record body is too large")
    if len(data) != 14 + body_length:
        raise DecodeError("record length does not match body")

    offset = 14
    for expected_tag, expected_value in expected_fields:
        if offset + 6 > len(data):
            raise DecodeError("truncated record discriminator")
        tag = decode_uint(data[offset : offset + 2], 2)
        length = decode_uint(data[offset + 2 : offset + 6], 4)
        if tag != expected_tag or length != len(expected_value):
            raise DecodeError("unexpected record discriminator")
        end = offset + 6 + length
        if end > len(data) or data[offset + 6 : end] != expected_value:
            raise DecodeError("unexpected record discriminator")
        offset = end


def encode_record(magic: bytes, fields: Iterable[tuple[int, bytes]]) -> bytes:
    if not isinstance(magic, bytes) or len(magic) != 8:
        raise ValueError("record magic must be exactly 8 bytes")
    body = encode_tlv(fields)
    if len(body) > MAX_RECORD_BODY_LENGTH:
        raise ValueError("record body is too large")
    return magic + encode_uint(RECORD_VERSION, 2) + encode_uint(len(body), 4) + body


def decode_record(
    data: bytes,
    *,
    magic: bytes,
    allowed_tags: frozenset[int],
    required_tags: frozenset[int] | None = None,
) -> dict[int, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("record encoding must be bytes")
    if len(data) < 14 or data[:8] != magic:
        raise DecodeError("invalid record magic")
    if len(data) > 14 + MAX_RECORD_BODY_LENGTH:
        raise DecodeError("record is too large")
    if decode_uint(data[8:10], 2) != RECORD_VERSION:
        raise DecodeError("unsupported record version")
    body_length = decode_uint(data[10:14], 4)
    if body_length > MAX_RECORD_BODY_LENGTH:
        raise DecodeError("record body is too large")
    if body_length != len(data) - 14:
        raise DecodeError("record length mismatch")
    fields = decode_tlv(data[14:], allowed_tags=allowed_tags)
    required = allowed_tags if required_tags is None else required_tags
    if set(fields) != set(required):
        raise DecodeError("missing required record field")
    return fields


def encode_bytes_sequence(values: Iterable[bytes]) -> bytes:
    items = tuple(values)
    if not items or len(items) > MAX_SEQUENCE_ITEMS:
        raise ValueError("byte sequence item count is out of range")
    output = bytearray(encode_uint(len(items), 2))
    for item in items:
        if not isinstance(item, bytes):
            raise TypeError("byte sequence items must be bytes")
        if not item or len(item) > MAX_SEQUENCE_ITEM_LENGTH:
            raise ValueError("byte sequence item length is out of range")
        output.extend(encode_uint(len(item), 4))
        output.extend(item)
    return bytes(output)


def decode_bytes_sequence(data: bytes) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) < 2:
        raise DecodeError("truncated byte sequence")
    count = decode_uint(data[:2], 2)
    if not 0 < count <= MAX_SEQUENCE_ITEMS:
        raise DecodeError("byte sequence item count is out of range")
    offset = 2
    items: list[bytes] = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise DecodeError("truncated byte sequence length")
        length = decode_uint(data[offset : offset + 4], 4)
        offset += 4
        if not 0 < length <= MAX_SEQUENCE_ITEM_LENGTH or offset + length > len(data):
            raise DecodeError("invalid byte sequence item length")
        items.append(data[offset : offset + length])
        offset += length
    if offset != len(data):
        raise DecodeError("trailing byte sequence data")
    return tuple(items)
