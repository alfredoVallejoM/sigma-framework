"""Strict canonical codecs for Sigma Tree V1."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from .ids import TREE_DOMAIN_MAGIC, TREE_WIRE_VERSION, TreeDomainId

_TLV_HEADER = struct.Struct(">HI")
_MAX_FIELD = 1 << 20
MAX_TREE_RECORD_BYTES = 8 << 20


class TreeDecodeError(ValueError):
    """Raised when a Sigma Tree record is not canonical."""


def u16(value: int) -> bytes:
    return _uint(value, 2)


def u32(value: int) -> bytes:
    return _uint(value, 4)


def u64(value: int) -> bytes:
    return _uint(value, 8)


def _uint(value: int, width: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("integer field must be int")
    if not 0 <= value < 1 << (8 * width):
        raise ValueError("integer field is out of range")
    return value.to_bytes(width, "big")


def decode_uint(data: bytes, width: int) -> int:
    if not isinstance(data, bytes) or len(data) != width:
        raise TreeDecodeError(f"expected {width}-byte integer")
    return int.from_bytes(data, "big")


def tlv(fields: Iterable[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    previous = 0
    for tag, value in fields:
        if isinstance(tag, bool) or not isinstance(tag, int) or not 1 <= tag <= 0xFFFF:
            raise ValueError("invalid TLV tag")
        if tag <= previous:
            raise ValueError("TLV tags must be strictly increasing")
        if not isinstance(value, bytes):
            raise TypeError("TLV value must be bytes")
        if len(value) > _MAX_FIELD:
            raise ValueError("TLV field exceeds Sigma Tree V1 limit")
        out += _TLV_HEADER.pack(tag, len(value))
        out += value
        previous = tag
    return bytes(out)


def parse_tlv(data: bytes, *, allowed: frozenset[int]) -> dict[int, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("record body must be bytes")
    out: dict[int, bytes] = {}
    offset = 0
    previous = 0
    while offset < len(data):
        if len(data) - offset < _TLV_HEADER.size:
            raise TreeDecodeError("truncated TLV header")
        tag, length = _TLV_HEADER.unpack_from(data, offset)
        offset += _TLV_HEADER.size
        if tag not in allowed:
            raise TreeDecodeError(f"unknown TLV tag: {tag}")
        if tag <= previous:
            raise TreeDecodeError("TLV tags are duplicate or out of order")
        if length > _MAX_FIELD:
            raise TreeDecodeError("TLV field exceeds Sigma Tree V1 limit")
        end = offset + length
        if end > len(data):
            raise TreeDecodeError("truncated TLV field")
        out[tag] = data[offset:end]
        offset = end
        previous = tag
    if set(out) != set(allowed):
        raise TreeDecodeError("missing required TLV fields")
    return out


def record(magic: bytes, fields: Iterable[tuple[int, bytes]]) -> bytes:
    if not isinstance(magic, bytes) or len(magic) != 8:
        raise ValueError("record magic must contain exactly 8 bytes")
    body = tlv(fields)
    return magic + u16(TREE_WIRE_VERSION) + u32(len(body)) + body


def parse_record(data: bytes, *, magic: bytes, allowed: frozenset[int]) -> dict[int, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("record must be bytes")
    if len(data) > MAX_TREE_RECORD_BYTES:
        raise TreeDecodeError("record exceeds Sigma Tree V1 total-size limit")
    header = 14
    if len(data) < header or data[:8] != magic:
        raise TreeDecodeError("invalid or truncated record magic")
    version = decode_uint(data[8:10], 2)
    if version != TREE_WIRE_VERSION:
        raise TreeDecodeError(f"unsupported Sigma Tree wire version: {version}")
    body_len = decode_uint(data[10:14], 4)
    if body_len != len(data) - header:
        raise TreeDecodeError("record length mismatch or trailing bytes")
    return parse_tlv(data[header:], allowed=allowed)


def domain_tag(domain: TreeDomainId) -> bytes:
    if not isinstance(domain, TreeDomainId):
        raise TypeError("domain must be TreeDomainId")
    return TREE_DOMAIN_MAGIC + u16(int(domain))


def encode_items(items: Iterable[bytes], *, max_items: int) -> bytes:
    values = tuple(items)
    if len(values) > max_items:
        raise ValueError("too many sequence items")
    out = bytearray(u16(len(values)))
    for value in values:
        if not isinstance(value, bytes):
            raise TypeError("sequence items must be bytes")
        if len(value) > _MAX_FIELD:
            raise ValueError("sequence item too large")
        out += u32(len(value)) + value
    return bytes(out)


def decode_items(data: bytes, *, max_items: int) -> tuple[bytes, ...]:
    if len(data) < 2:
        raise TreeDecodeError("truncated sequence")
    count = decode_uint(data[:2], 2)
    if count > max_items:
        raise TreeDecodeError("sequence item count exceeds limit")
    offset = 2
    values: list[bytes] = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise TreeDecodeError("truncated sequence length")
        length = decode_uint(data[offset : offset + 4], 4)
        offset += 4
        if length > _MAX_FIELD:
            raise TreeDecodeError("sequence item too large")
        end = offset + length
        if end > len(data):
            raise TreeDecodeError("truncated sequence item")
        values.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise TreeDecodeError("trailing bytes in sequence")
    return tuple(values)
