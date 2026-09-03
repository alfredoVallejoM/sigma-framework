"""Small canonical TLV codec used by Sigma v2.

Fields are strictly increasing unsigned 16-bit tags followed by a 32-bit
big-endian length. The parser rejects every alternative representation.
"""

import struct
from typing import Dict, FrozenSet, Iterable, Tuple

from sigma.validation import require_int

MAX_FIELD_LENGTH = 1 << 20
_TLV_HEADER = struct.Struct(">HI")
_DOMAIN_MAGIC = b"SIGMADST"


class DecodeError(ValueError):
    """Raised when bytes are not a canonical Sigma encoding."""


def encode_uint(value: int, width: int) -> bytes:
    if width not in (1, 2, 4, 8):
        raise ValueError("integer width must be 1, 2, 4, or 8 bytes")
    checked = require_int("value", value, minimum=0, maximum=(1 << (width * 8)) - 1)
    return checked.to_bytes(width, "big")


def decode_uint(data: bytes, width: int) -> int:
    if not isinstance(data, bytes):
        raise TypeError("encoded integer must be bytes")
    if width not in (1, 2, 4, 8):
        raise ValueError("integer width must be 1, 2, 4, or 8 bytes")
    if len(data) != width:
        raise DecodeError(f"expected {width}-byte integer")
    return int.from_bytes(data, "big")


def encode_tlv_field(tag: int, value: bytes) -> bytes:
    """Encode one validated field for fixed-schema codecs."""

    if isinstance(tag, bool) or not isinstance(tag, int) or not 0 < tag <= 0xFFFF:
        raise ValueError("TLV tag must be an integer in [1, 65535]")
    if not isinstance(value, bytes):
        raise TypeError("TLV values must be bytes")
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError("TLV field exceeds the configured limit")
    return _TLV_HEADER.pack(tag, len(value)) + value


def encode_tlv(fields: Iterable[Tuple[int, bytes]]) -> bytes:
    output = bytearray()
    previous = -1
    for tag, value in fields:
        encoded = encode_tlv_field(tag, value)
        if tag <= previous:
            raise ValueError("TLV tags must be unique and strictly increasing")
        output += encoded
        previous = tag
    return bytes(output)


def decode_tlv(data: bytes, *, allowed_tags: FrozenSet[int]) -> Dict[int, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("encoded value must be bytes")
    fields: Dict[int, bytes] = {}
    offset = 0
    previous = -1
    while offset < len(data):
        if len(data) - offset < _TLV_HEADER.size:
            raise DecodeError("truncated TLV header")
        tag, length = _TLV_HEADER.unpack_from(data, offset)
        offset += _TLV_HEADER.size
        if tag not in allowed_tags:
            raise DecodeError(f"unknown TLV tag: {tag}")
        if tag <= previous:
            raise DecodeError("TLV tags are duplicated or out of order")
        if length > MAX_FIELD_LENGTH:
            raise DecodeError("TLV field exceeds the configured limit")
        end = offset + length
        if end > len(data):
            raise DecodeError("truncated TLV value")
        fields[tag] = data[offset:end]
        offset = end
        previous = tag
    return fields


def encode_u16_sequence(values: Iterable[int]) -> bytes:
    items = tuple(values)
    if len(items) > 0xFFFF:
        raise ValueError("too many sequence items")
    return encode_uint(len(items), 2) + b"".join(encode_uint(item, 2) for item in items)


def decode_u16_sequence(data: bytes) -> Tuple[int, ...]:
    if len(data) < 2:
        raise DecodeError("truncated sequence count")
    count = decode_uint(data[:2], 2)
    if len(data) != 2 + count * 2:
        raise DecodeError("sequence length does not match its count")
    return tuple(decode_uint(data[i : i + 2], 2) for i in range(2, len(data), 2))


def domain_tag(domain_id: int) -> bytes:
    """Return the fixed-width, globally separated tag for a registered domain."""

    return _DOMAIN_MAGIC + encode_uint(domain_id, 2)
