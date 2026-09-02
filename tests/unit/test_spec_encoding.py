import struct
from typing import Any

import pytest

from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import DecodeError, decode_tlv, encode_tlv, encode_uint
from sigma.spec.ids import CONTEXT_MAGIC


def test_context_round_trip_is_unique() -> None:
    context = SigmaContextV2(salt=b"salt", challenge=b"challenge", application_context=b"tests")
    encoded = context.to_bytes()
    assert SigmaContextV2.from_bytes(encoded) == context
    assert SigmaContextV2.from_bytes(encoded).to_bytes() == encoded


def test_default_context_known_answer() -> None:
    assert SigmaContextV2().to_bytes().hex() == (
        "5349474d4143545800020000005e00010000000200010002000000020001"
        "000300000002000100040000000200010005000000040000000100060000"
        "0002000200070000000a0004000100020003000400080000000400000000"
        "000900000000000a00000000000b00000000"
    )


@pytest.mark.parametrize("value,width", [(-1, 2), (256, 1), (65536, 2), (1 << 32, 4)])
def test_integer_overflow_is_rejected(value: int, width: int) -> None:
    with pytest.raises(ValueError):
        encode_uint(value, width)


def test_tlv_requires_strict_order_and_unique_tags() -> None:
    with pytest.raises(ValueError):
        encode_tlv(((2, b"a"), (1, b"b")))
    with pytest.raises(ValueError):
        encode_tlv(((1, b"a"), (1, b"b")))


def test_tlv_rejects_unknown_and_truncated_fields() -> None:
    with pytest.raises(DecodeError, match="unknown"):
        decode_tlv(struct.pack(">HI", 99, 0), allowed_tags=frozenset({1}))
    with pytest.raises(DecodeError, match="truncated"):
        decode_tlv(struct.pack(">HI", 1, 3) + b"x", allowed_tags=frozenset({1}))


def test_context_rejects_trailing_bytes() -> None:
    with pytest.raises(DecodeError, match="length mismatch"):
        SigmaContextV2.from_bytes(SigmaContextV2().to_bytes() + b"\x00")


def test_every_truncated_context_prefix_is_rejected() -> None:
    encoded = SigmaContextV2().to_bytes()
    for end in range(len(encoded)):
        with pytest.raises(DecodeError):
            SigmaContextV2.from_bytes(encoded[:end])


def test_context_rejects_noncanonical_field_order() -> None:
    encoded = bytearray(SigmaContextV2().to_bytes())
    body_offset = len(CONTEXT_MAGIC) + 6
    first_length = 6 + int.from_bytes(encoded[body_offset + 2 : body_offset + 6], "big")
    first = encoded[body_offset : body_offset + first_length]
    second_start = body_offset + first_length
    second_length = 6 + int.from_bytes(encoded[second_start + 2 : second_start + 6], "big")
    second = encoded[second_start : second_start + second_length]
    encoded[body_offset : second_start + second_length] = second + first
    with pytest.raises(DecodeError, match="out of order"):
        SigmaContextV2.from_bytes(bytes(encoded))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target_round": -1},
        {"target_round": 1_000_001},
        {"state_count": 0},
        {"state_count": 17},
        {"branches": ()},
    ],
)
def test_context_resource_limits(kwargs: dict[str, Any]) -> None:
    with pytest.raises((TypeError, ValueError)):
        SigmaContextV2(**kwargs)
