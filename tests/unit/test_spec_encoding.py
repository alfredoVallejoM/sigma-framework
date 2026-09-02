import struct
from typing import Any

import pytest

from sigma.spec.context import SigmaContextV2, parse_context, validate_registered_context
from sigma.spec.encoding import (
    MAX_FIELD_LENGTH,
    DecodeError,
    decode_tlv,
    decode_u16_sequence,
    decode_uint,
    domain_tag,
    encode_tlv,
    encode_u16_sequence,
    encode_uint,
)
from sigma.spec.ids import (
    CONTEXT_MAGIC,
    AlgorithmId,
    AnchorProfileId,
    OutputProfileId,
    RoundProfileId,
    SuiteId,
)
from sigma.suites.registry import get_suite


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


@pytest.mark.parametrize("width", [0, 3, 5, 16])
def test_integer_width_is_closed(width: int) -> None:
    with pytest.raises(ValueError, match="width"):
        encode_uint(0, width)


@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_integer_codec_exact_boundaries(width: int) -> None:
    maximum = (1 << (width * 8)) - 1
    assert encode_uint(0, width) == b"\x00" * width
    assert decode_uint(encode_uint(maximum, width), width) == maximum
    with pytest.raises(DecodeError):
        decode_uint(b"\x00" * (width + 1), width)


def test_tlv_requires_strict_order_and_unique_tags() -> None:
    with pytest.raises(ValueError):
        encode_tlv(((2, b"a"), (1, b"b")))
    with pytest.raises(ValueError):
        encode_tlv(((1, b"a"), (1, b"b")))


def test_tlv_tag_and_value_boundaries_are_exact() -> None:
    assert decode_tlv(
        encode_tlv(((1, b""), (0xFFFF, b"x"))), allowed_tags=frozenset({1, 0xFFFF})
    ) == {
        1: b"",
        0xFFFF: b"x",
    }
    for tag in (0, 0x10000, True, 1.0):
        with pytest.raises((TypeError, ValueError)):
            encode_tlv(((tag, b""),))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="bytes"):
        encode_tlv(((1, bytearray()),))  # type: ignore[arg-type]


def test_tlv_field_length_budget_accepts_limit_and_rejects_next_byte() -> None:
    at_limit = b"x" * MAX_FIELD_LENGTH
    assert decode_tlv(encode_tlv(((1, at_limit),)), allowed_tags=frozenset({1}))[1] == at_limit
    with pytest.raises(ValueError, match="limit"):
        encode_tlv(((1, at_limit + b"x"),))


def test_tlv_rejects_unknown_and_truncated_fields() -> None:
    with pytest.raises(DecodeError, match="unknown"):
        decode_tlv(struct.pack(">HI", 99, 0), allowed_tags=frozenset({1}))
    with pytest.raises(DecodeError, match="truncated"):
        decode_tlv(struct.pack(">HI", 1, 3) + b"x", allowed_tags=frozenset({1}))


def test_tlv_rejects_every_truncated_header_and_noncanonical_order() -> None:
    header = struct.pack(">HI", 1, 0)
    for end in range(1, len(header)):
        with pytest.raises(DecodeError, match="header"):
            decode_tlv(header[:end], allowed_tags=frozenset({1}))
    with pytest.raises(DecodeError, match="header"):
        decode_tlv(header + b"\x00", allowed_tags=frozenset({1, 2}))
    duplicate = struct.pack(">HI", 1, 0) * 2
    with pytest.raises(DecodeError, match="order"):
        decode_tlv(duplicate, allowed_tags=frozenset({1}))
    descending = struct.pack(">HI", 2, 0) + struct.pack(">HI", 1, 0)
    with pytest.raises(DecodeError, match="order"):
        decode_tlv(descending, allowed_tags=frozenset({1, 2}))


def test_u16_sequence_and_domain_boundaries() -> None:
    assert decode_u16_sequence(b"\x00\x00") == ()
    values = tuple(range(0xFFFF))
    encoded = encode_u16_sequence(values)
    assert decode_u16_sequence(encoded) == values
    with pytest.raises(ValueError, match="too many"):
        encode_u16_sequence((*values, 0))
    with pytest.raises(DecodeError, match="truncated"):
        decode_u16_sequence(b"\x00")
    with pytest.raises(DecodeError, match="count"):
        decode_u16_sequence(b"\x00\x01")
    assert domain_tag(0).endswith(b"\x00\x00")
    assert domain_tag(0xFFFF).endswith(b"\xff\xff")
    with pytest.raises(ValueError):
        domain_tag(0x10000)


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


def test_syntax_only_parser_does_not_authorize_mismatched_suite() -> None:
    mismatched = SigmaContextV2(anchor_profile=AnchorProfileId.CROSS_WIDE)
    assert parse_context(mismatched.to_bytes()) == mismatched
    with pytest.raises(DecodeError, match="registered suite"):
        SigmaContextV2.from_bytes(mismatched.to_bytes())
    with pytest.raises(DecodeError, match="registered suite"):
        validate_registered_context(mismatched)


def test_registered_context_matrix_accepts_only_exact_suite_tuples() -> None:
    branch_sets = (
        (AlgorithmId.SHA512, AlgorithmId.SHA3_512),
        (
            AlgorithmId.SHA512,
            AlgorithmId.SHA3_512,
            AlgorithmId.BLAKE2B_512,
            AlgorithmId.SHAKE256_512,
        ),
    )
    for suite_id in SuiteId:
        suite = get_suite(suite_id)
        for anchor_profile in AnchorProfileId:
            for round_profile in RoundProfileId:
                for output_profile in OutputProfileId:
                    for branches in branch_sets:
                        for chunk_size in (0, 65536):
                            context = SigmaContextV2(
                                suite_id=suite_id,
                                anchor_profile=anchor_profile,
                                round_profile=round_profile,
                                output_profile=output_profile,
                                branches=branches,
                                chunk_size=chunk_size,
                            )
                            expected = (
                                anchor_profile is suite.anchor_profile
                                and round_profile is suite.round_profile
                                and output_profile is suite.output_profile
                                and branches == suite.branches
                                and chunk_size
                                == (65536 if anchor_profile is AnchorProfileId.TREE_WIDE else 0)
                            )
                            if expected:
                                assert validate_registered_context(context) is context
                                assert SigmaContextV2.from_bytes(context.to_bytes()) == context
                            else:
                                with pytest.raises(DecodeError):
                                    validate_registered_context(context)
