import hashlib
from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sigma.binding import (
    AnchorV3,
    CardinalityDescriptor,
    JointSignature,
    LengthSignature,
    PersistentBinding,
    PublicTrajectoryHeader,
    TrajectoryParameters,
    TrajectoryWindow,
)
from sigma.layout import LayoutPlacement, LayoutPlan
from sigma.spec.codec_v3 import (
    decode_bytes_sequence,
    decode_record,
    encode_bytes_sequence,
    encode_record,
    validate_record_prefix,
)
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, encode_tlv_field, encode_uint
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import (
    BindingFieldIdV3,
    LayoutKindV3,
    SuiteIdV3,
)
from sigma.suites import registry_v3


def reference_context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"tests/v3",
    )


def binding() -> PersistentBinding:
    cardinality = CardinalityDescriptor(7)
    algorithms = tuple(AlgorithmId)
    components = (b"a" * 64, b"b" * 64, b"c" * 64, b"d" * 64)
    anchor = AnchorV3(SuiteIdV3.REFERENCE_IAP_V3, 7, algorithms, components)
    length_signature = LengthSignature(cardinality, b"l" * 64)
    joint = JointSignature(
        algorithms,
        (b"j" * 64, b"k" * 64, b"m" * 64, b"n" * 64),
    )
    return PersistentBinding(anchor, cardinality, length_signature, joint)


def test_context_v3_round_trip_and_separates_derived_parameters() -> None:
    context = reference_context()

    assert SigmaContextV3.from_bytes(context.to_bytes()) == context
    assert not hasattr(context, "target_round")
    assert not hasattr(context, "state_count")


def test_context_v3_rejects_inverted_ranges_and_branch_mismatch() -> None:
    context = reference_context()

    with pytest.raises(ValueError, match="inverted"):
        replace(context, t_min=33)
    with pytest.raises(ValueError, match="branch_count"):
        replace(context, branch_count=3)


@given(st.integers(min_value=0, max_value=(1 << 64) - 1))
def test_cardinality_round_trip(byte_length: int) -> None:
    value = CardinalityDescriptor(byte_length)
    assert CardinalityDescriptor.from_bytes(value.to_bytes()) == value


def test_binding_types_round_trip_and_enforce_redundancy() -> None:
    value = binding()

    assert PersistentBinding.from_bytes(value.to_bytes()) == value
    with pytest.raises(ValueError, match="anchor length"):
        replace(value, cardinality=CardinalityDescriptor(8))
    with pytest.raises(ValueError, match="descriptor"):
        replace(value, length_signature=LengthSignature(CardinalityDescriptor(8), b"l" * 64))


def test_components_must_match_registered_algorithm_width() -> None:
    algorithms = tuple(AlgorithmId)
    cardinality = CardinalityDescriptor(1)

    with pytest.raises(ValueError, match="algorithm output size"):
        AnchorV3(
            SuiteIdV3.REFERENCE_IAP_V3,
            1,
            algorithms,
            (b"x", b"a" * 64, b"b" * 64, b"c" * 64),
        )
    with pytest.raises(ValueError, match="algorithm output size"):
        JointSignature((AlgorithmId.SHA512,), (b"x",))
    with pytest.raises(ValueError, match="algorithm output size"):
        LengthSignature(cardinality, b"x")


def test_public_header_excludes_joint_signature() -> None:
    value = binding()
    parameters = TrajectoryParameters(8, 2)
    header = PublicTrajectoryHeader(
        value.cardinality,
        value.anchor,
        value.length_signature,
        parameters,
    )

    encoded = header.to_bytes()
    assert PublicTrajectoryHeader.from_bytes(encoded) == header
    assert value.joint_signature.to_bytes() not in encoded
    with pytest.raises(ValueError, match="registered suite"):
        replace(header, parameters=TrajectoryParameters(33, 5))


def test_window_enforces_state_count() -> None:
    parameters = TrajectoryParameters(8, 2)
    window = TrajectoryWindow(parameters, (b"a" * 64, b"b" * 64))

    assert TrajectoryWindow.from_bytes(window.to_bytes()) == window
    with pytest.raises(ValueError, match="state_count"):
        TrajectoryWindow(parameters, (b"a" * 64,))
    with pytest.raises(ValueError, match="length"):
        TrajectoryWindow(TrajectoryParameters(8, 1), (b"x" * 4097,))
    with pytest.raises(ValueError, match="uniform"):
        TrajectoryWindow(parameters, (b"a" * 64, b"b" * 32))


def test_layout_plan_requires_all_fields_in_canonical_order() -> None:
    placements = (
        LayoutPlacement(BindingFieldIdV3.ANCHOR, 0),
        LayoutPlacement(BindingFieldIdV3.CARDINALITY, 1),
        LayoutPlacement(BindingFieldIdV3.LENGTH_SIGNATURE, 1),
        LayoutPlacement(BindingFieldIdV3.JOINT_SIGNATURE, 4),
    )
    plan = LayoutPlan(LayoutKindV3.ROUND, 3, 4, placements)

    assert LayoutPlan.from_bytes(plan.to_bytes()) == plan
    with pytest.raises(ValueError, match="every binding field"):
        LayoutPlan(LayoutKindV3.ROUND, 3, 4, placements[:-1])
    with pytest.raises(ValueError, match="canonical"):
        LayoutPlan(LayoutKindV3.ROUND, 3, 4, tuple(reversed(placements)))
    with pytest.raises(ValueError, match="round_index zero"):
        LayoutPlan(LayoutKindV3.INIT, 3, 4, placements)


def _field_blobs(encoded: bytes) -> list[bytes]:
    blobs: list[bytes] = []
    offset = 14
    while offset < len(encoded):
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        end = offset + 6 + length
        blobs.append(encoded[offset:end])
        offset = end
    assert offset == len(encoded)
    return blobs


def _record_with_fields(encoded: bytes, fields: list[bytes]) -> bytes:
    body = b"".join(fields)
    return encoded[:10] + encode_uint(len(body), 4) + body


def _all_records():
    value = binding()
    parameters = TrajectoryParameters(8, 2)
    header = PublicTrajectoryHeader(
        value.cardinality, value.anchor, value.length_signature, parameters
    )
    placements = tuple(
        LayoutPlacement(field, index) for index, field in enumerate(BindingFieldIdV3)
    )
    plan = LayoutPlan(LayoutKindV3.ROUND, 1, 3, placements)
    return (
        (SigmaContextV3.from_bytes, reference_context().to_bytes()),
        (CardinalityDescriptor.from_bytes, value.cardinality.to_bytes()),
        (AnchorV3.from_bytes, value.anchor.to_bytes()),
        (LengthSignature.from_bytes, value.length_signature.to_bytes()),
        (JointSignature.from_bytes, value.joint_signature.to_bytes()),
        (PersistentBinding.from_bytes, value.to_bytes()),
        (TrajectoryParameters.from_bytes, parameters.to_bytes()),
        (PublicTrajectoryHeader.from_bytes, header.to_bytes()),
        (
            TrajectoryWindow.from_bytes,
            TrajectoryWindow(parameters, (b"a" * 64, b"b" * 64)).to_bytes(),
        ),
        (LayoutPlacement.from_bytes, placements[0].to_bytes()),
        (LayoutPlan.from_bytes, plan.to_bytes()),
    )


@pytest.mark.parametrize(
    "parser,encoded",
    _all_records(),
)
def test_v3_records_reject_trailing_bytes(parser, encoded: bytes) -> None:
    with pytest.raises(DecodeError, match="length mismatch"):
        parser(encoded + b"\x00")


@pytest.mark.parametrize("parser,encoded", _all_records())
def test_v3_records_reject_magic_version_missing_and_unknown_fields(parser, encoded: bytes) -> None:
    fields = _field_blobs(encoded)

    with pytest.raises(DecodeError):
        parser(b"BADMAGIC" + encoded[8:])
    with pytest.raises(DecodeError, match="version"):
        parser(encoded[:8] + encode_uint(4, 2) + encoded[10:])
    with pytest.raises(DecodeError, match="missing"):
        parser(_record_with_fields(encoded, fields[:-1]))
    with pytest.raises(DecodeError):
        parser(_record_with_fields(encoded, [*fields, encode_tlv_field(0xFFFF, b"x")]))


def test_v3_records_reject_duplicate_and_out_of_order_fields() -> None:
    encoded = reference_context().to_bytes()
    fields = _field_blobs(encoded)

    with pytest.raises(DecodeError):
        SigmaContextV3.from_bytes(_record_with_fields(encoded, [*fields, fields[-1]]))
    with pytest.raises(DecodeError):
        SigmaContextV3.from_bytes(_record_with_fields(encoded, [fields[1], fields[0], *fields[2:]]))


def test_semantically_invalid_wire_is_normalized_to_decode_error() -> None:
    encoded = TrajectoryParameters(8, 2).to_bytes()
    fields = _field_blobs(encoded)
    invalid_state_count = encode_tlv_field(2, encode_uint(0, 8))

    with pytest.raises(DecodeError, match="trajectory parameters"):
        TrajectoryParameters.from_bytes(
            _record_with_fields(encoded, [fields[0], invalid_state_count])
        )


def test_context_rejects_unknown_suite_identifier() -> None:
    encoded = reference_context().to_bytes()
    fields = _field_blobs(encoded)
    fields[0] = encode_tlv_field(1, encode_uint(0xFFFF, 2))

    with pytest.raises(DecodeError, match="unknown suite"):
        SigmaContextV3.from_bytes(_record_with_fields(encoded, fields))


def test_envelope_suite_cannot_be_used_for_context_or_binding() -> None:
    with pytest.raises(ValueError, match="unregistered Sigma v3 suite"):
        SigmaContextV3.for_suite(
            SuiteIdV3.EXPLICIT_AUDIT_V3,
            salt=b"",
            challenge=b"",
            application_context=b"",
        )
    with pytest.raises(ValueError, match="unregistered Sigma v3 suite"):
        replace(binding().anchor, suite_id=SuiteIdV3.EXPLICIT_AUDIT_V3)


@pytest.mark.parametrize(
    "encoded",
    (
        b"\x00\x01",
        b"\x00\x01\x00\x01\x00\x00x",
        b"\x00\x01\x00\x00\x00\x01x\x00",
    ),
)
def test_byte_sequences_reject_truncation_and_trailing_data(encoded: bytes) -> None:
    with pytest.raises(DecodeError):
        decode_bytes_sequence(encoded)


def test_small_record_codec_rejects_invalid_types_and_bounds() -> None:
    magic = b"SIGMA3ZZ"
    encoded = encode_record(magic, ((1, b"x"),))
    validate_record_prefix(encoded, magic=magic, expected_fields=((1, b"x"),))

    with pytest.raises(DecodeError, match="must be bytes"):
        validate_record_prefix("bad", magic=magic, expected_fields=())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exactly 8"):
        validate_record_prefix(encoded, magic=b"short", expected_fields=())
    with pytest.raises(DecodeError, match="magic or truncated"):
        validate_record_prefix(b"short", magic=magic, expected_fields=())

    wrong_version = encoded[:8] + b"\x00\x02" + encoded[10:]
    with pytest.raises(DecodeError, match="version"):
        validate_record_prefix(wrong_version, magic=magic, expected_fields=())
    oversized = encoded[:10] + encode_uint((1 << 20) + 1, 4)
    with pytest.raises(DecodeError, match="too large"):
        validate_record_prefix(oversized, magic=magic, expected_fields=())
    empty_record = encode_record(magic, ())
    with pytest.raises(DecodeError, match="discriminator"):
        validate_record_prefix(empty_record, magic=magic, expected_fields=((1, b"x"),))

    with pytest.raises(TypeError, match="must be bytes"):
        decode_record("bad", magic=magic, allowed_tags=frozenset())  # type: ignore[arg-type]
    with pytest.raises(DecodeError, match="body is too large"):
        decode_record(oversized, magic=magic, allowed_tags=frozenset())


def test_byte_sequence_encoder_rejects_invalid_items_and_bounds() -> None:
    with pytest.raises(ValueError, match="item count"):
        encode_bytes_sequence(())
    with pytest.raises(ValueError, match="item count"):
        encode_bytes_sequence((b"x",) * 65)
    with pytest.raises(TypeError, match="must be bytes"):
        encode_bytes_sequence(("x",))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="item length"):
        encode_bytes_sequence((b"",))


def test_record_size_is_rejected_before_tlv_parsing() -> None:
    encoded = reference_context().to_bytes()
    oversized = encoded[:10] + encode_uint((1 << 20) + 1, 4) + b"x" * ((1 << 20) + 1)

    with pytest.raises(DecodeError, match="too large"):
        SigmaContextV3.from_bytes(oversized)


def test_suite_registry_is_immutable() -> None:
    with pytest.raises(TypeError):
        registry_v3._SUITES_V3[SuiteIdV3.REFERENCE_IAP_V3] = registry_v3.REFERENCE_IAP_V3  # type: ignore[index]


@pytest.mark.parametrize(
    "changes",
    (
        {"chunk_size": -1},
        {"state_size": True},
        {"anchor_algorithms": ("not-an-algorithm",)},
        {"length_algorithm": 1},
    ),
)
def test_suite_descriptor_rejects_invalid_construction(changes) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(registry_v3.REFERENCE_IAP_V3, **changes)


def test_record_encoder_and_decoder_share_size_limit() -> None:
    with pytest.raises(ValueError, match="too large"):
        encode_record(b"SIGMA3ZZ", ((1, b"a" * 600_000), (2, b"b" * 600_000)))


def test_r1_record_known_answer_hashes() -> None:
    expected = {
        "SigmaContextV3": "ebccc2d2329211b06e16789fb4910b61cec9ff0750ba6ba27149acd5617a08c4",
        "CardinalityDescriptor": "9e176314c9a9fb9186c76c577bcd79947766bd005a27732551de7d640db05c98",
        "AnchorV3": "3effcdc50709102d17551c4465789899f60521ecdd975eb27886682d731cde73",
        "LengthSignature": "5d0ea6d78622a5052a74533d1baef2783bf51a55026c27eab9fa3ff0c1dcbaf2",
        "JointSignature": "7dc16ad5b5f907241fcc4c0b26837e366c8326259e17474d9b628d5f82202bc2",
        "PersistentBinding": "8677313c30faa3991338637d99524a2e354aa1d1c8961025591d34fab035673b",
        "TrajectoryParameters": "f6ed24720eed68f14048c16ce493998779d21af2a4e24c4999c49ed579d5536e",
        "PublicTrajectoryHeader": "e573835475db17cd12d05da169d832c6062b2930f0712add2e841a7ce3fc2f14",
        "TrajectoryWindow": "d7af1e0af8794010e49dc14185e90dc49355dff6d279a8999ba2c03034ee6c01",
        "LayoutPlacement": "235a652696ba76a84942d25636f85cb7015f2e9e2fb602761f28402726fba769",
        "LayoutPlan": "80f56404b84af9cadfb46d243df946fe6b6288d44ccf70041048f166989c4182",
    }
    actual = {
        parser.__self__.__name__: hashlib.sha256(encoded).hexdigest()
        for parser, encoded in _all_records()
    }

    assert actual == expected
