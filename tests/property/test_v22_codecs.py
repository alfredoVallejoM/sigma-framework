from collections.abc import Callable
from contextlib import suppress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sigma.anchors import AnchorEvidence, StreamWide
from sigma.applications.kdf_argon2id import (
    KDF_FINAL_DOMAIN,
    Argon2idParameters,
    SigmaKdfResult,
)
from sigma.outputs import SigmaDigestV2
from sigma.presets import lightweight_v2_2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError
from sigma.v2 import hash_bytes

PROPERTY_SETTINGS = settings(max_examples=100, derandomize=True, deadline=None)


@st.composite
def contexts(draw) -> SigmaContextV2:
    return lightweight_v2_2(
        target_round=draw(st.integers(min_value=0, max_value=8)),
        state_count=draw(st.integers(min_value=1, max_value=4)),
        salt=draw(st.binary(max_size=64)),
        challenge=draw(st.binary(max_size=64)),
        application_context=draw(st.binary(max_size=64)),
    )


@PROPERTY_SETTINGS
@given(context=contexts())
def test_registered_context_round_trip_property(context: SigmaContextV2) -> None:
    assert SigmaContextV2.from_bytes(context.to_bytes()) == context


@PROPERTY_SETTINGS
@given(context=contexts(), message=st.binary(max_size=256))
def test_digest_and_evidence_round_trip_property(context: SigmaContextV2, message: bytes) -> None:
    anchor = StreamWide.compute(context, (message,))
    digest = hash_bytes(message, context)
    assert AnchorEvidence.from_bytes(anchor.to_bytes(), context) == anchor
    assert SigmaDigestV2.from_bytes(digest.to_bytes()) == digest


def _never_crashes_unclassified(parser: Callable[[bytes], object], data: bytes) -> None:
    with suppress(DecodeError, TypeError, ValueError):
        parser(data)


@PROPERTY_SETTINGS
@given(data=st.binary(max_size=2048))
def test_public_parsers_reject_arbitrary_bytes_without_unclassified_crashes(data: bytes) -> None:
    context = lightweight_v2_2()
    parsers: tuple[Callable[[bytes], object], ...] = (
        SigmaContextV2.from_bytes,
        SigmaDigestV2.from_bytes,
        lambda value: AnchorEvidence.from_bytes(value, context),
        SigmaKdfResult.from_bytes,
    )
    for parser in parsers:
        _never_crashes_unclassified(parser, data)


@PROPERTY_SETTINGS
@given(
    salt=st.binary(min_size=8, max_size=32),
    base=st.binary(min_size=1, max_size=64),
    output_length=st.integers(min_value=16, max_value=128),
)
def test_kdf_result_round_trip_property(salt: bytes, base: bytes, output_length: int) -> None:
    parameters = Argon2idParameters(19_456, 2, 1, output_length=output_length)
    context = lightweight_v2_2(
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + parameters.to_bytes(),
    )
    result = SigmaKdfResult.bind(parameters, salt, hash_bytes(base, context))
    assert SigmaKdfResult.from_bytes(result.to_bytes()) == result


@PROPERTY_SETTINGS
@given(value=st.one_of(st.booleans(), st.floats(), st.text(), st.none()))
def test_numeric_context_fields_never_coerce_other_types(value: object) -> None:
    with pytest.raises(ValueError):
        SigmaContextV2(target_round=value)  # type: ignore[arg-type]
