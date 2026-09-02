import io

import pytest

from sigma.anchors import AnchorEvidence, CrossWide, StreamWide
from sigma.backends import MultiprocessingTreeBackend
from sigma.presets import paranoid_deep_v2
from sigma.rounds import Deep, TraceConfig, TracePolicy, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import encode_uint
from sigma.v2 import hash_reader
from sigma.validation import ValidationError

INVALID_NUMBERS = (True, False, 1.0, "1", None)


@pytest.mark.parametrize("value", INVALID_NUMBERS)
@pytest.mark.parametrize("field", ("target_round", "state_count", "chunk_size"))
def test_context_rejects_non_integer_numeric_fields(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        SigmaContextV2(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("value", INVALID_NUMBERS)
def test_unsigned_encoder_rejects_implicit_numeric_coercion(value: object) -> None:
    with pytest.raises(ValidationError):
        encode_uint(value, 4)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", INVALID_NUMBERS)
def test_backend_and_reader_reject_non_integer_controls(value: object) -> None:
    with pytest.raises(ValidationError):
        MultiprocessingTreeBackend(value)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        hash_reader(io.BytesIO(b"abc"), read_size=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", (*INVALID_NUMBERS, -1, 2**64))
def test_anchor_evidence_rejects_invalid_message_length(value: object) -> None:
    context = SigmaContextV2()
    anchor = StreamWide.compute(context, (b"abc",))
    with pytest.raises(ValidationError):
        AnchorEvidence(anchor.algorithms, anchor.roots, value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", (*INVALID_NUMBERS, -1, 2**64))
def test_round_engines_reject_invalid_indices(value: object) -> None:
    context = SigmaContextV2()
    anchor = StreamWide.compute(context, (b"abc",))
    with pytest.raises(ValidationError):
        WideOnce(context).next_state(anchor, value, b"s" * 64)  # type: ignore[arg-type]

    deep_context = paranoid_deep_v2()
    deep_anchor = CrossWide.compute(deep_context, (b"abc",))
    with pytest.raises(ValidationError):
        Deep(deep_context).next_state(deep_anchor, value, b"s" * 64)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ("every_n", "max_entries"))
@pytest.mark.parametrize("value", INVALID_NUMBERS)
def test_trace_controls_reject_non_integer_values(field: str, value: object) -> None:
    arguments = {field: value, "policy": TracePolicy.EVERY_N}
    with pytest.raises((TypeError, ValueError)):
        TraceConfig(**arguments)  # type: ignore[arg-type]


def test_numeric_bounds_are_rejected_before_work() -> None:
    with pytest.raises(ValidationError):
        SigmaContextV2(target_round=-1)
    with pytest.raises(ValidationError):
        SigmaContextV2(target_round=1_000_001)
    with pytest.raises(ValidationError):
        MultiprocessingTreeBackend(257)
    with pytest.raises(ValidationError):
        encode_uint(2**32, 4)
