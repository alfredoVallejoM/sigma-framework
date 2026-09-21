from __future__ import annotations

import hashlib
from collections import Counter

import pytest

import sigma.binding.parameters as parameter_module
from sigma.binding import (
    derive_trajectory_parameters,
    prepare_binding_v3,
    sample_uniform,
)
from sigma.crypto.primitives import ShakeReader
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3
from sigma.spec.transcript import encode_transcript


class SequenceReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.offset = 0

    def read(self, length: int) -> bytes:
        result = self._data[self.offset : self.offset + length]
        self.offset += length
        return result


def _context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"R4-salt",
        challenge=b"R4-challenge",
        application_context=b"tests/v3/parameters",
    )


def test_uniform_sampler_exhaustively_balances_small_ranges() -> None:
    for width in range(1, 17):
        accepted = 256 - (256 % width)
        counts = Counter(
            sample_uniform(SequenceReader(bytes((value,))), 7, 7 + width - 1)
            for value in range(accepted)
        )
        assert set(counts) == set(range(7, 7 + width))
        assert set(counts.values()) == {accepted // width}


def test_uniform_sampler_rejects_tail_and_preserves_cursor_order() -> None:
    reader = SequenceReader(bytes((255, 4, 5)))
    assert sample_uniform(reader, 10, 12) == 11
    assert reader.offset == 2
    assert sample_uniform(reader, 20, 22) == 22
    assert reader.offset == 3


def test_uniform_sampler_supports_multibyte_and_singleton_ranges() -> None:
    assert sample_uniform(SequenceReader(b"\x01\x2c"), 0, 256) == 43
    assert sample_uniform(SequenceReader(b"\xff"), 91, 91) == 91


@pytest.mark.parametrize(
    ("minimum", "maximum", "error"),
    [
        (True, 2, TypeError),
        (0, False, TypeError),
        (-1, 2, ValueError),
        (3, 2, ValueError),
    ],
)
def test_uniform_sampler_rejects_invalid_ranges(
    minimum: int, maximum: int, error: type[Exception]
) -> None:
    with pytest.raises(error):
        sample_uniform(SequenceReader(b"\x00"), minimum, maximum)


def test_parameter_derivation_is_deterministic_bounded_and_input_bound() -> None:
    context = _context()
    first_binding = prepare_binding_v3(context, BytesSource(b"message-a"))
    second_binding = prepare_binding_v3(context, BytesSource(b"message-b"))

    first = derive_trajectory_parameters(context, first_binding)
    assert derive_trajectory_parameters(context, first_binding) == first
    assert context.t_min <= first.target_round <= context.t_max
    assert context.k_min <= first.state_count <= context.k_max
    assert derive_trajectory_parameters(context, second_binding) != first


def test_parameter_derivation_known_answer() -> None:
    context = _context()
    binding = prepare_binding_v3(context, BytesSource(b"Sigma v3 R4 KAT"))
    parameters = derive_trajectory_parameters(context, binding)

    assert parameters.to_bytes().hex() == (
        "5349474d4133545000030000001c000100000008000000000000000a0002000000080000000000000004"
    )
    seed = encode_transcript(
        DomainIdV3.PARAMETER_DERIVATION,
        ((1, context.to_bytes()), (2, binding.to_bytes())),
    )
    assert len(seed) == 1110
    assert hashlib.sha256(seed).hexdigest() == (
        "f1aa0cc781d92ad252bbf03a7e641712552cf11a6c4c407ab0fdd79295d54c85"
    )
    assert ShakeReader(DomainIdV3.PARAMETER_DERIVATION, seed).read(32).hex() == (
        "46a78e742166328b89b6cfd03badc9870620b31464dfc90bc8bdc6cb47afe115"
    )


def test_parameter_derivation_uses_one_cursor_t_then_k_with_rejections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context()
    binding = prepare_binding_v3(context, BytesSource(b"controlled-reader"))
    reader = SequenceReader(bytes((255, 0, 255, 1)))
    monkeypatch.setattr(parameter_module, "ShakeReader", lambda domain, seed: reader)

    parameters = derive_trajectory_parameters(context, binding)

    assert (parameters.target_round, parameters.state_count) == (2, 3)
    assert reader.offset == 4


def test_parameter_derivation_validates_public_types() -> None:
    context = _context()
    binding = prepare_binding_v3(context, BytesSource(b"typed"))
    with pytest.raises(TypeError, match="context"):
        derive_trajectory_parameters(object(), binding)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="binding"):
        derive_trajectory_parameters(context, object())  # type: ignore[arg-type]
