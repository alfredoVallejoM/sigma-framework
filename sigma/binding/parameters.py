"""Deterministic trajectory-parameter derivation for Sigma v3."""

from __future__ import annotations

from typing import Protocol

from sigma.binding.types import PersistentBinding, TrajectoryParameters
from sigma.crypto.primitives import ShakeReader
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3
from sigma.spec.transcript import encode_transcript
from sigma.suites.registry_v3 import get_suite_v3


class ByteReader(Protocol):
    """Minimal interface required by unbiased integer sampling."""

    def read(self, length: int) -> bytes: ...


def sample_uniform(reader: ByteReader, minimum: int, maximum: int) -> int:
    """Sample uniformly from the inclusive range using rejection sampling."""
    if not hasattr(reader, "read") or not callable(reader.read):
        raise TypeError("reader must provide read(length)")
    for name, value in (("minimum", minimum), ("maximum", maximum)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be int")
    if minimum < 0:
        raise ValueError("minimum must be non-negative")
    if maximum < minimum:
        raise ValueError("sample range is inverted")

    width = maximum - minimum + 1
    byte_count = max(1, ((width - 1).bit_length() + 7) // 8)
    sample_space = 1 << (8 * byte_count)
    acceptance_limit = sample_space - (sample_space % width)

    while True:
        raw = reader.read(byte_count)
        if not isinstance(raw, bytes):
            raise TypeError("reader output must be bytes")
        if len(raw) != byte_count:
            raise ValueError("reader returned an unexpected number of bytes")
        candidate = int.from_bytes(raw, "big")
        if candidate < acceptance_limit:
            return minimum + (candidate % width)


def derive_trajectory_parameters(
    context: SigmaContextV3,
    binding: PersistentBinding,
) -> TrajectoryParameters:
    """Derive ``t`` then ``k`` from the canonical context and binding."""
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if not isinstance(binding, PersistentBinding):
        raise TypeError("binding must be PersistentBinding")
    if binding.anchor.suite_id != context.suite_id:
        raise ValueError("binding and context suites do not match")

    suite = get_suite_v3(context.suite_id)
    transcript = encode_transcript(
        DomainIdV3.PARAMETER_DERIVATION,
        (
            (1, context.to_bytes()),
            (2, binding.to_bytes()),
        ),
    )
    reader = ShakeReader(DomainIdV3.PARAMETER_DERIVATION, transcript)
    target_round = sample_uniform(reader, suite.t_min, suite.t_max)
    state_count = sample_uniform(reader, suite.k_min, suite.k_max)
    return TrajectoryParameters(target_round, state_count)
