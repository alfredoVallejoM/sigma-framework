import io
import os
import random

import pytest

from sigma.backends import SERIAL_BACKEND, MultiprocessingTreeBackend
from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
    reference_v2_2,
    simultaneous_v2_2,
)
from sigma.rounds import WideOnce
from sigma.v2 import hash_bytes, hash_chunks, hash_file, hash_reader, trace_bytes

PRESETS = (
    reference_v2_2,
    lightweight_v2_2,
    simultaneous_v2_2,
    paranoid_wide_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
)


def partitions(payload: bytes, seed: int):
    generator = random.Random(seed)
    offset = 0
    yield b""
    while offset < len(payload):
        length = generator.randint(1, 8192)
        yield payload[offset : offset + length]
        offset += length
        if generator.random() < 0.2:
            yield b""


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 65535, 65536, 65537])
def test_adapter_and_partition_canonicality(preset, size: int, tmp_path) -> None:
    payload = bytes((index * 37 + size) % 256 for index in range(size))
    context = preset(target_round=2, state_count=2)
    expected = hash_bytes(payload, context)
    assert hash_chunks(partitions(payload, size + 17), context) == expected
    assert hash_reader(io.BytesIO(payload), context, read_size=127) == expected

    if os.name != "nt":
        # Frozen v2.2 FileSnapshot uses POSIX-style path/descriptor identity.
        # R12.5 does not rewrite that historical semantic asset.
        path = tmp_path / "input.bin"
        path.write_bytes(payload)
        assert hash_file(path, context) == expected


def test_parallel_backend_matches_anchor_and_transcript() -> None:
    context = simultaneous_v2_2(target_round=3, state_count=2)
    payload = b"parallel canonicality" * 10000
    serial_anchor = SERIAL_BACKEND.compute_anchor(payload, context)
    parallel_anchor = MultiprocessingTreeBackend(4).compute_anchor(payload, context)
    assert parallel_anchor == serial_anchor

    serial_digest, serial_transcript = WideOnce(context).evaluate(serial_anchor)
    parallel_digest, parallel_transcript = WideOnce(context).evaluate(parallel_anchor)
    assert parallel_transcript == serial_transcript
    assert parallel_digest == serial_digest


@pytest.mark.parametrize("preset", PRESETS)
def test_authenticated_parameters_change_digest(preset) -> None:
    payload = b"parameter binding"
    base = hash_bytes(payload, preset())
    assert hash_bytes(payload, preset(salt=b"salt")) != base
    assert hash_bytes(payload, preset(challenge=b"challenge")) != base
    assert hash_bytes(payload, preset(application_context=b"application")) != base
    assert hash_bytes(payload, preset(target_round=2)) != base
    assert hash_bytes(payload, preset(state_count=3)) != base


def test_trace_is_reproducible() -> None:
    context = paranoid_deep_v2_2(target_round=3)
    assert trace_bytes(b"trace", context) == trace_bytes(b"trace", context)
