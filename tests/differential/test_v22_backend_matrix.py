import io
import random

import pytest

from sigma.anchors import CrossWide, StreamWide, TreeWide
from sigma.backends import SERIAL_BACKEND, MultiprocessingTreeBackend
from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
    reference_v2_2,
    simultaneous_v2_2,
)
from sigma.rounds import Deep, ThreadedDeepBranchBackend
from sigma.v2 import hash_bytes, hash_chunks, hash_file, hash_reader

ACTIVE_PRESETS = (
    reference_v2_2,
    lightweight_v2_2,
    simultaneous_v2_2,
    paranoid_wide_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
)


def _partitions(payload: bytes, seed: int):
    generator = random.Random(seed)
    offset = 0
    yield b""
    while offset < len(payload):
        width = generator.randint(1, 4096)
        yield payload[offset : offset + width]
        offset += width
        if generator.randrange(4) == 0:
            yield b""


@pytest.mark.parametrize("preset", ACTIVE_PRESETS)
@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 65_535, 65_536, 65_537])
def test_every_v22_adapter_is_digest_invariant(preset, size: int, tmp_path) -> None:
    payload = bytes((size + 19 * index) % 256 for index in range(size))
    context = preset(target_round=2, state_count=3)
    expected = hash_bytes(payload, context)
    assert hash_chunks(_partitions(payload, size + 7), context) == expected
    assert hash_reader(io.BytesIO(payload), context, read_size=127) == expected
    path = tmp_path / "input.bin"
    path.write_bytes(payload)
    assert hash_file(path, context) == expected


@pytest.mark.parametrize("size", [0, 1, 65_535, 65_536, 65_537, 131_089])
def test_tree_backends_match_context_anchor_evidence_states_and_digest(size: int, tmp_path) -> None:
    payload = bytes((size + 23 * index) % 256 for index in range(size))
    context = simultaneous_v2_2(target_round=3, state_count=2)
    serial_anchor = SERIAL_BACKEND.compute_anchor(payload, context)
    parallel = MultiprocessingTreeBackend(2)
    parallel_anchor = parallel.compute_anchor(payload, context)
    assert parallel_anchor == serial_anchor
    assert parallel_anchor.to_bytes() == serial_anchor.to_bytes()
    assert hash_bytes(payload, context, parallel) == hash_bytes(payload, context)

    path = tmp_path / "tree-input.bin"
    path.write_bytes(payload)
    assert hash_file(path, context, parallel) == hash_bytes(payload, context)


def test_deep_branch_schedulers_match_every_intermediate() -> None:
    context = paranoid_deep_v2_2(target_round=4, state_count=3)
    anchor = CrossWide.compute(context, (b"scheduler invariant",))
    serial_digest, serial_trace = Deep(context).evaluate(anchor)
    threaded_digest, threaded_trace = Deep(context, ThreadedDeepBranchBackend(workers=4)).evaluate(
        anchor
    )
    assert threaded_trace.state_indices == serial_trace.state_indices
    assert threaded_trace.branch_output_indices == serial_trace.branch_output_indices
    assert threaded_trace.states == serial_trace.states
    assert threaded_trace.branch_outputs == serial_trace.branch_outputs
    assert threaded_digest == serial_digest


@pytest.mark.parametrize(
    "context,anchor_type",
    [
        (reference_v2_2(), StreamWide),
        (simultaneous_v2_2(), TreeWide),
        (paranoid_wide_v2_2(), CrossWide),
    ],
)
def test_anchor_backend_contract_preserves_canonical_evidence(context, anchor_type) -> None:
    payload = b"backend-contract"
    direct = anchor_type.compute(context, (payload,))
    backend = SERIAL_BACKEND.compute_anchor(payload, context)
    assert backend == direct
    assert backend.to_bytes() == direct.to_bytes()
