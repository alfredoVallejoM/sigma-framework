from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sigma.binding import prepare_input_v3
from sigma.layout import derive_layout_v3
from sigma.rounds.framing_v3 import (
    DeepBranchFrame,
    InitFrame,
    RoundFrame,
    VectorRoundFrame,
)
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import LayoutKindV3


def _context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"R6-salt",
        challenge=b"R6-challenge",
        application_context=b"tests/v3/framing",
    )


def _prepared(message: bytes = b"frame-message"):
    context = _context()
    prepared = prepare_input_v3(context, BytesSource(message))
    return context, prepared


class ChunkedSource(CanonicalSource):
    def __init__(self, data: bytes) -> None:
        self.data = data

    @property
    def byte_length(self) -> int:
        return len(self.data)

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        for offset in range(0, len(self.data), 2):
            yield self.data[offset : offset + 2]


def test_init_frame_is_streaming_and_chunk_invariant() -> None:
    message = b"chunk-invariant-init"
    context, prepared = _prepared(message)
    binding = prepared.binding
    layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=len(message),
    )

    contiguous = InitFrame(context, prepared, layout, BytesSource(message))
    chunked = InitFrame(context, prepared, layout, ChunkedSource(message))
    assert contiguous.to_bytes() == chunked.to_bytes()
    assert len(contiguous.to_bytes()) == contiguous.encoded_length


def test_round_vector_and_branch_frames_are_domain_and_field_sensitive() -> None:
    context, prepared = _prepared()
    binding = prepared.binding
    state = bytes(range(context.state_size))
    layout0 = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=len(state),
    )
    layout1 = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=1,
        base_length=len(state),
    )
    round0 = RoundFrame(context, binding, layout0, 0, state).to_bytes()
    round1 = RoundFrame(context, binding, layout1, 1, state).to_bytes()
    changed_state = RoundFrame(
        context, binding, layout0, 0, bytes((state[0] ^ 1,)) + state[1:]
    ).to_bytes()
    assert len({round0, round1, changed_state}) == 3

    vector_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=4 * 64,
    )
    vector_frame = VectorRoundFrame(
        context, binding, vector_layout, 0, bytes(range(256))
    ).to_bytes()
    assert vector_frame != round0
    branches = tuple(
        DeepBranchFrame(
            context,
            0,
            index,
            algorithm,
            VectorRoundFrame(context, binding, vector_layout, 0, bytes(range(256))),
        ).to_bytes()
        for index, algorithm in enumerate(context.joint_algorithms)
    )
    assert len(set(branches)) == len(branches)


def test_frame_known_answers() -> None:
    message = b"Sigma v3 R6 KAT"
    context, prepared = _prepared(message)
    binding = prepared.binding
    init_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=len(message),
    )
    round_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=3,
        base_length=64,
    )
    init_bytes = InitFrame(context, prepared, init_layout, BytesSource(message)).to_bytes()
    round_bytes = RoundFrame(context, binding, round_layout, 3, b"s" * 64).to_bytes()

    assert hashlib.sha256(init_bytes).hexdigest() == (
        "faf6ae66de6a787f09af84d1d97c85f1e4796253cf54fd82a02ea9f778dff013"
    )
    assert hashlib.sha256(round_bytes).hexdigest() == (
        "4cc67cf311b63ccf5890498465d25b1be0cca09d16749c5053ce528e9f570268"
    )
    assert init_bytes[:12].hex() == "5349474d4133545200030308"
    assert round_bytes[:12].hex() == "5349474d4133545200030309"


def test_all_four_frames_match_complete_byte_vectors() -> None:
    vector_path = (
        Path(__file__).parents[2] / "specification" / "test-vectors" / "conformance-v3-r6.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    message = bytes.fromhex(vector["message_hex"])
    context = SigmaContextV3.reference(salt=b"", challenge=b"", application_context=b"")
    prepared = prepare_input_v3(context, BytesSource(message))
    binding = prepared.binding
    init_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=len(message),
    )
    round_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=64,
    )
    vector_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=256,
    )
    vector_frame = VectorRoundFrame(context, binding, vector_layout, 0, b"v" * 256)

    actual = {
        "init": InitFrame(context, prepared, init_layout, BytesSource(message)).to_bytes(),
        "round": RoundFrame(context, binding, round_layout, 0, b"s" * 64).to_bytes(),
        "vector": vector_frame.to_bytes(),
        "deep": DeepBranchFrame(
            context, 0, 0, context.joint_algorithms[0], vector_frame
        ).to_bytes(),
    }
    for name, encoded in actual.items():
        assert encoded == bytes.fromhex(vector[name])


def test_frames_reject_cross_kind_index_size_and_context() -> None:
    context, prepared = _prepared(b"x")
    binding = prepared.binding
    init_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=1,
    )
    round_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=64,
    )
    with pytest.raises(ValueError, match="INIT"):
        InitFrame(context, prepared, round_layout, BytesSource(b"x"))
    with pytest.raises(ValueError, match="ROUND"):
        RoundFrame(context, binding, init_layout, 0, b"s" * 64)
    with pytest.raises(ValueError, match="state size"):
        RoundFrame(context, binding, round_layout, 0, b"short")
    other = SigmaContextV3.reference(
        salt=b"other",
        challenge=context.challenge,
        application_context=context.application_context,
    )
    with pytest.raises(ValueError, match="context"):
        RoundFrame(other, binding, round_layout, 0, b"s" * 64)


def test_init_rejects_same_length_wrong_source_and_branch_requires_typed_vector() -> None:
    context, prepared = _prepared(b"AAAA")
    binding = prepared.binding
    init_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=4,
    )
    with pytest.raises(ValueError, match="does not match"):
        InitFrame(context, prepared, init_layout, BytesSource(b"BBBB")).to_bytes()

    vector_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=1,
        base_length=256,
    )
    vector = VectorRoundFrame(context, binding, vector_layout, 1, b"v" * 256)
    with pytest.raises(ValueError, match="round differs"):
        DeepBranchFrame(context, 0, 0, context.joint_algorithms[0], vector)
    with pytest.raises(TypeError, match="VectorRoundFrame"):
        DeepBranchFrame(
            context,
            0,
            0,
            context.joint_algorithms[0],
            b"not-a-vector-frame",  # type: ignore[arg-type]
        )


def test_vector_frame_rejects_noncanonical_width() -> None:
    context, prepared = _prepared()
    wrong_width = len(context.joint_algorithms) * 64 - 1
    layout = derive_layout_v3(
        context,
        prepared.binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=wrong_width,
    )

    with pytest.raises(ValueError, match="vector width"):
        VectorRoundFrame(
            context,
            prepared.binding,
            layout,
            0,
            b"v" * wrong_width,
        )
