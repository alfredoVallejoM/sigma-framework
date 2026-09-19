"""Exclusive canonical frame builders for Sigma v3 state transitions."""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass

from sigma.binding.prepare import PreparedBindingV3, derive_length_signature_v3
from sigma.binding.types import MAX_U64, PersistentBinding
from sigma.layout import (
    LayoutPlan,
    derive_layout_v3,
    iter_placed_binding_v3,
    placed_binding_length_v3,
)
from sigma.sources import CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import encode_uint
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import ALGORITHM_OUTPUT_SIZE_V3, DomainIdV3, LayoutKindV3
from sigma.spec.transcript import TranscriptSink, TranscriptWriter, encode_transcript

MAX_MATERIALIZED_FRAME = 1 << 20


def _validate_context_binding(context: SigmaContextV3, binding: PersistentBinding) -> None:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if not isinstance(binding, PersistentBinding):
        raise TypeError("binding must be PersistentBinding")
    if binding.anchor.suite_id != context.suite_id:
        raise ValueError("binding and context suites differ")
    if binding.length_signature != derive_length_signature_v3(context, binding.cardinality):
        raise ValueError("binding length signature does not match context")


def _validate_index(index: int) -> None:
    if isinstance(index, bool) or not isinstance(index, int):
        raise TypeError("round_index must be int")
    if not 0 <= index <= MAX_U64:
        raise ValueError("round_index is out of range")


def _validate_canonical_layout(
    context: SigmaContextV3,
    binding: PersistentBinding,
    layout: LayoutPlan,
    *,
    kind: LayoutKindV3,
    round_index: int,
    base_length: int,
) -> None:
    expected = derive_layout_v3(
        context,
        binding,
        kind=kind,
        round_index=round_index,
        base_length=base_length,
    )
    if layout != expected:
        raise ValueError("layout is not canonical for context and binding")


@dataclass(frozen=True)
class InitFrame:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    layout: LayoutPlan
    source: CanonicalSource

    def __post_init__(self) -> None:
        if not isinstance(self.prepared, PreparedBindingV3):
            raise TypeError("prepared must be PreparedBindingV3")
        _validate_context_binding(self.context, self.prepared.binding)
        if not isinstance(self.layout, LayoutPlan):
            raise TypeError("layout must be LayoutPlan")
        if self.layout.kind is not LayoutKindV3.INIT:
            raise ValueError("init frame requires INIT layout")
        if not isinstance(self.source, CanonicalSource):
            raise TypeError("source must be CanonicalSource")
        if self.layout.base_length != self.source.byte_length:
            raise ValueError("init layout length does not match source")
        if self.prepared.binding.cardinality.byte_length != self.source.byte_length:
            raise ValueError("binding cardinality does not match source")
        _validate_canonical_layout(
            self.context,
            self.prepared.binding,
            self.layout,
            kind=LayoutKindV3.INIT,
            round_index=0,
            base_length=self.source.byte_length,
        )

    @property
    def encoded_length(self) -> int:
        placed_length = placed_binding_length_v3(self.prepared.binding, self.layout)
        return (
            12
            + (10 + len(self.context.to_bytes()))
            + (10 + len(self.layout.to_bytes()))
            + (10 + placed_length)
        )

    def write_to(self, sink: TranscriptSink) -> None:
        source_digest = hashlib.sha256()

        def checked_chunks():
            for chunk in self.source.iter_chunks(self.context.chunk_size):
                source_digest.update(chunk)
                yield chunk

        writer = TranscriptWriter(sink, DomainIdV3.INIT_FRAME)
        writer.write_bytes(1, self.context.to_bytes())
        writer.write_bytes(2, self.layout.to_bytes())
        writer.write_field(
            3,
            placed_binding_length_v3(self.prepared.binding, self.layout),
            iter_placed_binding_v3(
                checked_chunks(),
                self.prepared.binding,
                self.layout,
            ),
        )
        if source_digest.digest() != self.prepared.source_sha256:
            raise ValueError("init source content does not match prepared binding")
        writer.finish()

    def to_bytes(self) -> bytes:
        if self.encoded_length > MAX_MATERIALIZED_FRAME:
            raise ValueError("init frame is too large to materialize")

        class Sink:
            def __init__(self) -> None:
                self.buffer = io.BytesIO()

            def update(self, data: bytes) -> None:
                self.buffer.write(data)

        sink = Sink()
        self.write_to(sink)
        return sink.buffer.getvalue()


@dataclass(frozen=True)
class RoundFrame:
    context: SigmaContextV3
    binding: PersistentBinding
    layout: LayoutPlan
    round_index: int
    state: bytes

    def __post_init__(self) -> None:
        _validate_context_binding(self.context, self.binding)
        _validate_index(self.round_index)
        if not isinstance(self.layout, LayoutPlan):
            raise TypeError("layout must be LayoutPlan")
        if self.layout.kind is not LayoutKindV3.ROUND:
            raise ValueError("round frame requires ROUND layout")
        if self.layout.round_index != self.round_index:
            raise ValueError("layout and frame round indices differ")
        if not isinstance(self.state, bytes):
            raise TypeError("state must be bytes")
        if len(self.state) != self.context.state_size:
            raise ValueError("state size does not match context")
        if self.layout.base_length != len(self.state):
            raise ValueError("layout length does not match state")
        _validate_canonical_layout(
            self.context,
            self.binding,
            self.layout,
            kind=LayoutKindV3.ROUND,
            round_index=self.round_index,
            base_length=len(self.state),
        )

    def to_bytes(self) -> bytes:
        placed = b"".join(iter_placed_binding_v3((self.state,), self.binding, self.layout))
        return encode_transcript(
            DomainIdV3.ROUND_FRAME,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, self.layout.to_bytes()),
                (4, placed),
            ),
        )


@dataclass(frozen=True)
class VectorRoundFrame:
    context: SigmaContextV3
    binding: PersistentBinding
    layout: LayoutPlan
    round_index: int
    vector: bytes

    def __post_init__(self) -> None:
        _validate_context_binding(self.context, self.binding)
        _validate_index(self.round_index)
        if not isinstance(self.layout, LayoutPlan):
            raise TypeError("layout must be LayoutPlan")
        if self.layout.kind is not LayoutKindV3.ROUND:
            raise ValueError("vector frame requires ROUND layout")
        if self.layout.round_index != self.round_index:
            raise ValueError("layout and frame round indices differ")
        if not isinstance(self.vector, bytes) or not self.vector:
            raise ValueError("vector must be non-empty bytes")
        expected_width = len(self.context.joint_algorithms) * ALGORITHM_OUTPUT_SIZE_V3
        if len(self.vector) != expected_width:
            raise ValueError("vector width does not match joint algorithms")
        if self.layout.base_length != len(self.vector):
            raise ValueError("layout length does not match vector")
        _validate_canonical_layout(
            self.context,
            self.binding,
            self.layout,
            kind=LayoutKindV3.ROUND,
            round_index=self.round_index,
            base_length=len(self.vector),
        )

    def to_bytes(self) -> bytes:
        placed = b"".join(iter_placed_binding_v3((self.vector,), self.binding, self.layout))
        return encode_transcript(
            DomainIdV3.VECTOR_ROUND_FRAME,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, self.layout.to_bytes()),
                (4, placed),
            ),
        )


@dataclass(frozen=True)
class DeepBranchFrame:
    context: SigmaContextV3
    round_index: int
    branch_index: int
    algorithm: AlgorithmId
    vector_frame: VectorRoundFrame

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV3):
            raise TypeError("context must be SigmaContextV3")
        _validate_index(self.round_index)
        if isinstance(self.branch_index, bool) or not isinstance(self.branch_index, int):
            raise TypeError("branch_index must be int")
        if not 0 <= self.branch_index < len(self.context.joint_algorithms):
            raise ValueError("branch_index is out of range")
        if not isinstance(self.algorithm, AlgorithmId):
            raise TypeError("algorithm must be AlgorithmId")
        if self.algorithm is not self.context.joint_algorithms[self.branch_index]:
            raise ValueError("algorithm does not match branch index")
        if not isinstance(self.vector_frame, VectorRoundFrame):
            raise TypeError("vector_frame must be VectorRoundFrame")
        if self.vector_frame.context != self.context:
            raise ValueError("vector frame context differs from branch context")
        if self.vector_frame.round_index != self.round_index:
            raise ValueError("vector frame round differs from branch round")

    def to_bytes(self) -> bytes:
        return encode_transcript(
            DomainIdV3.DEEP_BRANCH_FRAME,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, encode_uint(self.branch_index, 2)),
                (4, encode_uint(self.algorithm, 2)),
                (5, self.vector_frame.to_bytes()),
            ),
        )
