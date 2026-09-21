"""Two-pass preparation of the Sigma v3 persistent binding."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from sigma.binding.types import (
    AnchorV3,
    CardinalityDescriptor,
    JointSignature,
    LengthSignature,
    PersistentBinding,
)
from sigma.crypto.primitives import HashAccumulator, hash_bytes
from sigma.sources import CanonicalSource, SourceChangedError
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3
from sigma.spec.transcript import TranscriptWriter, encode_transcript


class MessageSink(Protocol):
    """Optional consumer sharing the second message pass (for future init)."""

    def update(self, data: bytes) -> None: ...


@dataclass(frozen=True)
class PreparedBindingV3:
    """Binding plus the operational identity of its canonical source bytes."""

    binding: PersistentBinding
    source_sha256: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.binding, PersistentBinding):
            raise TypeError("binding must be PersistentBinding")
        if not isinstance(self.source_sha256, bytes) or len(self.source_sha256) != 32:
            raise ValueError("source_sha256 must contain exactly 32 bytes")


class _FanoutSink:
    def __init__(self, sinks: tuple[HashAccumulator, ...]) -> None:
        self._sinks = sinks

    def update(self, data: bytes) -> None:
        for sink in self._sinks:
            sink.update(data)


def derive_length_signature_v3(
    context: SigmaContextV3, cardinality: CardinalityDescriptor
) -> LengthSignature:
    """Recompute the context-bound canonical length signature."""

    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if not isinstance(cardinality, CardinalityDescriptor):
        raise TypeError("cardinality must be CardinalityDescriptor")
    transcript = encode_transcript(
        DomainIdV3.LENGTH_SIGNATURE,
        ((1, context.to_bytes()), (2, cardinality.to_bytes())),
    )
    return LengthSignature(
        cardinality,
        hash_bytes(context.length_algorithm, DomainIdV3.LENGTH_SIGNATURE, transcript),
    )


def _write_message_transcript(
    source: CanonicalSource,
    writer: TranscriptWriter,
    *,
    tag: int,
    expected: int,
    chunk_size: int,
    observer: MessageSink | None = None,
) -> bytes:
    total = 0
    consistency_digest = hashlib.sha256()

    def chunks():
        nonlocal total
        for chunk in source.iter_chunks(chunk_size):
            if not isinstance(chunk, bytes):
                raise TypeError("canonical source chunks must be bytes")
            if not chunk:
                raise SourceChangedError("canonical source yielded an empty chunk")
            if len(chunk) > chunk_size:
                raise SourceChangedError("source chunk exceeds requested chunk_size")
            total += len(chunk)
            if total > expected:
                raise SourceChangedError("source exceeds declared cardinality")
            consistency_digest.update(chunk)
            if observer is not None:
                observer.update(chunk)
            yield chunk
        if total != expected:
            raise SourceChangedError("source does not match declared cardinality")

    writer.write_field(tag, expected, chunks())
    return consistency_digest.digest()


def prepare_input_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    *,
    second_pass_sink: MessageSink | None = None,
) -> PreparedBindingV3:
    """Compute binding and source identity in exactly two source replays."""

    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")
    if second_pass_sink is not None and not callable(getattr(second_pass_sink, "update", None)):
        raise TypeError("second_pass_sink must provide update(bytes)")

    cardinality = CardinalityDescriptor(source.byte_length)
    context_bytes = context.to_bytes()
    cardinality_bytes = cardinality.to_bytes()

    anchor_hashes = tuple(
        HashAccumulator(algorithm, DomainIdV3.ANCHOR_BRANCH)
        for algorithm in context.anchor_algorithms
    )
    anchor_writer = TranscriptWriter(_FanoutSink(anchor_hashes), DomainIdV3.ANCHOR_BRANCH)
    anchor_writer.write_bytes(1, context_bytes)
    anchor_writer.write_bytes(2, cardinality_bytes)
    anchor_source_digest = _write_message_transcript(
        source,
        anchor_writer,
        tag=3,
        expected=cardinality.byte_length,
        chunk_size=context.chunk_size,
    )
    anchor_writer.finish()
    anchor = AnchorV3(
        context.suite_id,
        cardinality.byte_length,
        context.anchor_algorithms,
        tuple(value.digest() for value in anchor_hashes),
    )

    length_signature = derive_length_signature_v3(context, cardinality)

    joint_hashes = tuple(
        HashAccumulator(algorithm, DomainIdV3.JOINT_SIGNATURE)
        for algorithm in context.joint_algorithms
    )
    joint_writer = TranscriptWriter(_FanoutSink(joint_hashes), DomainIdV3.JOINT_SIGNATURE)
    joint_writer.write_bytes(1, context_bytes)
    joint_writer.write_bytes(2, cardinality_bytes)
    joint_source_digest = _write_message_transcript(
        source,
        joint_writer,
        tag=3,
        expected=cardinality.byte_length,
        chunk_size=context.chunk_size,
        observer=second_pass_sink,
    )
    if joint_source_digest != anchor_source_digest:
        raise SourceChangedError("source content changed between replays")
    joint_writer.write_bytes(4, anchor.to_bytes())
    joint_writer.write_bytes(5, length_signature.to_bytes())
    joint_writer.finish()
    joint_signature = JointSignature(
        context.joint_algorithms,
        tuple(value.digest() for value in joint_hashes),
    )

    return PreparedBindingV3(
        PersistentBinding(anchor, cardinality, length_signature, joint_signature),
        anchor_source_digest,
    )


def prepare_binding_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    *,
    second_pass_sink: MessageSink | None = None,
) -> PersistentBinding:
    """Compatibility helper returning only the prepared persistent binding."""

    return prepare_input_v3(context, source, second_pass_sink=second_pass_sink).binding
