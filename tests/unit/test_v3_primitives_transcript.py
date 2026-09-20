import hashlib

import pytest

from sigma.crypto.primitives import (
    MAX_SHAKE_READER_BYTES,
    HashAccumulator,
    ShakeReader,
    domain_tag_v3,
    hash_bytes,
)
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import DomainIdV3
from sigma.spec.transcript import TranscriptWriter, encode_transcript


class BufferSink:
    def __init__(self) -> None:
        self.data = bytearray()

    def update(self, data: bytes) -> None:
        self.data.extend(data)


def test_transcript_constructor_and_byte_helpers_reject_wrong_types() -> None:
    with pytest.raises(TypeError, match="DomainIdV3"):
        TranscriptWriter(BufferSink(), 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="provide update"):
        TranscriptWriter(object(), DomainIdV3.ROUND_FRAME)  # type: ignore[arg-type]

    writer = TranscriptWriter(BufferSink(), DomainIdV3.ROUND_FRAME)
    with pytest.raises(TypeError, match="length must be int"):
        writer.write_field(1, True, ())

    writer = TranscriptWriter(BufferSink(), DomainIdV3.ROUND_FRAME)
    with pytest.raises(TypeError, match="value must be bytes"):
        writer.write_bytes(1, "bad")  # type: ignore[arg-type]


def test_all_v3_domain_tags_and_outputs_are_distinct() -> None:
    tags = {domain_tag_v3(domain) for domain in DomainIdV3}
    outputs = {hash_bytes(AlgorithmId.SHA512, domain, b"same input") for domain in DomainIdV3}

    assert len(tags) == len(DomainIdV3)
    assert len(outputs) == len(DomainIdV3)
    assert all(tag.startswith(b"SIGMA3DS") and len(tag) == 10 for tag in tags)


@pytest.mark.parametrize("algorithm", tuple(AlgorithmId))
def test_hash_accumulator_is_chunk_invariant(algorithm: AlgorithmId) -> None:
    expected = hash_bytes(algorithm, DomainIdV3.JOINT_SIGNATURE, b"abcdef")
    accumulator = HashAccumulator(algorithm, DomainIdV3.JOINT_SIGNATURE)
    for chunk in (b"a", b"bc", b"", b"def"):
        accumulator.update(chunk)

    assert accumulator.digest() == expected
    with pytest.raises(RuntimeError, match="finalized"):
        accumulator.update(b"later")


def test_sha512_wrapper_matches_standard_primitive() -> None:
    expected = hashlib.sha512(domain_tag_v3(DomainIdV3.LENGTH_SIGNATURE) + b"input").digest()
    assert hash_bytes(AlgorithmId.SHA512, DomainIdV3.LENGTH_SIGNATURE, b"input") == expected


@pytest.mark.parametrize(
    "algorithm,expected",
    (
        (
            AlgorithmId.SHA512,
            "14ab54f1b1826af8495586ce7956918036f31366819f719de13bfd0e6378daf17"
            "8be329a79520f79fe65d8f30295637c7a3d11da8e2c9e58ae7fed0641404981",
        ),
        (
            AlgorithmId.SHA3_512,
            "6bb66c0fa5fc072996c11240cc6fcd6996cd0d5013a6f897d6c478bc9066040f"
            "515f605409e3cf8a74b5ab5074d5f53e2e85d3e87ea34e5d9cf3600f9be95313",
        ),
        (
            AlgorithmId.BLAKE2B_512,
            "42c38538a5ecb2dbd36db3f446eafaab518132e4417d148bd5c298e5efa1f151"
            "760153c4eddd67bf4ee7c8cd431a0f5ff312c8196522cab1a61482f5c6091b64",
        ),
        (
            AlgorithmId.SHAKE256_512,
            "9cd1284bc0aab3744f1c45b977db4fd4d78c747e23c7b852eac3d5ed528c4dc9"
            "d1124c158b979c4a3d2084adc57e7098b0ce7aa144fcb9dc255b2606c80e71f4",
        ),
    ),
)
def test_primitive_known_answers(algorithm: AlgorithmId, expected: str) -> None:
    assert hash_bytes(algorithm, DomainIdV3.JOINT_SIGNATURE, b"R2-KAT").hex() == expected


def test_shake_reader_is_chunk_invariant_and_bounded() -> None:
    whole = ShakeReader(DomainIdV3.PARAMETER_DERIVATION, b"seed").read(64)
    split_reader = ShakeReader(DomainIdV3.PARAMETER_DERIVATION, b"seed")

    assert split_reader.read(7) + split_reader.read(57) == whole
    with pytest.raises(ValueError, match="range"):
        split_reader.read((1 << 20) + 1)

    bounded = ShakeReader(DomainIdV3.PARAMETER_DERIVATION, b"bounded")
    bounded.read(MAX_SHAKE_READER_BYTES)
    with pytest.raises(ValueError, match="total"):
        bounded.read(1)

    one_byte_reader = ShakeReader(DomainIdV3.LAYOUT_ROUND, b"many-reads")
    many_reads = b"".join(one_byte_reader.read(1) for _ in range(10_000))
    assert many_reads == ShakeReader(DomainIdV3.LAYOUT_ROUND, b"many-reads").read(10_000)
    tiny_reader = ShakeReader(DomainIdV3.PARAMETER_DERIVATION, b"tiny")
    tiny_reader.read(1)
    assert tiny_reader.buffered_bytes == 64


def test_streaming_transcript_matches_materialized_encoding() -> None:
    expected = encode_transcript(
        DomainIdV3.JOINT_SIGNATURE,
        ((1, b"abc"), (2, b""), (3, b"defgh")),
    )
    sink = BufferSink()
    writer = TranscriptWriter(sink, DomainIdV3.JOINT_SIGNATURE)
    writer.write_field(1, 3, (b"a", b"bc"))
    writer.write_field(2, 0, ())
    writer.write_field(3, 5, (b"de", b"f", b"gh"))
    writer.finish()

    assert bytes(sink.data) == expected


def test_transcript_known_answer_bytes() -> None:
    encoded = encode_transcript(
        DomainIdV3.LENGTH_SIGNATURE,
        ((1, b"A"), (2, b"BC")),
    )

    assert encoded.hex() == (
        "5349474d41335452000303030001000000000000000141000200000000000000024243"
    )


@pytest.mark.parametrize(
    "tag,length,chunks,error",
    (
        (0, 0, (), "tags"),
        (1, 1, (), "shorter"),
        (1, 1, (b"xx",), "exceeds"),
        (1, -1, (), "range"),
    ),
)
def test_transcript_rejects_invalid_fields(tag, length, chunks, error: str) -> None:
    writer = TranscriptWriter(BufferSink(), DomainIdV3.ROUND_FRAME)
    with pytest.raises((TypeError, ValueError), match=error):
        writer.write_field(tag, length, chunks)


@pytest.mark.parametrize(
    "chunks,error",
    (
        ((b"xx",), ValueError),
        ((), ValueError),
        ((bytearray(b"x"),), TypeError),
    ),
)
def test_transcript_is_poisoned_after_partial_field(chunks, error) -> None:
    writer = TranscriptWriter(BufferSink(), DomainIdV3.ROUND_FRAME)

    with pytest.raises(error):
        writer.write_field(1, 1, chunks)
    with pytest.raises(RuntimeError, match="invalid"):
        writer.write_bytes(1, b"x")
    with pytest.raises(RuntimeError, match="invalid"):
        writer.finish()


def test_transcript_is_poisoned_when_iterable_or_sink_fails() -> None:
    def failing_chunks():
        yield b"x"
        raise OSError("iterator failed")

    writer = TranscriptWriter(BufferSink(), DomainIdV3.ROUND_FRAME)
    with pytest.raises(OSError, match="iterator"):
        writer.write_field(1, 2, failing_chunks())
    with pytest.raises(RuntimeError, match="invalid"):
        writer.finish()

    class FailingSink(BufferSink):
        def update(self, data: bytes) -> None:
            super().update(data)
            if len(self.data) > 12:
                raise OSError("sink failed")

    writer = TranscriptWriter(FailingSink(), DomainIdV3.ROUND_FRAME)
    with pytest.raises(OSError, match="sink"):
        writer.write_bytes(1, b"x")
    with pytest.raises(RuntimeError, match="invalid"):
        writer.finish()


def test_transcript_rejects_duplicate_or_out_of_order_tags() -> None:
    writer = TranscriptWriter(BufferSink(), DomainIdV3.ROUND_FRAME)
    writer.write_bytes(2, b"ok")

    with pytest.raises(ValueError, match="strictly increasing"):
        writer.write_bytes(2, b"duplicate")
    with pytest.raises(ValueError, match="strictly increasing"):
        writer.write_bytes(1, b"out-of-order")


def test_transcript_cannot_continue_after_finish() -> None:
    writer = TranscriptWriter(BufferSink(), DomainIdV3.INIT_FRAME)
    writer.finish()

    with pytest.raises(RuntimeError, match="finalized"):
        writer.write_bytes(1, b"late")
    with pytest.raises(RuntimeError, match="already finalized"):
        writer.finish()
