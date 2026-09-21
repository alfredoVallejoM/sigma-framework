from __future__ import annotations

import hashlib
import io
from collections.abc import Iterator

import pytest

from sigma.binding import prepare_binding_v3
from sigma.sources import (
    BytesSource,
    CanonicalSource,
    SourceChangedError,
    SourceClosedError,
    SourceLimitError,
    SpoolingStreamSource,
    StableFileSource,
)
from sigma.spec.context_v3 import SigmaContextV3


def reference_context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"R3-salt",
        challenge=b"R3-challenge",
        application_context=b"tests/v3/sources",
    )


class RecordingSource(CanonicalSource):
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.replays = 0

    @property
    def byte_length(self) -> int:
        return len(self.data)

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self.replays += 1
        for offset in range(0, len(self.data), 3):
            yield self.data[offset : offset + 3]


class RecordingSink:
    def __init__(self) -> None:
        self.data = bytearray()

    def update(self, data: bytes) -> None:
        self.data.extend(data)


def test_binding_is_identical_for_bytes_file_and_stream(tmp_path) -> None:
    payload = bytes(range(256)) * 17 + b"canonical-tail"
    path = tmp_path / "input.bin"
    path.write_bytes(payload)

    expected = prepare_binding_v3(reference_context(), BytesSource(payload))
    from_file = prepare_binding_v3(reference_context(), StableFileSource(path))
    with SpoolingStreamSource(
        io.BytesIO(payload), max_memory_bytes=31, max_spool_bytes=len(payload)
    ) as stream_source:
        assert stream_source.rolled_to_disk
        from_stream = prepare_binding_v3(reference_context(), stream_source)

    assert from_file == expected == from_stream
    assert expected.anchor.message_length == expected.cardinality.byte_length == len(payload)


def test_preparation_uses_two_replays_and_can_share_second_pass() -> None:
    payload = b"two-pass-message"
    source = RecordingSource(payload)
    sink = RecordingSink()

    binding = prepare_binding_v3(reference_context(), source, second_pass_sink=sink)

    assert source.replays == 2
    assert bytes(sink.data) == payload
    assert binding.anchor.message_length == binding.cardinality.byte_length
    assert binding == prepare_binding_v3(reference_context(), BytesSource(payload))


def test_failed_second_pass_sink_aborts_and_its_state_is_not_transactional() -> None:
    source = RecordingSource(b"observer-failure")

    class FailingSink(RecordingSink):
        def update(self, data: bytes) -> None:
            super().update(data)
            raise OSError("sink failed")

    sink = FailingSink()
    with pytest.raises(OSError, match="sink failed"):
        prepare_binding_v3(reference_context(), source, second_pass_sink=sink)
    assert source.replays == 2
    assert sink.data  # Caller must discard this partial state after the exception.


def test_stable_file_detects_mutation_between_replays(tmp_path) -> None:
    path = tmp_path / "mutable.bin"
    path.write_bytes(b"first")
    source = StableFileSource(path)
    assert b"".join(source.iter_chunks(2)) == b"first"

    path.write_bytes(b"other")
    with pytest.raises(SourceChangedError, match="changed"):
        b"".join(source.iter_chunks(2))

    replacement = tmp_path / "removed.bin"
    replacement.write_bytes(b"present")
    removed_source = StableFileSource(replacement)
    replacement.unlink()
    with pytest.raises(SourceChangedError, match="unavailable"):
        b"".join(removed_source.iter_chunks(2))


def test_stable_file_detects_mutation_during_preparation(tmp_path) -> None:
    path = tmp_path / "mutated-during-read.bin"
    path.write_bytes(b"original")

    class MutatingSink:
        def update(self, data: bytes) -> None:
            path.write_bytes(b"modified")

    with pytest.raises(SourceChangedError, match="changed"):
        prepare_binding_v3(
            reference_context(),
            StableFileSource(path),
            second_pass_sink=MutatingSink(),
        )


def test_spool_is_bounded_and_cleaned_up(tmp_path) -> None:
    payload = b"x" * 4096
    source = SpoolingStreamSource(
        io.BytesIO(payload),
        max_memory_bytes=32,
        max_spool_bytes=len(payload),
        read_size=17,
        temp_dir=tmp_path,
    )
    assert source.rolled_to_disk
    assert source.byte_length == len(payload)
    assert b"".join(source.iter_chunks(19)) == payload
    source.close()
    assert source.closed
    assert not list(tmp_path.iterdir())

    class OversizedRead(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            return super().read(-1 if size is None else size + 1)

    with pytest.raises(SourceLimitError, match="read_size"):
        SpoolingStreamSource(
            OversizedRead(b"0123456789"),
            max_memory_bytes=16,
            max_spool_bytes=100,
            read_size=4,
            temp_dir=tmp_path,
        )
    assert not list(tmp_path.iterdir())
    with pytest.raises(SourceClosedError):
        list(source.iter_chunks(1))

    with pytest.raises(SourceLimitError, match="max_spool_bytes"):
        SpoolingStreamSource(
            io.BytesIO(payload),
            max_memory_bytes=16,
            max_spool_bytes=100,
            read_size=17,
            temp_dir=tmp_path,
        )
    assert not list(tmp_path.iterdir())


def test_empty_sources_and_declared_cardinality_mismatch() -> None:
    empty = prepare_binding_v3(reference_context(), BytesSource(b""))
    assert empty.cardinality.byte_length == 0

    class ShortSource(CanonicalSource):
        @property
        def byte_length(self) -> int:
            return 2

        def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
            yield b"x"

    with pytest.raises(SourceChangedError, match="cardinality"):
        prepare_binding_v3(reference_context(), ShortSource())


def test_preparation_rejects_changed_custom_source() -> None:
    class ChangingContentSource(CanonicalSource):
        def __init__(self) -> None:
            self.replay = 0

        @property
        def byte_length(self) -> int:
            return 4

        def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
            self.replay += 1
            yield b"AAAA" if self.replay == 1 else b"BBBB"

    with pytest.raises(SourceChangedError, match="content"):
        prepare_binding_v3(reference_context(), ChangingContentSource())

    class ChangingLengthSource(CanonicalSource):
        def __init__(self) -> None:
            self.length = 3

        @property
        def byte_length(self) -> int:
            self.length += 1
            return self.length

        def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
            yield b"x" * self.byte_length

    with pytest.raises(SourceChangedError, match="cardinality"):
        prepare_binding_v3(reference_context(), ChangingLengthSource())

    class OversizedChunkSource(CanonicalSource):
        @property
        def byte_length(self) -> int:
            return (1 << 20) + 1

        def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
            yield b"x" * (chunk_size + 1)

    with pytest.raises(SourceChangedError, match="chunk_size"):
        prepare_binding_v3(reference_context(), OversizedChunkSource())

    class EmptyChunkSource(CanonicalSource):
        @property
        def byte_length(self) -> int:
            return 1

        def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
            yield b""
            yield b"x"

    with pytest.raises(SourceChangedError, match="empty chunk"):
        prepare_binding_v3(reference_context(), EmptyChunkSource())


def test_binding_known_answer_vector() -> None:
    binding = prepare_binding_v3(reference_context(), BytesSource(b"Sigma-R3-KAT"))

    assert tuple(value.hex() for value in binding.anchor.components) == (
        "ca7e10b20085a9aa651f64be2d90978391cf7ef8788b3300bb5a91c02747facd"
        "285d0103282be311f667b317d0cc6835360332afabf6dab94ee5dd5772903808",
        "fcca62b382fbbca1acc1a34b3db0403e191212a0f1a8c44d147f29f4cab7ee77"
        "177c4d4be449a7f9d6115468a4ff5ec56e6bd2d2158e8b1510c902a3fa7eb976",
        "2fcf58af9962eeaa030f858d98bca2c31ed82e83630a84d6fccf404544472582"
        "5e9bdc8e878e048a03fd2ad8132ca5aaf0c3af9849a9af012c357365ea53ee77",
        "22d357b14f85ea24e47016dcfa2a0356bfbb163a3b26f2e411071b73fa409fc0"
        "2b6a05b4a5d65e7c403ce4ac6a881c828454ed79ae132ced44d6beeb53c59ee9",
    )
    assert binding.length_signature.digest.hex() == (
        "c2d7dc41ad0a8306c7a231e6aa8532368b3102ac74a15ee412ec37ace30fb9e6"
        "bae609ad59b07802a65eb58fbd7a6224156362ee4868508f07eced20cf4a950e"
    )
    assert tuple(value.hex() for value in binding.joint_signature.components) == (
        "db3781c3bb8423b15a51c16b0e9516ec3da9bcc2ab5fc37ddf0fd746015d7d87"
        "d46ce983bfc2dcc19586740f21e6fb1077f0deea9be0b81ac89f46b1c3d016f2",
        "6b89460601932121acc76f4facc0642c8ac13ef34588771dbfef2d9892bcb41b0"
        "8bac6e24e3c7816469e27bfd73f63ae170a64fbe4c6e6de6545fa2296b06863",
        "fa89dbe7ddf62949e82dcf166a8f1622b17aa1e501438a6e171b040b6f9727d4"
        "b9a5cd6de570b40b2e0e0503c70b2ad71a6e8d5ef3e13e86a4c7dcf765dff21a",
        "343b4d0822daef425b3db16fe86341cc24eda824d899fea30f0bd80f5a05db16"
        "6efee863bd59441c167637e63d604e6152bee43c3e370ca3c47d426696233036",
    )
    assert hashlib.sha256(binding.to_bytes()).hexdigest() == (
        "cc6bac919886413f4859e966e68f3667fb26315099c79017f3833858a483bcab"
    )
