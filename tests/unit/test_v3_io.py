from __future__ import annotations

import io
import multiprocessing
from collections.abc import Iterator

import pytest

from sigma.incremental_v3 import IncrementalSigmaV3
from sigma.io_v3 import evaluate_file_v3, evaluate_reader_v3
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.rounds.backends_v3 import (
    DeepBranchBackendV3,
    DeepBranchResultV3,
    DeepBranchTaskV3,
    ProcessDeepBranchBackendV3,
)
from sigma.rounds.control_v3 import CancellationTokenV3, EvaluationCancelledV3
from sigma.rounds.evaluate_v3 import evaluate_v3
from sigma.sources import (
    BytesSource,
    CanonicalSource,
    IncrementalSpoolSource,
    MmapFileSource,
    SourceChangedError,
    SourceClosedError,
    SourceLimitError,
    StableFileSource,
)
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3


def _context(suite_id: SuiteIdV3) -> SigmaContextV3:
    return SigmaContextV3.for_suite(
        suite_id,
        salt=b"",
        challenge=b"",
        application_context=b"",
    )


@pytest.mark.parametrize(
    ("suite_id", "message"),
    (
        (SuiteIdV3.REFERENCE_IAP_V3, b"R10-wide"),
        (SuiteIdV3.DEEP_V3, b"24"),
        (SuiteIdV3.DEEP_VECTOR_V3, b"38"),
        (SuiteIdV3.REFERENCE_IAP_HISTORY_V3, b"R12.5-wide"),
        (SuiteIdV3.DEEP_HISTORY_V3, b"R12.5-deep"),
        (SuiteIdV3.DEEP_VECTOR_HISTORY_V3, b"R12.5-vector"),
    ),
)
def test_bytes_file_mmap_spool_and_incremental_are_identical(
    tmp_path, suite_id: SuiteIdV3, message: bytes
) -> None:
    context = _context(suite_id)
    path = tmp_path / "message.bin"
    path.write_bytes(message)
    expected = evaluate_v3(context, BytesSource(message))

    with StableFileSource(path) as source:
        stable = evaluate_v3(context, source)
    with MmapFileSource(path) as source:
        mapped = evaluate_v3(context, source)
    spooled = evaluate_reader_v3(
        context,
        io.BytesIO(message),
        max_memory_bytes=2,
        max_spool_bytes=len(message),
        read_size=3,
    )
    snapshot_file = evaluate_file_v3(context, path)
    snapshot_mmap = evaluate_file_v3(context, path, use_mmap=True)

    incremental = IncrementalSigmaV3(
        context,
        max_memory_bytes=1,
        max_spool_bytes=len(message),
    )
    for offset in range(0, len(message), 2):
        incremental.update(message[offset : offset + 2])
    assert incremental.rolled_to_disk
    incremental_digest = incremental.finalize()

    assert expected == stable == mapped == spooled == snapshot_file == snapshot_mmap
    assert incremental_digest == digest_from_evaluation_v3(expected)


@pytest.mark.parametrize(
    "suite_id",
    (SuiteIdV3.REFERENCE_IAP_V3, SuiteIdV3.REFERENCE_IAP_HISTORY_V3),
)
def test_incremental_checkpoints_are_real_prefix_digests(suite_id: SuiteIdV3) -> None:
    context = _context(suite_id)
    incremental = IncrementalSigmaV3(
        context,
        max_memory_bytes=3,
        max_spool_bytes=32,
    )
    prefix = b""
    for chunk in (b"abc", b"defg", b"h"):
        incremental.update(chunk)
        prefix += chunk
        checkpoint = incremental.checkpoint()
        expected = digest_from_evaluation_v3(evaluate_v3(context, BytesSource(prefix)))
        assert checkpoint.offset == len(prefix)
        assert checkpoint.provisional
        assert checkpoint.digest == expected
    assert incremental.finalize() == digest_from_evaluation_v3(
        evaluate_v3(context, BytesSource(prefix))
    )
    with pytest.raises(RuntimeError, match="finalized"):
        incremental.update(b"late")


@pytest.mark.parametrize(
    ("suite_id", "message"),
    (
        (SuiteIdV3.DEEP_VECTOR_V3, b"38"),
        (SuiteIdV3.DEEP_VECTOR_HISTORY_V3, b"R12.5-process"),
    ),
)
def test_multiprocess_reader_matches_canonical_vector_and_cleans_children(
    suite_id: SuiteIdV3,
    message: bytes,
) -> None:
    context = _context(suite_id)
    expected = evaluate_v3(context, BytesSource(message))
    actual = evaluate_reader_v3(
        context,
        io.BytesIO(message),
        max_memory_bytes=1,
        max_spool_bytes=2,
        read_size=1,
        backend=ProcessDeepBranchBackendV3(2),
    )
    assert actual == expected
    assert not multiprocessing.active_children()


def test_stable_file_detects_and_mmap_snapshot_isolates_toctou(tmp_path) -> None:
    path = tmp_path / "mutable.bin"
    path.write_bytes(b"original")
    stable = StableFileSource(path)
    mapped = MmapFileSource(path)
    assert b"".join(stable.iter_chunks(2)) == b"original"
    assert b"".join(mapped.iter_chunks(2)) == b"original"
    path.write_bytes(b"mutation")
    with pytest.raises(SourceChangedError):
        b"".join(stable.iter_chunks(2))
    assert b"".join(mapped.iter_chunks(2)) == b"original"
    stable.close()
    mapped.close()
    with pytest.raises(SourceClosedError):
        _ = stable.byte_length
    with pytest.raises(SourceClosedError):
        _ = mapped.byte_length


def test_empty_mmap_file_is_a_valid_canonical_source(tmp_path) -> None:
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    context = _context(SuiteIdV3.REFERENCE_IAP_V3)
    with MmapFileSource(path) as source:
        actual = evaluate_v3(context, source)
    assert actual == evaluate_v3(context, BytesSource(b""))


class _CancellingSource(CanonicalSource):
    def __init__(self, token: CancellationTokenV3) -> None:
        self._token = token

    @property
    def byte_length(self) -> int:
        return 2

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._token.cancel()
        yield b"xx"


def test_cancellation_is_checked_before_and_during_io() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_V3)
    token = CancellationTokenV3()
    token.cancel()
    with pytest.raises(EvaluationCancelledV3):
        evaluate_v3(context, BytesSource(b"message"), cancellation=token)
    reader = io.BytesIO(b"message")
    with pytest.raises(EvaluationCancelledV3):
        evaluate_reader_v3(context, reader, cancellation=token)
    assert reader.tell() == 0

    token = CancellationTokenV3()
    with pytest.raises(EvaluationCancelledV3):
        evaluate_v3(context, _CancellingSource(token), cancellation=token)


def test_cancelled_incremental_finalization_releases_spool() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_V3)
    incremental = IncrementalSigmaV3(
        context,
        max_memory_bytes=1,
        max_spool_bytes=8,
    )
    incremental.update(b"data")
    token = CancellationTokenV3()
    token.cancel()
    with pytest.raises(EvaluationCancelledV3):
        incremental.finalize(cancellation=token)
    with pytest.raises((RuntimeError, SourceClosedError)):
        incremental.update(b"late")


class _CancelAfterProcessBackend(DeepBranchBackendV3):
    def __init__(self, token: CancellationTokenV3) -> None:
        self._token = token
        self._process = ProcessDeepBranchBackendV3(2)

    @property
    def name(self) -> str:
        return "cancel-after-process"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        results = self._process.execute(tasks)
        self._token.cancel()
        return results


def test_process_cancellation_is_controlled_and_cleans_workers() -> None:
    token = CancellationTokenV3()
    context = _context(SuiteIdV3.DEEP_VECTOR_V3)
    with pytest.raises(EvaluationCancelledV3):
        evaluate_v3(
            context,
            BytesSource(b"38"),
            backend=_CancelAfterProcessBackend(token),
            cancellation=token,
        )
    assert not multiprocessing.active_children()


def test_incremental_and_reader_resource_limits_are_enforced() -> None:
    source = IncrementalSpoolSource(max_memory_bytes=2, max_spool_bytes=3)
    source.update(b"abc")
    with pytest.raises(SourceLimitError):
        source.update(b"d")
    source.close()
    assert source.closed
    with pytest.raises(SourceClosedError):
        source.update(b"x")

    context = _context(SuiteIdV3.REFERENCE_IAP_V3)
    with pytest.raises(SourceLimitError):
        evaluate_reader_v3(
            context,
            io.BytesIO(b"four"),
            max_memory_bytes=2,
            max_spool_bytes=3,
            read_size=2,
        )
