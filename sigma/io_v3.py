"""Resource-safe Sigma v3 file, mmap and reader entry points."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, cast
from sigma.outputs.digest_v3 import SigmaDigestV3, digest_from_evaluation_v3
from sigma.rounds.backends_v3 import DeepBranchBackendV3
from sigma.rounds.control_v3 import CancellationTokenV3, check_cancellation_v3
from sigma.rounds.evaluate_v3 import EvaluationV3, evaluate_v3
from sigma.sources import MmapFileSource, SpoolingStreamSource, StableFileSource
from sigma.spec.context_v3 import SigmaContextV3


@contextmanager
def _immutable_snapshot_v3(path: Path) -> Iterator[Path]:
    """Create a private v3 snapshot after two byte-identical stable replays."""

    with (
        StableFileSource(path) as source,
        tempfile.TemporaryDirectory(prefix="sigma-v3-file-snapshot-") as directory,
    ):
        snapshot = Path(directory) / "input.bin"
        with snapshot.open("xb") as target:
            for chunk in source.iter_chunks(1 << 20):
                target.write(chunk)
        # The second replay is intentionally consumed only as a consistency
        # check. StableFileSource compares it with the copied first replay.
        for _chunk in source.iter_chunks(1 << 20):
            pass
        yield snapshot


def _evaluate_path_v3(
    context: SigmaContextV3,
    path: str | os.PathLike[str],
    *,
    use_mmap: bool,
    backend: DeepBranchBackendV3 | None,
    cancellation: CancellationTokenV3 | None,
) -> EvaluationV3:
    source_type = MmapFileSource if use_mmap else StableFileSource
    with source_type(path) as source:
        return evaluate_v3(
            context,
            source,
            backend=backend,
            cancellation=cancellation,
        )


def evaluate_file_v3(
    context: SigmaContextV3,
    path: str | os.PathLike[str],
    *,
    use_mmap: bool = False,
    snapshot: bool = True,
    backend: DeepBranchBackendV3 | None = None,
    cancellation: CancellationTokenV3 | None = None,
) -> EvaluationV3:
    if not isinstance(use_mmap, bool) or not isinstance(snapshot, bool):
        raise TypeError("use_mmap and snapshot must be bool")
    check_cancellation_v3(cancellation)
    if snapshot:
        with _immutable_snapshot_v3(Path(path)) as snapshot_path:
            check_cancellation_v3(cancellation)
            return _evaluate_path_v3(
                context,
                snapshot_path,
                use_mmap=use_mmap,
                backend=backend,
                cancellation=cancellation,
            )
    return _evaluate_path_v3(
        context,
        path,
        use_mmap=use_mmap,
        backend=backend,
        cancellation=cancellation,
    )


def digest_file_v3(
    context: SigmaContextV3,
    path: str | os.PathLike[str],
    *,
    use_mmap: bool = False,
    snapshot: bool = True,
    backend: DeepBranchBackendV3 | None = None,
    cancellation: CancellationTokenV3 | None = None,
) -> SigmaDigestV3:
    return digest_from_evaluation_v3(
        evaluate_file_v3(
            context,
            path,
            use_mmap=use_mmap,
            snapshot=snapshot,
            backend=backend,
            cancellation=cancellation,
        )
    )


def evaluate_reader_v3(
    context: SigmaContextV3,
    reader: BinaryIO,
    *,
    max_memory_bytes: int = 1 << 20,
    max_spool_bytes: int = 1 << 30,
    read_size: int = 1 << 20,
    backend: DeepBranchBackendV3 | None = None,
    cancellation: CancellationTokenV3 | None = None,
) -> EvaluationV3:
    check_cancellation_v3(cancellation)

    class CancellableReader:
        def read(self, size: int = -1) -> bytes:
            check_cancellation_v3(cancellation)
            data = reader.read(size)
            check_cancellation_v3(cancellation)
            return data

    with SpoolingStreamSource(
        cast(BinaryIO, CancellableReader()),
        max_memory_bytes=max_memory_bytes,
        max_spool_bytes=max_spool_bytes,
        read_size=read_size,
    ) as source:
        return evaluate_v3(
            context,
            source,
            backend=backend,
            cancellation=cancellation,
        )


__all__ = ["digest_file_v3", "evaluate_file_v3", "evaluate_reader_v3"]
