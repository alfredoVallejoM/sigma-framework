"""Canonical TreeWide leaf hashing across worker processes."""

import mmap
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Iterator, Tuple

from sigma.anchors import AnchorEvidence, TreeWide
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId

from .base import ExecutionBackend, FileExecutionBackend

MAX_WORKERS = 256


def _hash_leaf_task(
    arguments: Tuple[bytes, int, bytes],
) -> Tuple[Tuple[bytes, ...], int]:
    context_bytes, index, leaf = arguments
    context = SigmaContextV2.from_bytes(context_bytes)
    digests = tuple(
        TreeWide.leaf_digest(context, index, algorithm, leaf) for algorithm in context.branches
    )
    return digests, len(leaf)


def _hash_file_leaf_task(
    arguments: Tuple[str, bytes, int, int, int],
) -> Tuple[Tuple[bytes, ...], int]:
    path, context_bytes, index, offset, length = arguments
    context = SigmaContextV2.from_bytes(context_bytes)
    with (
        open(path, "rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
    ):
        leaf = bytes(mapped[offset : offset + length])
    digests = tuple(
        TreeWide.leaf_digest(context, index, algorithm, leaf) for algorithm in context.branches
    )
    return digests, length


@dataclass(frozen=True)
class MultiprocessingTreeBackend(ExecutionBackend, FileExecutionBackend):
    workers: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.workers, bool) or not isinstance(self.workers, int):
            raise TypeError("workers must be an integer")
        selected = self.workers or (os.cpu_count() or 1)
        if not 1 <= selected <= MAX_WORKERS:
            raise ValueError(f"workers must be in [1, {MAX_WORKERS}]")
        object.__setattr__(self, "workers", selected)

    @property
    def name(self) -> str:
        return "multiprocessing-tree"

    def compute_anchor(self, data: bytes, context: SigmaContextV2) -> AnchorEvidence:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if context.anchor_profile is not AnchorProfileId.TREE_WIDE:
            raise ValueError("multiprocessing backend only supports TreeWide")
        # Construction validates the suite even for the empty-message path.
        TreeWide(context)
        if not data:
            return TreeWide.compute(context, ())
        leaf_count = (len(data) + context.chunk_size - 1) // context.chunk_size
        context_bytes = context.to_bytes()
        effective_workers = min(self.workers, leaf_count)
        with ProcessPoolExecutor(max_workers=effective_workers) as executor:

            def bounded_results() -> Iterator[Tuple[Tuple[bytes, ...], int]]:
                batch_size = effective_workers * 2
                for start in range(0, leaf_count, batch_size):
                    end = min(start + batch_size, leaf_count)
                    futures = []
                    for index in range(start, end):
                        offset = index * context.chunk_size
                        leaf = data[offset : offset + context.chunk_size]
                        futures.append(
                            executor.submit(_hash_leaf_task, (context_bytes, index, leaf))
                        )
                    for future in futures:
                        yield future.result()

            return TreeWide.from_prehashed_leaves(context, bounded_results())

    def compute_anchor_file(self, path, context: SigmaContextV2) -> AnchorEvidence:
        if context.anchor_profile is not AnchorProfileId.TREE_WIDE:
            raise ValueError("multiprocessing backend only supports TreeWide")
        TreeWide(context)
        path_string = os.fspath(path)
        before = os.stat(path_string)
        if before.st_size == 0:
            evidence = TreeWide.compute(context, ())
            after = os.stat(path_string)
            if (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                raise RuntimeError("input file changed while it was being hashed")
            return evidence
        leaf_count = (before.st_size + context.chunk_size - 1) // context.chunk_size
        context_bytes = context.to_bytes()
        effective_workers = min(self.workers, leaf_count)
        with ProcessPoolExecutor(max_workers=effective_workers) as executor:

            def bounded_results() -> Iterator[Tuple[Tuple[bytes, ...], int]]:
                batch_size = effective_workers * 2
                for start in range(0, leaf_count, batch_size):
                    end = min(start + batch_size, leaf_count)
                    futures = []
                    for index in range(start, end):
                        offset = index * context.chunk_size
                        length = min(
                            context.chunk_size,
                            before.st_size - offset,
                        )
                        arguments = (
                            path_string,
                            context_bytes,
                            index,
                            offset,
                            length,
                        )
                        futures.append(executor.submit(_hash_file_leaf_task, arguments))
                    for future in futures:
                        yield future.result()

            evidence = TreeWide.from_prehashed_leaves(
                context,
                bounded_results(),
            )
        after = os.stat(path_string)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError("input file changed while it was being hashed")
        return evidence
