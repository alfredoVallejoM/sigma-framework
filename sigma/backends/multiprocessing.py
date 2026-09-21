"""Canonical TreeWide leaf hashing across worker processes."""

import mmap
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Iterator, Tuple

from sigma.anchors import AnchorEvidence, TreeWide
from sigma.file_snapshot import immutable_snapshot
from sigma.instrumentation import OracleInput, active_capture, extend_oracle_inputs
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId
from sigma.validation import require_int

from .base import ExecutionBackend, FileExecutionBackend

MAX_WORKERS = 256


def _hash_leaf_task(
    arguments: Tuple[bytes, int, bytes, bool],
) -> Tuple[Tuple[bytes, ...], int, list[OracleInput]]:
    context_bytes, index, leaf, capture = arguments
    context = SigmaContextV2.from_bytes(context_bytes)
    if capture:
        from sigma.instrumentation import capture_oracle_inputs

        with capture_oracle_inputs() as records:
            digests = tuple(
                TreeWide.leaf_digest(context, index, algorithm, leaf)
                for algorithm in context.branches
            )
        return digests, len(leaf), records
    digests = tuple(
        TreeWide.leaf_digest(context, index, algorithm, leaf) for algorithm in context.branches
    )
    return digests, len(leaf), []


def _hash_file_leaf_task(
    arguments: Tuple[str, bytes, int, int, int, bool],
) -> Tuple[Tuple[bytes, ...], int, list[OracleInput]]:
    path, context_bytes, index, offset, length, capture = arguments
    with (
        open(path, "rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
    ):
        leaf = bytes(mapped[offset : offset + length])
    digests, _, records = _hash_leaf_task((context_bytes, index, leaf, capture))
    return digests, length, records


@dataclass(frozen=True)
class MultiprocessingTreeBackend(ExecutionBackend, FileExecutionBackend):
    workers: int = 0

    def __post_init__(self) -> None:
        require_int("workers", self.workers, minimum=0, maximum=MAX_WORKERS)
        selected = self.workers or (os.cpu_count() or 1)
        require_int("workers", selected, minimum=1, maximum=MAX_WORKERS)
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
                            executor.submit(
                                _hash_leaf_task,
                                (context_bytes, index, leaf, active_capture() is not None),
                            )
                        )
                    for future in futures:
                        digests, length, records = future.result()
                        extend_oracle_inputs(records)
                        yield digests, length

            return TreeWide.from_prehashed_leaves(context, bounded_results())

    def compute_anchor_file(self, path, context: SigmaContextV2) -> AnchorEvidence:
        with immutable_snapshot(path) as (snapshot, _identity):
            return self._compute_anchor_snapshot(snapshot, context)

    def compute_anchor_snapshot(self, path, context: SigmaContextV2) -> AnchorEvidence:
        return self._compute_anchor_snapshot(path, context)

    def _compute_anchor_snapshot(self, path, context: SigmaContextV2) -> AnchorEvidence:
        if context.anchor_profile is not AnchorProfileId.TREE_WIDE:
            raise ValueError("multiprocessing backend only supports TreeWide")
        TreeWide(context)
        path_string = os.fspath(path)
        before = os.stat(path_string)
        if before.st_size == 0:
            return TreeWide.compute(context, ())
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
                            active_capture() is not None,
                        )
                        futures.append(executor.submit(_hash_file_leaf_task, arguments))
                    for future in futures:
                        digests, result_length, records = future.result()
                        extend_oracle_inputs(records)
                        yield digests, result_length

            evidence = TreeWide.from_prehashed_leaves(
                context,
                bounded_results(),
            )
        return evidence
