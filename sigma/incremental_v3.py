"""Replayable incremental Sigma v3 prefixes with semantically real checkpoints."""

from __future__ import annotations

from dataclasses import dataclass

from sigma.outputs.digest_v3 import SigmaDigestV3, digest_from_evaluation_v3
from sigma.rounds.backends_v3 import DeepBranchBackendV3
from sigma.rounds.control_v3 import CancellationTokenV3, check_cancellation_v3
from sigma.rounds.evaluate_v3 import evaluate_v3
from sigma.sources import IncrementalSpoolSource
from sigma.spec.context_v3 import SigmaContextV3


@dataclass(frozen=True)
class SigmaCheckpointV3:
    offset: int
    digest: SigmaDigestV3
    provisional: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.offset, bool) or not isinstance(self.offset, int):
            raise TypeError("offset must be int")
        if self.offset < 0:
            raise ValueError("offset must be non-negative")
        if not isinstance(self.digest, SigmaDigestV3):
            raise TypeError("digest must be SigmaDigestV3")
        if self.provisional is not True:
            raise ValueError("incremental checkpoints are provisional")


class IncrementalSigmaV3:
    def __init__(
        self,
        context: SigmaContextV3,
        *,
        backend: DeepBranchBackendV3 | None = None,
        max_memory_bytes: int = 1 << 20,
        max_spool_bytes: int = 1 << 30,
    ) -> None:
        if not isinstance(context, SigmaContextV3):
            raise TypeError("context must be SigmaContextV3")
        if backend is not None and not isinstance(backend, DeepBranchBackendV3):
            raise TypeError("backend must be DeepBranchBackendV3")
        self.context = context
        self.backend = backend
        self._source = IncrementalSpoolSource(
            max_memory_bytes=max_memory_bytes,
            max_spool_bytes=max_spool_bytes,
        )
        self._finalized = False
        self._closed = False

    @property
    def offset(self) -> int:
        self._ensure_active()
        return self._source.current_length

    @property
    def rolled_to_disk(self) -> bool:
        self._ensure_active()
        return self._source.rolled_to_disk

    def _ensure_active(self) -> None:
        if self._closed:
            raise RuntimeError("incremental Sigma v3 is closed")
        if self._finalized:
            raise RuntimeError("incremental Sigma v3 is finalized")

    def update(self, data: bytes) -> None:
        self._ensure_active()
        self._source.update(data)

    def checkpoint(self, *, cancellation: CancellationTokenV3 | None = None) -> SigmaCheckpointV3:
        self._ensure_active()
        check_cancellation_v3(cancellation)
        snapshot = self._source.snapshot()
        try:
            check_cancellation_v3(cancellation)
            evaluation = evaluate_v3(
                self.context,
                snapshot,
                backend=self.backend,
                cancellation=cancellation,
            )
            digest = digest_from_evaluation_v3(evaluation)
        finally:
            snapshot.close()
        return SigmaCheckpointV3(self._source.current_length, digest)

    def finalize(self, *, cancellation: CancellationTokenV3 | None = None) -> SigmaDigestV3:
        self._ensure_active()
        self._finalized = True
        self._source.finalize()
        try:
            evaluation = evaluate_v3(
                self.context,
                self._source,
                backend=self.backend,
                cancellation=cancellation,
            )
            return digest_from_evaluation_v3(evaluation)
        finally:
            self._source.close()

    def close(self) -> None:
        if not self._closed:
            self._source.close()
            self._closed = True

    def __enter__(self) -> IncrementalSigmaV3:
        self._ensure_active()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


__all__ = ["IncrementalSigmaV3", "SigmaCheckpointV3"]
