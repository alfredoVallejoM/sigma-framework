"""Cooperative cancellation for bounded Sigma v3 evaluation."""

from __future__ import annotations

import threading
from collections.abc import Iterator

from sigma.sources import CanonicalSource


class EvaluationCancelledV3(RuntimeError):
    """Evaluation was cancelled at a canonical boundary."""


class CancellationTokenV3:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise EvaluationCancelledV3("Sigma v3 evaluation cancelled")


class CancellableSourceV3(CanonicalSource):
    """Non-owning source view that checks cancellation around every chunk."""

    def __init__(self, source: CanonicalSource, token: CancellationTokenV3) -> None:
        if not isinstance(source, CanonicalSource):
            raise TypeError("source must be CanonicalSource")
        if not isinstance(token, CancellationTokenV3):
            raise TypeError("token must be CancellationTokenV3")
        self._source = source
        self._token = token

    @property
    def byte_length(self) -> int:
        self._token.raise_if_cancelled()
        return self._source.byte_length

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._token.raise_if_cancelled()
        for chunk in self._source.iter_chunks(chunk_size):
            self._token.raise_if_cancelled()
            yield chunk
        self._token.raise_if_cancelled()


def checked_source_v3(
    source: CanonicalSource,
    token: CancellationTokenV3 | None,
) -> CanonicalSource:
    if token is None:
        return source
    if not isinstance(token, CancellationTokenV3):
        raise TypeError("cancellation must be CancellationTokenV3")
    return CancellableSourceV3(source, token)


def check_cancellation_v3(token: CancellationTokenV3 | None) -> None:
    if token is not None:
        if not isinstance(token, CancellationTokenV3):
            raise TypeError("cancellation must be CancellationTokenV3")
        token.raise_if_cancelled()


__all__ = [
    "CancellableSourceV3",
    "CancellationTokenV3",
    "EvaluationCancelledV3",
    "check_cancellation_v3",
    "checked_source_v3",
]
