"""Bounded, replayable sources for the initial canonical-bytes profile."""

from __future__ import annotations

import hashlib
import os
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import IO, BinaryIO

MAX_U64 = (1 << 64) - 1
DEFAULT_CHUNK_SIZE = 1 << 20
DEFAULT_MAX_MEMORY_BYTES = 1 << 20
DEFAULT_MAX_SPOOL_BYTES = 1 << 30
MAX_SOURCE_CHUNK_SIZE = 1 << 24


class SourceChangedError(RuntimeError):
    """The canonical bytes changed between or during replays."""


class SourceClosedError(RuntimeError):
    """A source was used after its resources were released."""


class SourceLimitError(ValueError):
    """A stream exceeded its explicit spool policy."""


def _validate_chunk_size(chunk_size: int) -> None:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be int")
    if not 1 <= chunk_size <= MAX_SOURCE_CHUNK_SIZE:
        raise ValueError("chunk_size is out of range")


class CanonicalSource(ABC):
    """Replayable exact bytes with an immutable cardinality contract."""

    @property
    @abstractmethod
    def byte_length(self) -> int:
        """Exact number of canonical bytes produced by every replay."""

    @abstractmethod
    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        """Yield one complete replay in bounded chunks."""

    def close(self) -> None:
        """Release owned resources; no-op for resource-free sources."""
        return None

    def __enter__(self) -> CanonicalSource:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class BytesSource(CanonicalSource):
    """Immutable in-memory canonical bytes."""

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        self._data = data

    @property
    def byte_length(self) -> int:
        return len(self._data)

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        _validate_chunk_size(chunk_size)
        for offset in range(0, len(self._data), chunk_size):
            yield self._data[offset : offset + chunk_size]


def _stat_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class StableFileSource(CanonicalSource):
    """A file replay guarded by metadata and full-content consistency."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        initial = self._path.stat()
        if not self._path.is_file():
            raise ValueError("path must name a regular file")
        if not 0 <= initial.st_size <= MAX_U64:
            raise ValueError("file length is out of range")
        self._initial_fingerprint = _stat_fingerprint(initial)
        self._byte_length = initial.st_size
        self._content_digest: bytes | None = None
        self._closed = False

    @property
    def byte_length(self) -> int:
        self._ensure_open()
        return self._byte_length

    def _ensure_open(self) -> None:
        if self._closed:
            raise SourceClosedError("source is closed")

    def _require_initial_stat(self, value: os.stat_result) -> None:
        if _stat_fingerprint(value) != self._initial_fingerprint:
            raise SourceChangedError("file metadata changed")

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._ensure_open()
        _validate_chunk_size(chunk_size)
        try:
            self._require_initial_stat(self._path.stat())
            digest = hashlib.sha256()
            total = 0
            with self._path.open("rb", buffering=0) as stream:
                self._require_initial_stat(os.fstat(stream.fileno()))
                while True:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self._byte_length:
                        raise SourceChangedError("file grew during replay")
                    digest.update(chunk)
                    yield chunk
                self._require_initial_stat(os.fstat(stream.fileno()))
            self._require_initial_stat(self._path.stat())
            if total != self._byte_length:
                raise SourceChangedError("file length changed during replay")
            current_digest = digest.digest()
            if self._content_digest is None:
                self._content_digest = current_digest
            elif current_digest != self._content_digest:
                raise SourceChangedError("file content changed between replays")
        except OSError as exc:
            raise SourceChangedError("file became unavailable during replay") from exc

    def close(self) -> None:
        self._closed = True


class SpoolingStreamSource(CanonicalSource):
    """Capture a non-seekable stream once, then replay it safely."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
        max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
        read_size: int = DEFAULT_CHUNK_SIZE,
        temp_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        if not callable(getattr(stream, "read", None)):
            raise TypeError("stream must provide read(size)")
        for name, value, minimum in (
            ("max_memory_bytes", max_memory_bytes, 1),
            ("max_spool_bytes", max_spool_bytes, 0),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not minimum <= value <= MAX_U64:
                raise ValueError(f"{name} is out of range")
        if max_memory_bytes > max_spool_bytes and max_spool_bytes != 0:
            max_memory_bytes = max_spool_bytes
        _validate_chunk_size(read_size)
        spool_dir = os.fspath(temp_dir) if temp_dir is not None else None
        self._file: IO[bytes] = tempfile.SpooledTemporaryFile(
            max_size=max_memory_bytes,
            mode="w+b",
            dir=spool_dir,
        )
        self._closed = False
        self._byte_length = 0
        self._rolled_to_disk = False
        try:
            while True:
                chunk = stream.read(read_size)
                if not isinstance(chunk, bytes):
                    raise TypeError("stream.read() must return bytes")
                if not chunk:
                    break
                if len(chunk) > read_size:
                    raise SourceLimitError("stream returned more than requested read_size")
                new_length = self._byte_length + len(chunk)
                if new_length > max_spool_bytes:
                    raise SourceLimitError("stream exceeds max_spool_bytes")
                self._file.write(chunk)
                self._byte_length = new_length
            self._rolled_to_disk = self._byte_length > max_memory_bytes
            self._file.seek(0)
        except BaseException:
            self._file.close()
            self._closed = True
            raise

    @property
    def byte_length(self) -> int:
        self._ensure_open()
        return self._byte_length

    def __enter__(self) -> SpoolingStreamSource:
        self._ensure_open()
        return self

    @property
    def rolled_to_disk(self) -> bool:
        self._ensure_open()
        return self._rolled_to_disk

    @property
    def closed(self) -> bool:
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise SourceClosedError("source is closed")

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._ensure_open()
        _validate_chunk_size(chunk_size)
        self._file.seek(0)
        total = 0
        while True:
            chunk = self._file.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            yield chunk
        if total != self._byte_length:
            raise SourceChangedError("spool length changed")

    def close(self) -> None:
        if not self._closed:
            self._file.close()
            self._closed = True
