"""Bounded, replayable sources for the initial canonical-bytes profile."""

from __future__ import annotations

import hashlib
import mmap
import os
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import IO, BinaryIO, cast

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


def _stat_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    """Metadata fields that are stable across path/fd views on this platform.

    POSIX can reliably bind pathname and descriptor identity with device/inode
    plus mutation timestamps. Windows denies pathname replacement while an open
    descriptor is held, while device/inode/ctime representations can differ
    between path and handle views. There we retain size+mtime as the metadata
    guard and rely on the existing full SHA-256 replay check for byte identity.
    """

    if os.name == "nt":
        return (int(value.st_size), int(value.st_mtime_ns))
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _path_content_digest(path: Path, expected_size: int) -> bytes:
    """Hash the current pathname bytes with an exact-length guard."""

    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb", buffering=0) as stream:
            while True:
                chunk = stream.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    raise SourceChangedError("file grew during verification")
                digest.update(chunk)
    except OSError as exc:
        raise SourceChangedError("file became unavailable during verification") from exc
    if total != expected_size:
        raise SourceChangedError("file length changed during verification")
    return digest.digest()


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
            if (
                os.name == "nt"
                and _path_content_digest(self._path, self._byte_length) != current_digest
            ):
                # Windows path/fd metadata can be coarser than the mutations we
                # need to detect. Re-read the pathname after closing the handle
                # and require exact byte identity with the replay just emitted.
                raise SourceChangedError("file content changed during replay")
            if self._content_digest is None:
                self._content_digest = current_digest
            elif current_digest != self._content_digest:
                raise SourceChangedError("file content changed between replays")
        except OSError as exc:
            raise SourceChangedError("file became unavailable during replay") from exc

    def close(self) -> None:
        self._closed = True


class MmapFileSource(CanonicalSource):
    """Immutable temporary snapshot replayed through read-only mmap slices."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        initial = self._path.stat()
        if not self._path.is_file():
            raise ValueError("path must name a regular file")
        if not 0 <= initial.st_size <= MAX_U64:
            raise ValueError("file length is out of range")
        self._initial_fingerprint = _stat_fingerprint(initial)
        self._byte_length = initial.st_size
        self._file: IO[bytes] = tempfile.TemporaryFile(mode="w+b")
        self._view: mmap.mmap | None = None
        self._closed = True
        try:
            source_digest = hashlib.sha256()
            with self._path.open("rb", buffering=0) as source:
                self._require_initial_stat(os.fstat(source.fileno()))
                total = 0
                while True:
                    chunk = source.read(DEFAULT_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self._byte_length:
                        raise SourceChangedError("file grew during mmap snapshot")
                    source_digest.update(chunk)
                    self._file.write(chunk)
                self._require_initial_stat(os.fstat(source.fileno()))
            self._require_initial_stat(self._path.stat())
            if total != self._byte_length:
                raise SourceChangedError("file length changed during mmap snapshot")
            if (
                os.name == "nt"
                and _path_content_digest(self._path, self._byte_length) != source_digest.digest()
            ):
                raise SourceChangedError("file content changed during mmap snapshot")
            self._file.flush()
            self._file.seek(0)
            if self._byte_length:
                self._view = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            self._closed = False
        except BaseException:
            if self._view is not None:
                self._view.close()
            self._file.close()
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise SourceClosedError("source is closed")

    def _require_initial_stat(self, value: os.stat_result) -> None:
        if _stat_fingerprint(value) != self._initial_fingerprint:
            raise SourceChangedError("file metadata changed")

    @property
    def byte_length(self) -> int:
        self._ensure_open()
        return self._byte_length

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._ensure_open()
        _validate_chunk_size(chunk_size)
        if self._view is None:
            return
        for offset in range(0, self._byte_length, chunk_size):
            yield self._view[offset : min(offset + chunk_size, self._byte_length)]

    def close(self) -> None:
        if not self._closed:
            if self._view is not None:
                self._view.close()
            self._file.close()
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


class IncrementalSpoolSource(CanonicalSource):
    """Bounded incremental writer that becomes replayable only when finalized."""

    def __init__(
        self,
        *,
        max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
        max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
        temp_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        for name, value, minimum in (
            ("max_memory_bytes", max_memory_bytes, 1),
            ("max_spool_bytes", max_spool_bytes, 0),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not minimum <= value <= MAX_U64:
                raise ValueError(f"{name} is out of range")
        if max_memory_bytes > max_spool_bytes and max_spool_bytes != 0:
            raise ValueError("max_memory_bytes exceeds max_spool_bytes")
        spool_dir = os.fspath(temp_dir) if temp_dir is not None else None
        self._file: IO[bytes] = tempfile.SpooledTemporaryFile(
            max_size=max_memory_bytes,
            mode="w+b",
            dir=spool_dir,
        )
        self._max_memory_bytes = max_memory_bytes
        self._max_spool_bytes = max_spool_bytes
        self._byte_length = 0
        self._finalized = False
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise SourceClosedError("source is closed")

    def _ensure_finalized(self) -> None:
        self._ensure_open()
        if not self._finalized:
            raise RuntimeError("incremental source is not finalized")

    @property
    def byte_length(self) -> int:
        self._ensure_finalized()
        return self._byte_length

    @property
    def current_length(self) -> int:
        self._ensure_open()
        return self._byte_length

    @property
    def rolled_to_disk(self) -> bool:
        self._ensure_open()
        return self._byte_length > self._max_memory_bytes

    @property
    def closed(self) -> bool:
        return self._closed

    def update(self, data: bytes) -> None:
        self._ensure_open()
        if self._finalized:
            raise RuntimeError("incremental source is finalized")
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        new_length = self._byte_length + len(data)
        if new_length > self._max_spool_bytes:
            raise SourceLimitError("incremental source exceeds max_spool_bytes")
        self._file.seek(0, os.SEEK_END)
        self._file.write(data)
        self._byte_length = new_length

    def snapshot(self) -> SpoolingStreamSource:
        """Copy the current prefix into an independent replayable source."""

        self._ensure_open()
        self._file.seek(0)
        try:
            return SpoolingStreamSource(
                cast(BinaryIO, self._file),
                max_memory_bytes=self._max_memory_bytes,
                max_spool_bytes=self._max_spool_bytes,
            )
        finally:
            self._file.seek(0, os.SEEK_END)

    def finalize(self) -> IncrementalSpoolSource:
        self._ensure_open()
        if self._finalized:
            raise RuntimeError("incremental source is already finalized")
        self._finalized = True
        self._file.seek(0)
        return self

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._ensure_finalized()
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
            raise SourceChangedError("incremental spool length changed")

    def close(self) -> None:
        if not self._closed:
            self._file.close()
            self._closed = True
