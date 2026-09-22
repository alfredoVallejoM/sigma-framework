"""Portable resume checkpoints for Sigma Tree V1."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .codec import TreeDecodeError, decode_uint, parse_record, record, u64
from .core import TreeBuilder
from .ids import TREE_CHECKPOINT_MAGIC, TREE_SOURCE_HINT_MAGIC
from .model import DEFAULT_PROFILE, TreeFrontier, TreeProfileV1, TreeRoot


@dataclass(frozen=True)
class TreeSourceHintV1:
    """Operational source hint only; never cryptographic evidence."""

    size: int
    mtime_ns: int
    inode: int
    device: int

    def __post_init__(self) -> None:
        for name, value in (
            ("size", self.size),
            ("mtime_ns", self.mtime_ns),
            ("inode", self.inode),
            ("device", self.device),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"source hint {name} must be int")
            if not 0 <= value < 1 << 64:
                raise ValueError(f"source hint {name} is outside u64")

    def to_bytes(self) -> bytes:
        return record(
            TREE_SOURCE_HINT_MAGIC,
            (
                (1, u64(self.size)),
                (2, u64(self.mtime_ns)),
                (3, u64(self.inode)),
                (4, u64(self.device)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TreeSourceHintV1":
        fields = parse_record(
            data,
            magic=TREE_SOURCE_HINT_MAGIC,
            allowed=frozenset({1, 2, 3, 4}),
        )
        try:
            return cls(
                decode_uint(fields[1], 8),
                decode_uint(fields[2], 8),
                decode_uint(fields[3], 8),
                decode_uint(fields[4], 8),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid Sigma Tree source hint: {exc}") from exc


@dataclass(frozen=True)
class TreeResumeCheckpointV1:
    profile: TreeProfileV1
    completed_bytes: int
    completed_leaf_count: int
    frontier: TreeFrontier
    tail: bytes = b""
    source_hint: TreeSourceHintV1 | None = None

    def __post_init__(self) -> None:
        if self.profile != DEFAULT_PROFILE:
            raise ValueError("unsupported checkpoint profile")
        for name, value in (
            ("completed_bytes", self.completed_bytes),
            ("completed_leaf_count", self.completed_leaf_count),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not 0 <= value < 1 << 64:
                raise ValueError(f"{name} is outside u64")
        if not isinstance(self.frontier, TreeFrontier):
            raise TypeError("checkpoint frontier must be TreeFrontier")
        if not isinstance(self.tail, bytes):
            raise TypeError("checkpoint tail must be bytes")
        if len(self.tail) >= self.profile.chunk_size:
            raise ValueError("checkpoint tail must be shorter than chunk size")
        if self.source_hint is not None and not isinstance(self.source_hint, TreeSourceHintV1):
            raise TypeError("source_hint must be TreeSourceHintV1 or None")

        if self.frontier.byte_length != self.frontier.leaf_count * self.profile.chunk_size:
            raise ValueError("checkpoint frontier must contain only complete leaves")
        if self.completed_leaf_count != self.frontier.leaf_count:
            raise ValueError("checkpoint leaf count does not match frontier")
        expected_bytes = self.frontier.byte_length + len(self.tail)
        if self.completed_bytes != expected_bytes:
            raise ValueError("checkpoint byte count does not match frontier + tail")
        if self.completed_bytes % self.profile.chunk_size != len(self.tail):
            raise ValueError("checkpoint offset arithmetic is non-canonical")

    def to_bytes(self) -> bytes:
        return record(
            TREE_CHECKPOINT_MAGIC,
            (
                (1, self.profile.to_bytes()),
                (2, u64(self.completed_bytes)),
                (3, u64(self.completed_leaf_count)),
                (4, self.frontier.to_bytes()),
                (5, self.tail),
                (6, self.source_hint.to_bytes() if self.source_hint is not None else b""),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TreeResumeCheckpointV1":
        fields = parse_record(
            data,
            magic=TREE_CHECKPOINT_MAGIC,
            allowed=frozenset({1, 2, 3, 4, 5, 6}),
        )
        try:
            profile = TreeProfileV1.from_bytes(fields[1])
            frontier = TreeFrontier.from_bytes(fields[4])
            source_hint = (
                TreeSourceHintV1.from_bytes(fields[6])
                if fields[6]
                else None
            )
            return cls(
                profile,
                decode_uint(fields[2], 8),
                decode_uint(fields[3], 8),
                frontier,
                fields[5],
                source_hint,
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid Sigma Tree checkpoint: {exc}") from exc

    @classmethod
    def from_builder(
        cls,
        builder: TreeBuilder,
        *,
        source_hint: TreeSourceHintV1 | None = None,
    ) -> "TreeResumeCheckpointV1":
        if not isinstance(builder, TreeBuilder):
            raise TypeError("builder must be TreeBuilder")
        frontier, tail, completed_bytes, completed_leaf_count = builder.checkpoint_state()
        return cls(
            builder.profile,
            completed_bytes,
            completed_leaf_count,
            frontier,
            tail,
            source_hint,
        )

    def restore_builder(self) -> TreeBuilder:
        builder = TreeBuilder.from_checkpoint_state(
            self.frontier,
            self.tail,
            profile=self.profile,
        )
        frontier, tail, completed_bytes, completed_leaf_count = builder.checkpoint_state()
        if (
            frontier != self.frontier
            or tail != self.tail
            or completed_bytes != self.completed_bytes
            or completed_leaf_count != self.completed_leaf_count
        ):
            raise RuntimeError("restored checkpoint state does not round-trip")
        return builder


def checkpoint_builder(
    builder: TreeBuilder,
    *,
    source_hint: TreeSourceHintV1 | None = None,
) -> TreeResumeCheckpointV1:
    return TreeResumeCheckpointV1.from_builder(builder, source_hint=source_hint)


def checkpoint_bytes(
    prefix: bytes,
    *,
    source_hint: TreeSourceHintV1 | None = None,
) -> TreeResumeCheckpointV1:
    if not isinstance(prefix, bytes):
        raise TypeError("checkpoint prefix must be bytes")
    builder = TreeBuilder()
    builder.update(prefix)
    return checkpoint_builder(builder, source_hint=source_hint)


def restore_builder(checkpoint: TreeResumeCheckpointV1) -> TreeBuilder:
    if not isinstance(checkpoint, TreeResumeCheckpointV1):
        raise TypeError("checkpoint must be TreeResumeCheckpointV1")
    return checkpoint.restore_builder()


def resume_tree(checkpoint: TreeResumeCheckpointV1, suffix: bytes) -> TreeRoot:
    if not isinstance(suffix, bytes):
        raise TypeError("checkpoint suffix must be bytes")
    builder = restore_builder(checkpoint)
    builder.update(suffix)
    return builder.finalize()


def source_hint_from_path(path: str | os.PathLike[str]) -> TreeSourceHintV1:
    stat_result = Path(path).stat()
    return TreeSourceHintV1(
        size=stat_result.st_size,
        mtime_ns=stat_result.st_mtime_ns,
        inode=stat_result.st_ino,
        device=stat_result.st_dev,
    )


def source_hint_matches_path(
    hint: TreeSourceHintV1,
    path: str | os.PathLike[str],
) -> bool:
    """Heuristic source check only; false/true is not a cryptographic statement."""
    if not isinstance(hint, TreeSourceHintV1):
        raise TypeError("hint must be TreeSourceHintV1")
    try:
        current = source_hint_from_path(path)
    except OSError:
        return False
    return current == hint


def write_checkpoint_atomic(
    path: str | os.PathLike[str],
    checkpoint: TreeResumeCheckpointV1,
) -> None:
    """Persist checkpoint transactionally using a same-directory atomic replace."""
    if not isinstance(checkpoint, TreeResumeCheckpointV1):
        raise TypeError("checkpoint must be TreeResumeCheckpointV1")
    destination = Path(path)
    parent = destination.parent
    if not parent.exists():
        raise FileNotFoundError(f"checkpoint parent directory does not exist: {parent}")
    payload = checkpoint.to_bytes()

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, destination)

        try:
            directory_fd = os.open(parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_checkpoint(path: str | os.PathLike[str]) -> TreeResumeCheckpointV1:
    return TreeResumeCheckpointV1.from_bytes(Path(path).read_bytes())
