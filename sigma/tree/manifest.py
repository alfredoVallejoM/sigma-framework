"""Canonical directory manifests built on Sigma Tree V1."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .codec import (
    MAX_TREE_RECORD_BYTES,
    TreeDecodeError,
    decode_items,
    decode_uint,
    encode_items,
    parse_record,
    record,
    u16,
    u64,
)
from .core import TreeBuilder, build_tree, empty_root
from .ids import (
    MAX_MANIFEST_ENTRIES,
    TREE_MANIFEST_ENTRY_MAGIC,
    TREE_MANIFEST_MAGIC,
    ManifestEntryKind,
    ManifestMetadataProfileId,
    ManifestProfileId,
)
from .model import DEFAULT_PROFILE, TreeRoot
from .path import canonical_path_bytes, canonical_relative_path, canonical_symlink_target_bytes

_MAX_ENTRY_WIRE_BYTES = 1 << 20
_SIGMA_V3_DIGEST_MAGIC = b"SIGMA3DG"


class SymlinkPolicy(Enum):
    REJECT = "reject"
    TEXT = "text"


@dataclass(frozen=True)
class ManifestEntryV1:
    path: str
    kind: ManifestEntryKind
    byte_length: int
    tree_root: TreeRoot
    trajectory_digest: bytes | None = None
    metadata_profile: ManifestMetadataProfileId = ManifestMetadataProfileId.BASE

    def __post_init__(self) -> None:
        canonical = canonical_relative_path(self.path)
        object.__setattr__(self, "path", canonical)
        if not isinstance(self.kind, ManifestEntryKind):
            raise TypeError("manifest entry kind must be ManifestEntryKind")
        if self.metadata_profile is not ManifestMetadataProfileId.BASE:
            raise ValueError("Sigma Manifest V1 supports only the base metadata profile")
        if isinstance(self.byte_length, bool) or not isinstance(self.byte_length, int):
            raise TypeError("manifest entry byte_length must be int")
        if not 0 <= self.byte_length < 1 << 64:
            raise ValueError("manifest entry byte_length is outside u64")
        if not isinstance(self.tree_root, TreeRoot):
            raise TypeError("manifest entry tree_root must be TreeRoot")
        if self.byte_length != self.tree_root.byte_length:
            raise ValueError("manifest entry byte_length must match TreeRoot")
        if self.kind is ManifestEntryKind.DIRECTORY and self.tree_root != empty_root():
            raise ValueError("directory entries must use the canonical empty TreeRoot")
        if self.trajectory_digest is not None:
            if self.kind is not ManifestEntryKind.FILE:
                raise ValueError("trajectory digest is only valid for regular-file entries")
            if not isinstance(self.trajectory_digest, bytes):
                raise TypeError("trajectory digest wire must be bytes")
            if not self.trajectory_digest.startswith(_SIGMA_V3_DIGEST_MAGIC):
                raise ValueError("trajectory digest wire must be a SigmaDigestV3 record")
            if len(self.trajectory_digest) > _MAX_ENTRY_WIRE_BYTES // 2:
                raise ValueError("trajectory digest wire exceeds ST1 entry budget")

    @property
    def path_bytes(self) -> bytes:
        return canonical_path_bytes(self.path)

    def to_bytes(self) -> bytes:
        encoded = record(
            TREE_MANIFEST_ENTRY_MAGIC,
            (
                (1, self.path_bytes),
                (2, u16(int(self.kind))),
                (3, u16(int(self.metadata_profile))),
                (4, u64(self.byte_length)),
                (5, self.tree_root.to_bytes()),
                (6, self.trajectory_digest or b""),
            ),
        )
        if len(encoded) > _MAX_ENTRY_WIRE_BYTES:
            raise ValueError("manifest entry exceeds canonical wire budget")
        return encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> "ManifestEntryV1":
        fields = parse_record(
            data,
            magic=TREE_MANIFEST_ENTRY_MAGIC,
            allowed=frozenset({1, 2, 3, 4, 5, 6}),
        )
        try:
            path = fields[1].decode("utf-8", "strict")
            if canonical_path_bytes(path) != fields[1]:
                raise ValueError("manifest entry path is not canonical NFC UTF-8")
            kind = ManifestEntryKind(decode_uint(fields[2], 2))
            metadata = ManifestMetadataProfileId(decode_uint(fields[3], 2))
            trajectory = fields[6] or None
            return cls(
                path=path,
                kind=kind,
                byte_length=decode_uint(fields[4], 8),
                tree_root=TreeRoot.from_bytes(fields[5]),
                trajectory_digest=trajectory,
                metadata_profile=metadata,
            )
        except (UnicodeDecodeError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid Sigma Manifest entry: {exc}") from exc


@dataclass(frozen=True)
class ManifestV1:
    entries: tuple[ManifestEntryV1, ...] = ()
    profile: ManifestProfileId = ManifestProfileId.BASE_V1

    def __post_init__(self) -> None:
        if self.profile is not ManifestProfileId.BASE_V1:
            raise ValueError("unsupported Sigma Manifest profile")
        if not isinstance(self.entries, tuple) or not all(
            isinstance(entry, ManifestEntryV1) for entry in self.entries
        ):
            raise TypeError("manifest entries must be an immutable tuple")
        if len(self.entries) > MAX_MANIFEST_ENTRIES:
            raise ValueError("manifest contains too many entries")
        keys = tuple(entry.path_bytes for entry in self.entries)
        if any(left >= right for left, right in zip(keys, keys[1:])):
            raise ValueError("manifest entries must have unique canonical UTF-8 ordering")

    def to_bytes(self) -> bytes:
        encoded = record(
            TREE_MANIFEST_MAGIC,
            (
                (1, u16(int(self.profile))),
                (
                    2,
                    encode_items(
                        (entry.to_bytes() for entry in self.entries),
                        max_items=MAX_MANIFEST_ENTRIES,
                    ),
                ),
            ),
        )
        if len(encoded) > MAX_TREE_RECORD_BYTES:
            raise ValueError("manifest exceeds Sigma Tree V1 total-size limit")
        return encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> "ManifestV1":
        fields = parse_record(
            data,
            magic=TREE_MANIFEST_MAGIC,
            allowed=frozenset({1, 2}),
        )
        try:
            profile = ManifestProfileId(decode_uint(fields[1], 2))
            entries = tuple(
                ManifestEntryV1.from_bytes(item)
                for item in decode_items(fields[2], max_items=MAX_MANIFEST_ENTRIES)
            )
            return cls(entries=entries, profile=profile)
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid Sigma Manifest: {exc}") from exc


def manifest_from_entries(entries: Sequence[ManifestEntryV1]) -> ManifestV1:
    values = tuple(entries)
    if len(values) > MAX_MANIFEST_ENTRIES:
        raise ValueError("manifest contains too many entries")
    ordered = tuple(sorted(values, key=lambda entry: entry.path_bytes))
    return ManifestV1(ordered)


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_ino and right.st_ino:
        return left.st_ino == right.st_ino and left.st_dev == right.st_dev
    return True


def _tree_root_from_file(path: Path) -> TreeRoot:
    """Hash one stable regular-file handle without intentionally following links."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("manifest file entry is no longer a regular file")

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("manifest file descriptor is not a regular file")
        if not _same_file_identity(before, opened):
            raise RuntimeError("manifest file changed identity before hashing")

        builder = TreeBuilder()
        while True:
            chunk = os.read(fd, DEFAULT_PROFILE.chunk_size)
            if not chunk:
                break
            builder.update(chunk)

        after = os.fstat(fd)
        if (
            opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or opened.st_ctime_ns != after.st_ctime_ns
        ):
            raise RuntimeError("manifest file changed while hashing")
        final_path = path.lstat()
        if not stat.S_ISREG(final_path.st_mode) or not _same_file_identity(opened, final_path):
            raise RuntimeError("manifest path changed identity while hashing")
        return builder.finalize()
    finally:
        os.close(fd)


def _normalize_trajectory_map(
    values: Mapping[str, bytes] | None,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    if values is None:
        return result
    for path, wire in values.items():
        canonical = canonical_relative_path(path)
        if canonical in result:
            raise ValueError("duplicate trajectory path after canonicalization")
        if not isinstance(wire, bytes):
            raise TypeError("trajectory digest mapping values must be bytes")
        result[canonical] = wire
    return result


def build_directory_manifest(
    root: str | os.PathLike[str],
    *,
    symlink_policy: SymlinkPolicy = SymlinkPolicy.REJECT,
    trajectory_by_path: Mapping[str, bytes] | None = None,
) -> ManifestV1:
    """Build a canonical manifest without following symbolic links."""
    if not isinstance(symlink_policy, SymlinkPolicy):
        raise TypeError("symlink_policy must be SymlinkPolicy")

    root_path = Path(root)
    root_stat = root_path.lstat()
    if stat.S_ISLNK(root_stat.st_mode):
        raise ValueError("manifest root must not be a symbolic link")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("manifest root must be a directory")

    trajectory = _normalize_trajectory_map(trajectory_by_path)
    used_trajectory: set[str] = set()
    entries: list[ManifestEntryV1] = []
    stack: list[tuple[Path, str]] = [(root_path, "")]

    while stack:
        directory, prefix = stack.pop()
        with os.scandir(directory) as iterator:
            for item in iterator:
                relative = item.name if not prefix else f"{prefix}/{item.name}"
                canonical = canonical_relative_path(relative)
                item_path = Path(item.path)

                if item.is_symlink():
                    if symlink_policy is SymlinkPolicy.REJECT:
                        raise ValueError(f"symbolic link rejected by manifest policy: {canonical}")
                    target = os.readlink(item.path)
                    target_bytes = canonical_symlink_target_bytes(target)
                    entries.append(
                        ManifestEntryV1(
                            canonical,
                            ManifestEntryKind.SYMLINK,
                            len(target_bytes),
                            build_tree(target_bytes),
                        )
                    )
                    continue

                if item.is_dir(follow_symlinks=False):
                    entries.append(
                        ManifestEntryV1(
                            canonical,
                            ManifestEntryKind.DIRECTORY,
                            0,
                            empty_root(),
                        )
                    )
                    stack.append((item_path, canonical))
                    continue

                if item.is_file(follow_symlinks=False):
                    tree_root = _tree_root_from_file(item_path)
                    digest = trajectory.get(canonical)
                    if digest is not None:
                        used_trajectory.add(canonical)
                    entries.append(
                        ManifestEntryV1(
                            canonical,
                            ManifestEntryKind.FILE,
                            tree_root.byte_length,
                            tree_root,
                            digest,
                        )
                    )
                    continue

                raise ValueError(f"unsupported filesystem entry type: {canonical}")

    unused = set(trajectory) - used_trajectory
    if unused:
        raise ValueError(
            "trajectory digests reference absent/non-file manifest paths: "
            + ", ".join(sorted(unused))
        )
    return manifest_from_entries(entries)
