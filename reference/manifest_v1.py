"""Independent stdlib-only reference for Sigma Manifest V1."""

from __future__ import annotations

import os
import stat
import unicodedata
from pathlib import Path, PureWindowsPath

from reference.tree_v1 import root_wire as tree_root_wire

VERSION = 1
ENTRY_MAGIC = b"SIGTENT1"
MANIFEST_MAGIC = b"SIGTMNF1"
MAX_ENTRIES = 65_535
MAX_PATH_BYTES = 4_096
MAX_TARGET_BYTES = 4_096
MAX_RECORD_BYTES = 8 << 20
MAX_ENTRY_BYTES = 1 << 20


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def tlv(fields):
    previous = 0
    out = bytearray()
    for tag, value in fields:
        if tag <= previous:
            raise ValueError("non-canonical TLV order")
        if len(value) > 1 << 20:
            raise ValueError("field too large")
        out += tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        previous = tag
    return bytes(out)


def record(magic: bytes, fields):
    body = tlv(fields)
    return magic + u16(VERSION) + u32(len(body)) + body


def items(values):
    values = tuple(values)
    if len(values) > MAX_ENTRIES:
        raise ValueError("too many manifest entries")
    return u16(len(values)) + b"".join(u32(len(value)) + value for value in values)


def canonical_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid manifest path")
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise ValueError("invalid manifest path")
    if PureWindowsPath(value).drive:
        raise ValueError("invalid manifest path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid manifest path")
    normalized = "/".join(unicodedata.normalize("NFC", part) for part in parts)
    encoded = normalized.encode("utf-8", "strict")
    if len(encoded) > MAX_PATH_BYTES:
        raise ValueError("manifest path too long")
    return normalized


def canonical_target(value: str) -> bytes:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("invalid symlink target")
    encoded = unicodedata.normalize("NFC", value).encode("utf-8", "strict")
    if len(encoded) > MAX_TARGET_BYTES:
        raise ValueError("symlink target too long")
    return encoded


def entry_wire(
    path: str,
    kind: int,
    payload: bytes,
    trajectory: bytes | None = None,
) -> bytes:
    canonical = canonical_path(path)
    if kind not in (1, 2, 3):
        raise ValueError("invalid entry kind")
    if kind == 2 and payload != b"":
        raise ValueError("directory payload must be empty")
    if trajectory is not None:
        if kind != 1 or not trajectory.startswith(b"SIGMA3DG"):
            raise ValueError("invalid trajectory attachment")
    root = tree_root_wire(payload)
    encoded = record(
        ENTRY_MAGIC,
        (
            (1, canonical.encode("utf-8")),
            (2, u16(kind)),
            (3, u16(1)),
            (4, u64(len(payload))),
            (5, root),
            (6, trajectory or b""),
        ),
    )
    if len(encoded) > MAX_ENTRY_BYTES:
        raise ValueError("manifest entry too large")
    return encoded


def manifest_wire(entries) -> bytes:
    materialized = []
    seen = set()
    for path, kind, payload, trajectory in entries:
        canonical = canonical_path(path)
        key = canonical.encode("utf-8")
        if key in seen:
            raise ValueError("duplicate canonical path")
        seen.add(key)
        materialized.append((key, entry_wire(canonical, kind, payload, trajectory)))
    materialized.sort(key=lambda item: item[0])
    encoded = record(
        MANIFEST_MAGIC,
        (
            (1, u16(1)),
            (2, items(value for _, value in materialized)),
        ),
    )
    if len(encoded) > MAX_RECORD_BYTES:
        raise ValueError("manifest too large")
    return encoded


def build_directory_wire(
    root: str | os.PathLike[str],
    *,
    allow_symlinks: bool = False,
    trajectory_by_path: dict[str, bytes] | None = None,
) -> bytes:
    root_path = Path(root)
    root_stat = root_path.lstat()
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("manifest root must be a real directory")

    trajectory = {}
    for key, value in (trajectory_by_path or {}).items():
        canonical = canonical_path(key)
        if canonical in trajectory:
            raise ValueError("duplicate trajectory path")
        trajectory[canonical] = value

    used = set()
    logical = []
    stack = [(root_path, "")]
    while stack:
        directory, prefix = stack.pop()
        with os.scandir(directory) as iterator:
            for item in iterator:
                relative = item.name if not prefix else f"{prefix}/{item.name}"
                canonical = canonical_path(relative)
                item_path = Path(item.path)

                if item.is_symlink():
                    if not allow_symlinks:
                        raise ValueError("symbolic link rejected")
                    logical.append((canonical, 3, canonical_target(os.readlink(item.path)), None))
                elif item.is_dir(follow_symlinks=False):
                    logical.append((canonical, 2, b"", None))
                    stack.append((item_path, canonical))
                elif item.is_file(follow_symlinks=False):
                    payload = item_path.read_bytes()
                    digest = trajectory.get(canonical)
                    if digest is not None:
                        used.add(canonical)
                    logical.append((canonical, 1, payload, digest))
                else:
                    raise ValueError("unsupported filesystem entry")

    if set(trajectory) != used:
        raise ValueError("unused trajectory mapping")
    return manifest_wire(logical)
