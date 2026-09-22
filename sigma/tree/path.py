"""Canonical portable paths for Sigma Manifest V1."""

from __future__ import annotations

import unicodedata
from pathlib import PureWindowsPath

from .ids import MAX_MANIFEST_PATH_BYTES, MAX_MANIFEST_SYMLINK_TARGET_BYTES


def _utf8(value: str, *, label: str, limit: int) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be str")
    if "\x00" in value:
        raise ValueError(f"{label} contains NUL")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} is not valid Unicode/UTF-8") from exc
    if len(encoded) > limit:
        raise ValueError(f"{label} exceeds {limit} UTF-8 bytes")
    return encoded


def canonical_relative_path(value: str) -> str:
    """Return the NFC canonical form of a portable relative manifest path."""
    if not isinstance(value, str):
        raise TypeError("manifest path must be str")
    if not value:
        raise ValueError("manifest path must not be empty")
    if "\\" in value:
        raise ValueError("manifest path must use '/' separators")
    if value.startswith("/"):
        raise ValueError("manifest path must be relative")
    if PureWindowsPath(value).drive:
        raise ValueError("manifest path must not contain a Windows drive/UNC prefix")

    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("manifest path contains an empty, '.' or '..' component")

    normalized = "/".join(unicodedata.normalize("NFC", part) for part in parts)
    normalized_parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in normalized_parts):
        raise ValueError("manifest path is non-canonical after Unicode normalization")
    _utf8(normalized, label="manifest path", limit=MAX_MANIFEST_PATH_BYTES)
    return normalized


def canonical_path_bytes(value: str) -> bytes:
    return _utf8(
        canonical_relative_path(value),
        label="manifest path",
        limit=MAX_MANIFEST_PATH_BYTES,
    )


def decode_canonical_path(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("manifest path wire must be bytes")
    try:
        value = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("manifest path wire is not valid UTF-8") from exc
    canonical = canonical_relative_path(value)
    if canonical_path_bytes(canonical) != data:
        raise ValueError("manifest path wire is not in canonical NFC form")
    return canonical


def canonical_symlink_target(value: str) -> str:
    """Canonicalize only the textual representation; never resolve or follow it."""
    if not isinstance(value, str):
        raise TypeError("symlink target must be str")
    if not value:
        raise ValueError("symlink target must not be empty")
    normalized = unicodedata.normalize("NFC", value)
    _utf8(
        normalized,
        label="symlink target",
        limit=MAX_MANIFEST_SYMLINK_TARGET_BYTES,
    )
    return normalized


def canonical_symlink_target_bytes(value: str) -> bytes:
    return _utf8(
        canonical_symlink_target(value),
        label="symlink target",
        limit=MAX_MANIFEST_SYMLINK_TARGET_BYTES,
    )
