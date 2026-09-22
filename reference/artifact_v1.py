"""Independent stdlib-only encoder for Sigma Artifact V1."""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata

VERSION = 1
ARTIFACT_MAGIC = b"SIGARTF1"
IDENTITY_MAGIC = b"SIGAIDN1"
DESCRIPTOR_MAGIC = b"SIGADSC1"
ARTIFACT_ID_DOMAIN = b"SIGMA-ARTIFACT-ID-V1\x00"
MANIFEST_ID_DOMAIN = b"SIGMA-MANIFEST-ID-V1\x00"
MAX_FIELD_LENGTH = 1 << 20

PROFILE_TREE = 1
PROFILE_TRAJECTORY = 2
PROFILE_DUAL = 3
DESCRIPTOR_PROFILE_BASE = 1

_MEDIA_TYPE_RE = re.compile(
    rb"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*"
)


def _u(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def _field(tag: int, value: bytes) -> bytes:
    if not 0 < tag <= 0xFFFF:
        raise ValueError("invalid TLV tag")
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError("field too large")
    return struct.pack(">HI", tag, len(value)) + value


def _record(magic: bytes, fields) -> bytes:
    body = bytearray()
    previous = 0
    for tag, value in fields:
        if tag <= previous:
            raise ValueError("non-canonical TLV order")
        body.extend(_field(tag, value))
        previous = tag
    return magic + _u(VERSION, 2) + _u(len(body), 4) + bytes(body)


def _id_sequence(values) -> bytes:
    values = tuple(values)
    if tuple(sorted(set(values))) != values:
        raise ValueError("parent IDs must be sorted and unique")
    if any(len(value) != 32 for value in values):
        raise ValueError("parent IDs must be 32 bytes")
    return _u(len(values), 2) + b"".join(values)


def descriptor_wire(
    *,
    logical_name: str = "",
    media_type: str = "",
) -> bytes:
    if unicodedata.normalize("NFC", logical_name) != logical_name or "\x00" in logical_name:
        raise ValueError("non-canonical logical name")
    name = logical_name.encode("utf-8")
    if media_type:
        encoded_media = media_type.encode("ascii")
        if media_type.lower() != media_type or _MEDIA_TYPE_RE.fullmatch(encoded_media) is None:
            raise ValueError("non-canonical media type")
    else:
        encoded_media = b""
    return _record(
        DESCRIPTOR_MAGIC,
        (
            (1, _u(DESCRIPTOR_PROFILE_BASE, 2)),
            (2, name),
            (3, encoded_media),
        ),
    )


def identity_wire(
    *,
    profile: int,
    descriptor: bytes,
    tree_root: bytes = b"",
    trajectory_digest: bytes = b"",
    manifest_id: bytes = b"",
    parent_artifact_ids=(),
) -> bytes:
    has_tree = bool(tree_root)
    has_trajectory = bool(trajectory_digest)
    expected = {
        PROFILE_TREE: (True, False),
        PROFILE_TRAJECTORY: (False, True),
        PROFILE_DUAL: (True, True),
    }[profile]
    if (has_tree, has_trajectory) != expected:
        raise ValueError("profile/evidence mismatch")
    if manifest_id and len(manifest_id) != 32:
        raise ValueError("manifest ID must be 32 bytes")
    return _record(
        IDENTITY_MAGIC,
        (
            (1, _u(profile, 2)),
            (2, descriptor),
            (3, tree_root),
            (4, trajectory_digest),
            (5, manifest_id),
            (6, _id_sequence(parent_artifact_ids)),
        ),
    )


def artifact_id(identity: bytes) -> bytes:
    return hashlib.sha256(ARTIFACT_ID_DOMAIN + identity).digest()


def artifact_wire(
    *,
    identity: bytes,
    trajectory_audit: bytes = b"",
) -> bytes:
    return _record(
        ARTIFACT_MAGIC,
        (
            (1, artifact_id(identity)),
            (2, identity),
            (3, trajectory_audit),
        ),
    )


def manifest_id(manifest_wire: bytes) -> bytes:
    return hashlib.sha256(MANIFEST_ID_DOMAIN + manifest_wire).digest()


__all__ = [
    "DESCRIPTOR_PROFILE_BASE",
    "PROFILE_DUAL",
    "PROFILE_TRAJECTORY",
    "PROFILE_TREE",
    "artifact_id",
    "artifact_wire",
    "descriptor_wire",
    "identity_wire",
    "manifest_id",
]
