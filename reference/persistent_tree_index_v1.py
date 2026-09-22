"""Independent stdlib-only encoder for PX0 persistent Tree indexes."""

from __future__ import annotations

import hashlib

from reference import tree_v1

MAGIC = b"SIGTIDX1"
VERSION = 1
INTEGRITY_DOMAIN = b"SIGMA-PERSISTENT-TREE-INDEX-V1\x00"


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _canonical_nodes(data: bytes):
    leaves = tree_v1._leaves(data)
    if not leaves:
        return ()

    values = {}

    def build(start: int, count: int):
        key = (start, count)
        existing = values.get(key)
        if existing is not None:
            return existing
        if count == 1:
            node = leaves[start]
        else:
            left = 1 << ((count - 1).bit_length() - 1)
            node = tree_v1.parent(
                build(start, left),
                build(start + left, count - left),
            )
        values[key] = node
        return node

    build(0, len(leaves))
    return tuple(values[key] for key in sorted(values))


def _source_hint_wire(source_hint) -> bytes:
    if source_hint is None:
        return b""
    size, mtime_ns, inode, device = source_hint
    return tree_v1.record(
        b"SIGTSRC1",
        (
            (1, tree_v1.u64(size)),
            (2, tree_v1.u64(mtime_ns)),
            (3, tree_v1.u64(inode)),
            (4, tree_v1.u64(device)),
        ),
    )


def persistent_index_wire(data: bytes, *, source_hint=None) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    profile = tree_v1.profile_bytes()
    root = tree_v1.root_wire(data)
    hint = _source_hint_wire(source_hint)
    nodes = _canonical_nodes(data)

    out = bytearray()
    out.extend(MAGIC)
    out.extend(_u16(VERSION))
    out.extend(_u32(len(profile)))
    out.extend(profile)
    out.extend(_u32(len(root)))
    out.extend(root)
    out.extend(_u32(len(hint)))
    out.extend(hint)
    out.extend(_u64(len(nodes)))
    for node in nodes:
        raw = tree_v1.node_wire(node)
        out.extend(_u32(len(raw)))
        out.extend(raw)

    payload = bytes(out)
    return payload + hashlib.sha256(INTEGRITY_DOMAIN + payload).digest()


__all__ = ["persistent_index_wire"]
