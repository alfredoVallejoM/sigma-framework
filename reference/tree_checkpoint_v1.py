"""Independent stdlib-only reference for Sigma Tree V1 portable checkpoints."""

from __future__ import annotations

import struct

from reference.tree_v1 import (
    CHUNK,
    empty,
    items,
    leaf,
    node_wire,
    parent,
    profile_bytes,
    record,
    u64,
)

VERSION = 1
CHECKPOINT_MAGIC = b"SIGTCHK1"
SOURCE_HINT_MAGIC = b"SIGTSRC1"
FRONTIER_MAGIC = b"SIGTFRNT"
NODE_MAGIC = b"SIGTNODE"
MAX_RECORD_BYTES = 8 << 20
MAX_FIELD_BYTES = 1 << 20
MAX_FRONTIER_NODES = 64


def _u(data: bytes, width: int) -> int:
    if len(data) != width:
        raise ValueError("invalid integer width")
    return int.from_bytes(data, "big")


def _parse_record(data: bytes, magic: bytes, allowed: set[int]) -> dict[int, bytes]:
    if not isinstance(data, bytes) or len(data) > MAX_RECORD_BYTES:
        raise ValueError("invalid checkpoint record")
    if len(data) < 14 or data[:8] != magic or _u(data[8:10], 2) != VERSION:
        raise ValueError("invalid checkpoint record header")
    if _u(data[10:14], 4) != len(data) - 14:
        raise ValueError("checkpoint record length mismatch")
    result: dict[int, bytes] = {}
    offset = 14
    previous = 0
    while offset < len(data):
        if offset + 6 > len(data):
            raise ValueError("truncated checkpoint TLV")
        tag, length = struct.unpack_from(">HI", data, offset)
        offset += 6
        if tag not in allowed or tag <= previous or length > MAX_FIELD_BYTES:
            raise ValueError("non-canonical checkpoint TLV")
        end = offset + length
        if end > len(data):
            raise ValueError("truncated checkpoint field")
        result[tag] = data[offset:end]
        previous = tag
        offset = end
    if set(result) != allowed:
        raise ValueError("missing checkpoint fields")
    return result


def _parse_items(data: bytes, maximum: int) -> tuple[bytes, ...]:
    if len(data) < 2:
        raise ValueError("truncated checkpoint sequence")
    count = _u(data[:2], 2)
    if count > maximum:
        raise ValueError("too many checkpoint sequence items")
    offset = 2
    values = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise ValueError("truncated checkpoint item length")
        length = _u(data[offset : offset + 4], 4)
        offset += 4
        if length > MAX_FIELD_BYTES:
            raise ValueError("oversized checkpoint item")
        end = offset + length
        if end > len(data):
            raise ValueError("truncated checkpoint item")
        values.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise ValueError("trailing checkpoint sequence bytes")
    return tuple(values)


def _parse_digests(data: bytes):
    values = _parse_items(data, 4)
    if len(values) != 4 or any(len(value) != 64 for value in values):
        raise ValueError("invalid checkpoint digest vector")
    return values


def _parse_node(data: bytes):
    fields = _parse_record(data, NODE_MAGIC, {1, 2, 3, 4, 5})
    start = _u(fields[1], 8)
    count = _u(fields[2], 8)
    byte_length = _u(fields[3], 8)
    height = _u(fields[4], 4)
    digests = _parse_digests(fields[5])
    if count <= 0 or start + count >= 1 << 64:
        raise ValueError("invalid checkpoint node interval")
    if height != (count - 1).bit_length():
        raise ValueError("invalid checkpoint node height")
    if byte_length != count * CHUNK:
        raise ValueError("checkpoint frontier node must be byte-full")
    if count != 1 << height:
        raise ValueError("checkpoint frontier node must be perfect")
    return (start, count, byte_length, height, digests)


def _parse_frontier(data: bytes):
    fields = _parse_record(data, FRONTIER_MAGIC, {1, 2})
    if fields[1] != profile_bytes():
        raise ValueError("unsupported checkpoint frontier profile")
    nodes = tuple(_parse_node(raw) for raw in _parse_items(fields[2], MAX_FRONTIER_NODES))
    cursor = 0
    previous_height = None
    for node in nodes:
        start, count, _, height, _ = node
        if start != cursor:
            raise ValueError("checkpoint frontier is not contiguous")
        if previous_height is not None and height >= previous_height:
            raise ValueError("checkpoint frontier heights are not decreasing")
        cursor += count
        previous_height = height
    expected_heights = tuple(
        h for h in range(cursor.bit_length() - 1, -1, -1) if cursor & (1 << h)
    )
    if tuple(node[3] for node in nodes) != expected_heights:
        raise ValueError("checkpoint frontier is not the canonical binary decomposition")
    return nodes


def _parse_source_hint(data: bytes) -> None:
    if not data:
        return
    fields = _parse_record(data, SOURCE_HINT_MAGIC, {1, 2, 3, 4})
    for tag in (1, 2, 3, 4):
        _u(fields[tag], 8)


def parse_checkpoint(data: bytes):
    fields = _parse_record(data, CHECKPOINT_MAGIC, {1, 2, 3, 4, 5, 6})
    if fields[1] != profile_bytes():
        raise ValueError("unsupported checkpoint profile")
    completed_bytes = _u(fields[2], 8)
    completed_leaf_count = _u(fields[3], 8)
    frontier = _parse_frontier(fields[4])
    tail = fields[5]
    _parse_source_hint(fields[6])

    if len(tail) >= CHUNK:
        raise ValueError("checkpoint tail is too long")
    frontier_leaves = sum(node[1] for node in frontier)
    frontier_bytes = sum(node[2] for node in frontier)
    if completed_leaf_count != frontier_leaves:
        raise ValueError("checkpoint leaf accounting mismatch")
    if completed_bytes != frontier_bytes + len(tail):
        raise ValueError("checkpoint byte accounting mismatch")
    if completed_bytes % CHUNK != len(tail):
        raise ValueError("checkpoint offset arithmetic mismatch")
    return completed_bytes, completed_leaf_count, frontier, tail


def _integrate(nodes: list[tuple], node: tuple) -> None:
    while nodes and nodes[-1][3] == node[3]:
        node = parent(nodes.pop(), node)
    nodes.append(node)


def _frontier_wire(nodes: tuple[tuple, ...]) -> bytes:
    return record(
        FRONTIER_MAGIC,
        (
            (1, profile_bytes()),
            (2, items(node_wire(node) for node in nodes)),
        ),
    )


def checkpoint_wire(prefix: bytes) -> bytes:
    if not isinstance(prefix, bytes):
        raise TypeError("prefix must be bytes")
    full_count = len(prefix) // CHUNK
    tail = prefix[full_count * CHUNK :]
    nodes: list[tuple] = []
    for index in range(full_count):
        raw = prefix[index * CHUNK : (index + 1) * CHUNK]
        _integrate(nodes, leaf(index, raw))
    return record(
        CHECKPOINT_MAGIC,
        (
            (1, profile_bytes()),
            (2, u64(len(prefix))),
            (3, u64(full_count)),
            (4, _frontier_wire(tuple(nodes))),
            (5, tail),
            (6, b""),
        ),
    )


def _root_wire_from_state(nodes: list[tuple], tail: bytes, leaf_count: int, byte_length: int) -> bytes:
    if tail:
        _integrate(nodes, leaf(leaf_count, tail))
        leaf_count += 1
    if not nodes:
        digests = empty()
        return record(
            b"SIGTROOT",
            ((1, profile_bytes()), (2, u64(0)), (3, u64(0)), (4, items(digests))),
        )
    node = nodes[-1]
    for left in reversed(nodes[:-1]):
        node = parent(left, node)
    if node[0] != 0 or node[1] != leaf_count or node[2] != byte_length:
        raise ValueError("reference checkpoint root accounting failed")
    return record(
        b"SIGTROOT",
        (
            (1, profile_bytes()),
            (2, u64(byte_length)),
            (3, u64(leaf_count)),
            (4, items(node[4])),
        ),
    )


def resume_checkpoint_wire(checkpoint: bytes, suffix: bytes) -> bytes:
    if not isinstance(suffix, bytes):
        raise TypeError("suffix must be bytes")
    completed_bytes, completed_leaf_count, frontier, tail = parse_checkpoint(checkpoint)
    if completed_bytes + len(suffix) >= 1 << 64:
        raise ValueError("resumed input exceeds u64")

    nodes = list(frontier)
    leaf_count = completed_leaf_count
    buffer = bytearray(tail)
    offset = 0

    if buffer:
        take = min(CHUNK - len(buffer), len(suffix))
        buffer.extend(suffix[:take])
        offset = take
        if len(buffer) == CHUNK:
            _integrate(nodes, leaf(leaf_count, bytes(buffer)))
            leaf_count += 1
            buffer.clear()

    while len(suffix) - offset >= CHUNK:
        end = offset + CHUNK
        _integrate(nodes, leaf(leaf_count, suffix[offset:end]))
        leaf_count += 1
        offset = end

    buffer.extend(suffix[offset:])
    return _root_wire_from_state(
        nodes,
        bytes(buffer),
        leaf_count,
        completed_bytes + len(suffix),
    )
