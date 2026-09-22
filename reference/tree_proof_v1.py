"""Independent stdlib-only verifier for Sigma Tree V1 ST2 proofs.

This module imports no code from sigma. It consumes proof wires produced by
the product implementation and reconstructs the ST0 TreeRoot using the
independent Tree V1 reference.
"""

from __future__ import annotations

import hmac
import struct

from reference.tree_v1 import CHUNK, leaf, parent, profile_bytes

VERSION = 1
NODE_MAGIC = b"SIGTNODE"
ROOT_MAGIC = b"SIGTROOT"
STEP_MAGIC = b"SIGTPST1"
INCLUSION_MAGIC = b"SIGTIPF1"
RANGE_MAGIC = b"SIGTRPF1"
MAX_RECORD_BYTES = 8 << 20
MAX_FIELD_BYTES = 1 << 20
MAX_INCLUSION_STEPS = 64
MAX_RANGE_WITNESSES = 128


def _u(data: bytes, width: int) -> int:
    if len(data) != width:
        raise ValueError("invalid integer width")
    return int.from_bytes(data, "big")


def _parse_record(data: bytes, magic: bytes, allowed: set[int]) -> dict[int, bytes]:
    if not isinstance(data, bytes) or len(data) > MAX_RECORD_BYTES:
        raise ValueError("invalid record")
    if len(data) < 14 or data[:8] != magic or _u(data[8:10], 2) != VERSION:
        raise ValueError("invalid record header")
    if _u(data[10:14], 4) != len(data) - 14:
        raise ValueError("record length mismatch")
    out: dict[int, bytes] = {}
    offset = 14
    previous = 0
    while offset < len(data):
        if offset + 6 > len(data):
            raise ValueError("truncated TLV")
        tag, length = struct.unpack_from(">HI", data, offset)
        offset += 6
        if tag not in allowed or tag <= previous or length > MAX_FIELD_BYTES:
            raise ValueError("non-canonical TLV")
        end = offset + length
        if end > len(data):
            raise ValueError("truncated TLV value")
        out[tag] = data[offset:end]
        previous = tag
        offset = end
    if set(out) != allowed:
        raise ValueError("missing proof fields")
    return out


def _parse_items(data: bytes, maximum: int) -> tuple[bytes, ...]:
    if len(data) < 2:
        raise ValueError("truncated sequence")
    count = _u(data[:2], 2)
    if count > maximum:
        raise ValueError("too many sequence items")
    values = []
    offset = 2
    for _ in range(count):
        if offset + 4 > len(data):
            raise ValueError("truncated sequence length")
        length = _u(data[offset : offset + 4], 4)
        offset += 4
        if length > MAX_FIELD_BYTES:
            raise ValueError("oversized sequence item")
        end = offset + length
        if end > len(data):
            raise ValueError("truncated sequence item")
        values.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise ValueError("trailing sequence bytes")
    return tuple(values)


def _expected_height(count: int) -> int:
    if count <= 0:
        raise ValueError("invalid subtree count")
    return (count - 1).bit_length()


def _parse_digests(data: bytes) -> tuple[bytes, ...]:
    values = _parse_items(data, 4)
    if len(values) != 4 or any(len(value) != 64 for value in values):
        raise ValueError("invalid digest vector")
    return values


def _parse_node(data: bytes):
    fields = _parse_record(data, NODE_MAGIC, {1, 2, 3, 4, 5})
    start = _u(fields[1], 8)
    count = _u(fields[2], 8)
    length = _u(fields[3], 8)
    height = _u(fields[4], 4)
    digests = _parse_digests(fields[5])
    if count <= 0 or start + count >= 1 << 64:
        raise ValueError("invalid node leaf interval")
    if height != _expected_height(count):
        raise ValueError("invalid node height")
    if not (count - 1) * CHUNK + 1 <= length <= count * CHUNK:
        raise ValueError("invalid node byte length")
    return (start, count, length, height, digests)


def _parse_root(data: bytes):
    fields = _parse_record(data, ROOT_MAGIC, {1, 2, 3, 4})
    if fields[1] != profile_bytes():
        raise ValueError("unsupported root profile")
    length = _u(fields[2], 8)
    count = _u(fields[3], 8)
    digests = _parse_digests(fields[4])
    if (length == 0) != (count == 0):
        raise ValueError("invalid empty root accounting")
    if count and not (count - 1) * CHUNK + 1 <= length <= count * CHUNK:
        raise ValueError("invalid root byte length")
    return (length, count, digests)


def _leaf_length(root, index: int) -> int:
    length, count, _ = root
    if not 0 <= index < count:
        raise ValueError("leaf outside root")
    return CHUNK if index < count - 1 else length - index * CHUNK


def _span_length(root, start: int, count: int) -> int:
    length, leaf_count, _ = root
    if count <= 0 or start < 0 or start + count > leaf_count:
        raise ValueError("span outside root")
    if start + count < leaf_count:
        return count * CHUNK
    return length - start * CHUNK


def _split(count: int) -> int:
    if count <= 1:
        raise ValueError("cannot split singleton")
    return 1 << ((count - 1).bit_length() - 1)


def _inclusion_geometry(root, index: int):
    _, total, _ = root
    if total == 0 or not 0 <= index < total:
        raise ValueError("invalid inclusion target")

    def walk(start: int, count: int):
        if count == 1:
            return []
        left_count = _split(count)
        right_start = start + left_count
        right_count = count - left_count
        if index < right_start:
            values = walk(start, left_count)
            values.append((2, right_start, right_count, _span_length(root, right_start, right_count)))
            return values
        values = walk(right_start, right_count)
        values.append((1, start, left_count, _span_length(root, start, left_count)))
        return values

    return tuple(walk(0, total))


def _range_geometry(root, start: int, length: int):
    total_bytes, total_leaves, _ = root
    if total_leaves == 0 or length <= 0 or start < 0:
        raise ValueError("invalid range")
    end = start + length
    if end >= 1 << 64 or start >= total_bytes or end > total_bytes:
        raise ValueError("range outside root")
    first = start // CHUNK
    last = (end - 1) // CHUNK
    prefix = start - first * CHUNK
    suffix = _leaf_length(root, last) - (end - last * CHUNK)
    return first, last + 1, prefix, suffix


def _range_witness_geometry(root, first: int, last_exclusive: int):
    _, total, _ = root
    if not 0 <= first < last_exclusive <= total:
        raise ValueError("invalid target leaf span")
    result = []

    def walk(start: int, count: int):
        end = start + count
        if end <= first or start >= last_exclusive:
            result.append((start, count, _span_length(root, start, count)))
            return
        if count == 1:
            return
        left_count = _split(count)
        walk(start, left_count)
        walk(start + left_count, count - left_count)

    walk(0, total)
    return tuple(result)


def _parse_step(data: bytes):
    fields = _parse_record(data, STEP_MAGIC, {1, 2})
    side = _u(fields[1], 2)
    if side not in (1, 2):
        raise ValueError("invalid proof side")
    return side, _parse_node(fields[2])


def parse_inclusion(data: bytes):
    fields = _parse_record(data, INCLUSION_MAGIC, {1, 2, 3, 4, 5})
    if fields[1] != profile_bytes():
        raise ValueError("unsupported inclusion profile")
    root = _parse_root(fields[2])
    index = _u(fields[3], 8)
    leaf_length = _u(fields[4], 4)
    steps = tuple(_parse_step(item) for item in _parse_items(fields[5], MAX_INCLUSION_STEPS))
    expected = _inclusion_geometry(root, index)
    if leaf_length != _leaf_length(root, index) or len(steps) != len(expected):
        raise ValueError("non-canonical inclusion geometry")
    for (side, node), (expected_side, start, count, byte_length) in zip(steps, expected, strict=True):
        if side != expected_side:
            raise ValueError("non-canonical inclusion orientation")
        if node[:4] != (start, count, byte_length, _expected_height(count)):
            raise ValueError("non-canonical inclusion sibling geometry")
    return root, index, leaf_length, steps


def parse_range(data: bytes):
    fields = _parse_record(data, RANGE_MAGIC, {1, 2, 3, 4, 5, 6, 7})
    if fields[1] != profile_bytes():
        raise ValueError("unsupported range profile")
    root = _parse_root(fields[2])
    start = _u(fields[3], 8)
    length = _u(fields[4], 8)
    first, last, prefix_length, suffix_length = _range_geometry(root, start, length)
    prefix, suffix = fields[5], fields[6]
    if len(prefix) != prefix_length or len(suffix) != suffix_length:
        raise ValueError("non-canonical edge complements")
    witnesses = tuple(_parse_node(item) for item in _parse_items(fields[7], MAX_RANGE_WITNESSES))
    expected = _range_witness_geometry(root, first, last)
    if len(witnesses) != len(expected):
        raise ValueError("non-canonical witness cardinality")
    for node, (node_start, count, byte_length) in zip(witnesses, expected, strict=True):
        if node[:4] != (node_start, count, byte_length, _expected_height(count)):
            raise ValueError("non-canonical range witness geometry")
    return root, start, length, prefix, suffix, witnesses


def _root_matches(node, root) -> bool:
    length, count, digests = root
    return (
        node[0] == 0
        and node[1] == count
        and node[2] == length
        and hmac.compare_digest(b"".join(node[4]), b"".join(digests))
    )


def verify_inclusion_wire(leaf_bytes: bytes, proof_wire: bytes) -> bool:
    if not isinstance(leaf_bytes, bytes):
        raise TypeError("leaf_bytes must be bytes")
    root, index, leaf_length, steps = parse_inclusion(proof_wire)
    if len(leaf_bytes) != leaf_length:
        return False
    node = leaf(index, leaf_bytes)
    for side, sibling in steps:
        node = parent(sibling, node) if side == 1 else parent(node, sibling)
    return _root_matches(node, root)


def _reconstruct(start: int, count: int, components):
    existing = components.get((start, count))
    if existing is not None:
        return existing
    if count == 1:
        raise ValueError("missing target leaf")
    left_count = _split(count)
    return parent(
        _reconstruct(start, left_count, components),
        _reconstruct(start + left_count, count - left_count, components),
    )


def verify_range_wire(range_bytes: bytes, proof_wire: bytes) -> bool:
    if not isinstance(range_bytes, bytes):
        raise TypeError("range_bytes must be bytes")
    root, start, length, prefix, suffix, witnesses = parse_range(proof_wire)
    if len(range_bytes) != length:
        return False
    first, last, _, _ = _range_geometry(root, start, length)
    target = prefix + range_bytes + suffix
    target_end = last * CHUNK if last < root[1] else root[0]
    if len(target) != target_end - first * CHUNK:
        return False

    components = {(node[0], node[1]): node for node in witnesses}
    cursor = 0
    for index in range(first, last):
        width = _leaf_length(root, index)
        raw = target[cursor : cursor + width]
        if len(raw) != width:
            return False
        components[(index, 1)] = leaf(index, raw)
        cursor += width
    if cursor != len(target):
        return False

    node = _reconstruct(0, root[1], components)
    return _root_matches(node, root)
