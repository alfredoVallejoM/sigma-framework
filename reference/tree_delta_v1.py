"""Independent stdlib-only reference semantics for Sigma Tree V1 ST4."""

from __future__ import annotations

from reference.tree_v1 import CHUNK, root_wire


class ReferenceRebuildRequired(ValueError):
    pass


def normalize_edits(edits, total_bytes: int):
    values = []
    for start, delete_length, replacement in edits:
        if not isinstance(start, int) or isinstance(start, bool) or start < 0:
            raise ValueError("invalid edit start")
        if not isinstance(delete_length, int) or isinstance(delete_length, bool) or delete_length < 0:
            raise ValueError("invalid edit delete length")
        if not isinstance(replacement, bytes):
            raise TypeError("replacement must be bytes")
        if delete_length != len(replacement):
            raise ReferenceRebuildRequired("boundary-shifting edit")
        if delete_length == 0:
            continue
        end = start + delete_length
        if end > total_bytes:
            raise ValueError("edit outside source")
        values.append((start, end, replacement))

    values.sort(key=lambda item: (item[0], item[1], item[2]))
    if not values:
        return ()

    out = []
    current_start, current_end, current_data = values[0][0], values[0][1], bytearray(values[0][2])
    for start, end, replacement in values[1:]:
        if start > current_end:
            out.append((current_start, current_end - current_start, bytes(current_data)))
            current_start, current_end, current_data = start, end, bytearray(replacement)
            continue
        overlap_end = min(current_end, end)
        if overlap_end > start:
            left = start - current_start
            width = overlap_end - start
            if bytes(current_data[left : left + width]) != replacement[:width]:
                raise ValueError("conflicting overlapping edits")
        if end > current_end:
            current_data.extend(replacement[current_end - start :])
            current_end = end
    out.append((current_start, current_end - current_start, bytes(current_data)))
    return tuple(out)


def apply_same_length(data: bytes, edits) -> bytes:
    normalized = normalize_edits(edits, len(data))
    result = bytearray(data)
    for start, delete_length, replacement in normalized:
        result[start : start + delete_length] = replacement
    return bytes(result)


def delta_root_wire(data: bytes, edits) -> bytes:
    return root_wire(apply_same_length(data, edits))


def append_root_wire(data: bytes, suffix: bytes) -> bytes:
    if not isinstance(suffix, bytes):
        raise TypeError("suffix must be bytes")
    return root_wire(data + suffix)


def affected_leaves(edits, total_bytes: int):
    normalized = normalize_edits(edits, total_bytes)
    result = set()
    for start, delete_length, _ in normalized:
        first = start // CHUNK
        last = (start + delete_length - 1) // CHUNK
        result.update(range(first, last + 1))
    return tuple(sorted(result))


def ancestor_closure(leaf_count: int, leaves):
    targets = set(leaves)
    out = set()

    def split(count: int) -> int:
        return 1 << ((count - 1).bit_length() - 1)

    def walk(start: int, count: int):
        if not any(start <= leaf < start + count for leaf in targets):
            return
        out.add((start, count))
        if count == 1:
            return
        left = split(count)
        walk(start, left)
        walk(start + left, count - left)

    if leaf_count and targets:
        walk(0, leaf_count)
    return tuple(sorted(out))
