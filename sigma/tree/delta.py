"""Incremental same-length replacement and append for Sigma Tree V1."""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass

from .core import combine_nodes, empty_root, leaf_node
from .model import DEFAULT_PROFILE, TreeFrontier, TreeNode, TreeProfileV1, TreeRoot


class RebuildRequired(ValueError):
    """Raised when an edit changes chunk boundaries and needs a full rebuild."""


@dataclass(frozen=True)
class TreeEditV1:
    start: int
    delete_length: int
    data: bytes

    def __post_init__(self) -> None:
        for name, value in (("start", self.start), ("delete_length", self.delete_length)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"edit {name} must be int")
            if value < 0 or value >= 1 << 64:
                raise ValueError(f"edit {name} is outside u64")
        if not isinstance(self.data, bytes):
            raise TypeError("edit data must be bytes")
        if self.start + self.delete_length >= 1 << 64:
            raise ValueError("edit interval exceeds u64")

    @property
    def end(self) -> int:
        return self.start + self.delete_length


@dataclass(frozen=True)
class TreeUpdateTelemetryV1:
    operation: str
    old_byte_length: int
    new_byte_length: int
    edit_bytes: int
    affected_leaves: tuple[int, ...]
    invalidated_nodes: tuple[tuple[int, int], ...]
    recomputed_nodes: tuple[tuple[int, int], ...]
    reused_nodes: tuple[tuple[int, int], ...]
    leaf_payload_bytes_rehashed: int
    branch_hash_invocations: int
    frontier_nodes_reused: int = 0

    @property
    def recomputed_leaf_count(self) -> int:
        return sum(1 for _, count in self.recomputed_nodes if count == 1)

    @property
    def recomputed_internal_node_count(self) -> int:
        return sum(1 for _, count in self.recomputed_nodes if count > 1)


@dataclass(frozen=True)
class TreeUpdateResultV1:
    root: TreeRoot
    telemetry: TreeUpdateTelemetryV1
    normalized_edits: tuple[TreeEditV1, ...] = ()


def normalize_tree_edits(
    edits: tuple[TreeEditV1, ...] | list[TreeEditV1],
    *,
    total_bytes: int,
) -> tuple[TreeEditV1, ...]:
    """Canonicalize supported same-length edits independent of input ordering."""
    if isinstance(total_bytes, bool) or not isinstance(total_bytes, int) or total_bytes < 0:
        raise TypeError("total_bytes must be a non-negative int")
    values = tuple(edits)
    if not all(isinstance(edit, TreeEditV1) for edit in values):
        raise TypeError("all delta edits must be TreeEditV1")

    supported: list[TreeEditV1] = []
    for edit in values:
        if edit.delete_length != len(edit.data):
            raise RebuildRequired(
                "interior insertion/deletion shifts chunk boundaries; full rebuild required"
            )
        if edit.delete_length == 0:
            continue
        if edit.end > total_bytes:
            raise ValueError("delta edit extends beyond current object")
        supported.append(edit)

    supported.sort(key=lambda edit: (edit.start, edit.end, edit.data))
    if not supported:
        return ()

    merged: list[TreeEditV1] = []
    current_start = supported[0].start
    current = bytearray(supported[0].data)
    current_end = supported[0].end

    for edit in supported[1:]:
        if edit.start > current_end:
            merged.append(TreeEditV1(current_start, len(current), bytes(current)))
            current_start = edit.start
            current = bytearray(edit.data)
            current_end = edit.end
            continue

        overlap_end = min(current_end, edit.end)
        if overlap_end > edit.start:
            left_offset = edit.start - current_start
            overlap = overlap_end - edit.start
            if bytes(current[left_offset : left_offset + overlap]) != edit.data[:overlap]:
                raise ValueError("overlapping delta edits disagree on replacement bytes")

        if edit.end > current_end:
            append_from = current_end - edit.start
            current.extend(edit.data[append_from:])
            current_end = edit.end

    merged.append(TreeEditV1(current_start, len(current), bytes(current)))
    return tuple(merged)


def _split(count: int) -> int:
    if count <= 1:
        raise ValueError("cannot split singleton subtree")
    return 1 << ((count - 1).bit_length() - 1)


def _is_canonical_key(start: int, count: int, total: int) -> bool:
    if count <= 0 or start < 0 or start + count > total or total <= 0:
        return False

    def descend(node_start: int, node_count: int) -> bool:
        if (node_start, node_count) == (start, count):
            return True
        if node_count == 1:
            return False
        left_count = _split(node_count)
        right_start = node_start + left_count
        if start >= right_start:
            return descend(right_start, node_count - left_count)
        if start + count <= right_start:
            return descend(node_start, left_count)
        return False

    return descend(0, total)


class TreeDeltaIndex:
    """Ephemeral mutable index for incremental Tree V1 updates.

    Initial index construction is O(B). Supported updates avoid materializing or
    rehashing the complete object; persistent index serialization belongs to ST5.
    """

    def __init__(self, data: bytes, profile: TreeProfileV1 = DEFAULT_PROFILE) -> None:
        if not isinstance(data, bytes):
            raise TypeError("delta index source must be bytes")
        if profile != DEFAULT_PROFILE:
            raise ValueError("unsupported Sigma Tree profile")
        self.profile = profile
        self._byte_length = len(data)
        self._leaves = [
            data[offset : offset + profile.chunk_size]
            for offset in range(0, len(data), profile.chunk_size)
        ]
        self._leaf_nodes: dict[int, TreeNode] = {
            index: leaf_node(profile, index, index * profile.chunk_size, raw)
            for index, raw in enumerate(self._leaves)
        }
        self._nodes: dict[tuple[int, int], TreeNode] = {}
        if not self._leaves:
            self.root = empty_root(profile)
        else:
            node = self._node(0, len(self._leaves))
            self.root = TreeRoot(profile, self._byte_length, len(self._leaves), node.digests)

    @property
    def byte_length(self) -> int:
        return self._byte_length

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    def leaf_bytes(self, index: int) -> bytes:
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("leaf index must be int")
        if not 0 <= index < len(self._leaves):
            raise IndexError("leaf index outside delta index")
        return self._leaves[index]

    def node(self, start: int, count: int) -> TreeNode:
        if not _is_canonical_key(start, count, len(self._leaves)):
            raise ValueError("requested span is not canonical in the current Tree")
        return self._nodes[(start, count)]

    def materialize(self) -> bytes:
        """Materialize current bytes for testing/export; this is intentionally O(B)."""
        return b"".join(self._leaves)

    def _node(self, start: int, count: int) -> TreeNode:
        key = (start, count)
        cached = self._nodes.get(key)
        if cached is not None:
            return cached
        if count == 1:
            node = self._leaf_nodes[start]
        else:
            left_count = _split(count)
            node = combine_nodes(
                self.profile,
                self._node(start, left_count),
                self._node(start + left_count, count - left_count),
            )
        self._nodes[key] = node
        return node

    def _ancestor_closure(self, affected_leaves: tuple[int, ...]) -> set[tuple[int, int]]:
        if not affected_leaves or not self._leaves:
            return set()
        ordered = tuple(sorted(set(affected_leaves)))
        closure: set[tuple[int, int]] = set()

        def intersects(start: int, count: int) -> bool:
            position = bisect_left(ordered, start)
            return position < len(ordered) and ordered[position] < start + count

        def walk(start: int, count: int) -> None:
            if not intersects(start, count):
                return
            closure.add((start, count))
            if count == 1:
                return
            left_count = _split(count)
            walk(start, left_count)
            walk(start + left_count, count - left_count)

        walk(0, len(self._leaves))
        return closure

    def _checkpoint_frontier(self) -> tuple[TreeFrontier, bytes]:
        full_count = self._byte_length // self.profile.chunk_size
        tail_length = self._byte_length % self.profile.chunk_size
        nodes: list[TreeNode] = []
        start = 0
        if full_count:
            for height in range(full_count.bit_length() - 1, -1, -1):
                if full_count & (1 << height):
                    count = 1 << height
                    key = (start, count)
                    node = self._nodes.get(key)
                    if node is None:
                        node = self._node(start, count)
                    nodes.append(node)
                    start += count
        tail = self._leaves[-1] if tail_length else b""
        return TreeFrontier(tuple(nodes)), tail

    def apply_delta(
        self,
        edits: tuple[TreeEditV1, ...] | list[TreeEditV1],
    ) -> TreeUpdateResultV1:
        normalized = normalize_tree_edits(edits, total_bytes=self._byte_length)
        if not normalized:
            telemetry = TreeUpdateTelemetryV1(
                "delta",
                self._byte_length,
                self._byte_length,
                0,
                (),
                (),
                (),
                (),
                0,
                0,
            )
            return TreeUpdateResultV1(self.root, telemetry, normalized)

        leaf_segments: dict[int, list[tuple[int, bytes]]] = {}
        for edit in normalized:
            position = edit.start
            while position < edit.end:
                leaf_index = position // self.profile.chunk_size
                leaf_start = leaf_index * self.profile.chunk_size
                leaf_end = leaf_start + len(self._leaves[leaf_index])
                end = min(edit.end, leaf_end)
                source_start = position - edit.start
                leaf_segments.setdefault(leaf_index, []).append(
                    (
                        position - leaf_start,
                        edit.data[source_start : source_start + (end - position)],
                    )
                )
                position = end

        affected_leaves = tuple(sorted(leaf_segments))
        closure = self._ancestor_closure(affected_leaves)

        updated_leaf_bytes: dict[int, bytes] = {}
        updated_leaf_nodes: dict[int, TreeNode] = {}
        for leaf_index in affected_leaves:
            raw = bytearray(self._leaves[leaf_index])
            leaf_start = leaf_index * self.profile.chunk_size
            for local_start, replacement in leaf_segments[leaf_index]:
                raw[local_start : local_start + len(replacement)] = replacement
            value = bytes(raw)
            updated_leaf_bytes[leaf_index] = value
            updated_leaf_nodes[leaf_index] = leaf_node(
                self.profile,
                leaf_index,
                leaf_start,
                value,
            )

        temp_nodes: dict[tuple[int, int], TreeNode] = {
            (index, 1): node for index, node in updated_leaf_nodes.items()
        }
        reused: set[tuple[int, int]] = set()

        def compute(start: int, count: int) -> TreeNode:
            key = (start, count)
            existing = temp_nodes.get(key)
            if existing is not None:
                return existing
            if key not in closure:
                reused.add(key)
                return self._nodes[key]
            left_count = _split(count)
            node = combine_nodes(
                self.profile,
                compute(start, left_count),
                compute(start + left_count, count - left_count),
            )
            temp_nodes[key] = node
            return node

        node = compute(0, len(self._leaves))
        new_root = TreeRoot(
            self.profile,
            self._byte_length,
            len(self._leaves),
            node.digests,
        )

        # Publish only after all hashing/composition has succeeded. Keep a
        # small rollback journal over exactly the touched state.
        old_leaf_bytes = {index: self._leaves[index] for index in affected_leaves}
        old_leaf_nodes = {index: self._leaf_nodes[index] for index in affected_leaves}
        touched_node_keys = set(closure) | set(temp_nodes)
        missing = object()
        old_nodes = {key: self._nodes.get(key, missing) for key in touched_node_keys}
        old_root = self.root
        try:
            for index, value in updated_leaf_bytes.items():
                self._leaves[index] = value
                self._leaf_nodes[index] = updated_leaf_nodes[index]
            for key in closure:
                self._nodes.pop(key, None)
            self._nodes.update(temp_nodes)
            self.root = new_root
        except Exception:
            for index, value in old_leaf_bytes.items():
                self._leaves[index] = value
                self._leaf_nodes[index] = old_leaf_nodes[index]
            for key, value in old_nodes.items():
                if value is missing:
                    self._nodes.pop(key, None)
                else:
                    self._nodes[key] = value
            self.root = old_root
            raise

        recomputed = tuple(sorted(temp_nodes))
        reused_nodes = tuple(sorted(reused))
        leaf_payload_bytes = sum(len(updated_leaf_bytes[index]) for index in affected_leaves)
        telemetry = TreeUpdateTelemetryV1(
            "delta",
            self._byte_length,
            self._byte_length,
            sum(len(edit.data) for edit in normalized),
            affected_leaves,
            tuple(sorted(closure)),
            recomputed,
            reused_nodes,
            leaf_payload_bytes,
            len(self.profile.algorithms) * len(recomputed),
        )
        return TreeUpdateResultV1(new_root, telemetry, normalized)

    def append(self, suffix: bytes) -> TreeUpdateResultV1:
        if not isinstance(suffix, bytes):
            raise TypeError("append suffix must be bytes")
        old_length = self._byte_length
        if not suffix:
            telemetry = TreeUpdateTelemetryV1(
                "append",
                old_length,
                old_length,
                0,
                (),
                (),
                (),
                (),
                0,
                0,
                len(self._checkpoint_frontier()[0].nodes),
            )
            return TreeUpdateResultV1(self.root, telemetry)

        if old_length + len(suffix) >= 1 << 64:
            raise ValueError("appended Sigma Tree exceeds u64 byte length")

        old_leaf_count = len(self._leaves)
        full_count = old_length // self.profile.chunk_size
        tail_length = old_length % self.profile.chunk_size
        old_tail = self._leaves[-1] if tail_length else b""
        frontier, _ = self._checkpoint_frontier()
        frontier_keys = {
            (node.start_leaf, node.leaf_count) for node in frontier.nodes
        }

        combined = old_tail + suffix
        new_chunks = [
            combined[offset : offset + self.profile.chunk_size]
            for offset in range(0, len(combined), self.profile.chunk_size)
        ]
        first_new_index = full_count
        new_leaf_bytes = {
            first_new_index + offset: raw for offset, raw in enumerate(new_chunks)
        }
        new_leaf_nodes = {
            index: leaf_node(
                self.profile,
                index,
                index * self.profile.chunk_size,
                raw,
            )
            for index, raw in new_leaf_bytes.items()
        }
        new_leaf_count = full_count + len(new_chunks)
        new_length = old_length + len(suffix)

        temp_nodes: dict[tuple[int, int], TreeNode] = {
            (index, 1): node for index, node in new_leaf_nodes.items()
        }
        reused: set[tuple[int, int]] = set()

        def can_reuse(start: int, count: int) -> bool:
            key = (start, count)
            if key not in self._nodes:
                return False
            if not _is_canonical_key(start, count, old_leaf_count):
                return False
            return start + count <= full_count

        def compute(start: int, count: int) -> TreeNode:
            key = (start, count)
            existing = temp_nodes.get(key)
            if existing is not None:
                return existing
            if can_reuse(start, count):
                reused.add(key)
                return self._nodes[key]
            if count == 1:
                if start < full_count:
                    # This leaf is unchanged but may not be a canonical cached key
                    # under the previous whole-tree shape.
                    reused.add(key)
                    return self._leaf_nodes[start]
                raise RuntimeError("append leaf state is incomplete")
            left_count = _split(count)
            node = combine_nodes(
                self.profile,
                compute(start, left_count),
                compute(start + left_count, count - left_count),
            )
            temp_nodes[key] = node
            return node

        node = compute(0, new_leaf_count)
        new_root = TreeRoot(
            self.profile,
            new_length,
            new_leaf_count,
            node.digests,
        )

        invalidated: set[tuple[int, int]] = set()
        affected_existing: tuple[int, ...] = ()
        if tail_length:
            affected_existing = (full_count,)
            invalidated = self._ancestor_closure(affected_existing)

        # Publish after the complete new root has been computed, with a
        # rollback journal limited to the changed tail/new leaves and bridge nodes.
        old_list_length = len(self._leaves)
        old_tail_value = self._leaves[full_count] if tail_length else None
        affected_leaf_node_keys = set(new_leaf_nodes)
        missing = object()
        old_leaf_node_values = {
            key: self._leaf_nodes.get(key, missing) for key in affected_leaf_node_keys
        }
        touched_node_keys = set(invalidated) | set(temp_nodes)
        old_node_values = {
            key: self._nodes.get(key, missing) for key in touched_node_keys
        }
        old_root = self.root
        try:
            if tail_length:
                self._leaves[full_count] = new_chunks[0]
                append_from = 1
            else:
                append_from = 0
            self._leaves.extend(new_chunks[append_from:])

            for index, node_value in new_leaf_nodes.items():
                self._leaf_nodes[index] = node_value
            for key in invalidated:
                self._nodes.pop(key, None)
            self._nodes.update(temp_nodes)
            self._byte_length = new_length
            self.root = new_root
        except Exception:
            del self._leaves[old_list_length:]
            if tail_length and old_tail_value is not None:
                self._leaves[full_count] = old_tail_value
            for key, value in old_leaf_node_values.items():
                if value is missing:
                    self._leaf_nodes.pop(key, None)
                else:
                    self._leaf_nodes[key] = value
            for key, value in old_node_values.items():
                if value is missing:
                    self._nodes.pop(key, None)
                else:
                    self._nodes[key] = value
            self._byte_length = old_length
            self.root = old_root
            raise

        recomputed = tuple(sorted(temp_nodes))
        reused_nodes = tuple(sorted(reused))
        payload_rehashed = sum(len(raw) for raw in new_leaf_bytes.values())
        telemetry = TreeUpdateTelemetryV1(
            "append",
            old_length,
            new_length,
            len(suffix),
            tuple(sorted(new_leaf_bytes)),
            tuple(sorted(invalidated)),
            recomputed,
            reused_nodes,
            payload_rehashed,
            len(self.profile.algorithms) * len(recomputed),
            len(frontier_keys & reused),
        )
        return TreeUpdateResultV1(new_root, telemetry)
