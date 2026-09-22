"""Inclusion and byte-range proofs for Sigma Tree V1."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from .codec import TreeDecodeError, decode_items, decode_uint, encode_items, parse_record, record, u16, u32, u64
from .core import _leaf_node_buffer, combine_nodes, empty_root, leaf_node
from .ids import (
    MAX_INCLUSION_STEPS,
    MAX_RANGE_WITNESS_NODES,
    TREE_INCLUSION_PROOF_MAGIC,
    TREE_PROOF_STEP_MAGIC,
    TREE_RANGE_PROOF_MAGIC,
    ProofSide,
)
from .model import DEFAULT_PROFILE, TreeNode, TreeProfileV1, TreeRoot


def _largest_power_strictly_less(count: int) -> int:
    if count <= 1:
        raise ValueError("canonical split requires count > 1")
    return 1 << ((count - 1).bit_length() - 1)


def _leaf_byte_length(root: TreeRoot, index: int) -> int:
    if not 0 <= index < root.leaf_count:
        raise ValueError("leaf index is outside the TreeRoot")
    if index < root.leaf_count - 1:
        return root.profile.chunk_size
    return root.byte_length - index * root.profile.chunk_size


def _span_byte_length(root: TreeRoot, start_leaf: int, leaf_count: int) -> int:
    if leaf_count <= 0 or start_leaf < 0 or start_leaf + leaf_count > root.leaf_count:
        raise ValueError("tree span is outside the TreeRoot")
    if start_leaf + leaf_count < root.leaf_count:
        return leaf_count * root.profile.chunk_size
    return root.byte_length - start_leaf * root.profile.chunk_size


def _expected_height(leaf_count: int) -> int:
    if leaf_count <= 0:
        raise ValueError("leaf_count must be positive")
    return (leaf_count - 1).bit_length()


@dataclass(frozen=True)
class InclusionStepV1:
    side: ProofSide
    sibling: TreeNode

    def __post_init__(self) -> None:
        if not isinstance(self.side, ProofSide):
            raise TypeError("proof side must be ProofSide")
        if not isinstance(self.sibling, TreeNode):
            raise TypeError("proof sibling must be TreeNode")

    def to_bytes(self) -> bytes:
        return record(
            TREE_PROOF_STEP_MAGIC,
            (
                (1, u16(int(self.side))),
                (2, self.sibling.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "InclusionStepV1":
        fields = parse_record(
            data,
            magic=TREE_PROOF_STEP_MAGIC,
            allowed=frozenset({1, 2}),
        )
        try:
            return cls(
                ProofSide(decode_uint(fields[1], 2)),
                TreeNode.from_bytes(fields[2]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid inclusion proof step: {exc}") from exc


def inclusion_geometry(
    root: TreeRoot,
    leaf_index: int,
) -> tuple[tuple[ProofSide, int, int, int], ...]:
    """Canonical leaf-to-root sibling geometry without hashing."""
    if not isinstance(root, TreeRoot):
        raise TypeError("root must be TreeRoot")
    if root.leaf_count == 0:
        raise ValueError("empty tree has no inclusion proofs")
    if isinstance(leaf_index, bool) or not isinstance(leaf_index, int):
        raise TypeError("leaf_index must be int")
    if not 0 <= leaf_index < root.leaf_count:
        raise ValueError("leaf index is outside the TreeRoot")

    def walk(start: int, count: int) -> list[tuple[ProofSide, int, int, int]]:
        if count == 1:
            return []
        left_count = _largest_power_strictly_less(count)
        right_start = start + left_count
        right_count = count - left_count
        if leaf_index < right_start:
            values = walk(start, left_count)
            values.append(
                (
                    ProofSide.RIGHT,
                    right_start,
                    right_count,
                    _span_byte_length(root, right_start, right_count),
                )
            )
            return values
        values = walk(right_start, right_count)
        values.append(
            (
                ProofSide.LEFT,
                start,
                left_count,
                _span_byte_length(root, start, left_count),
            )
        )
        return values

    return tuple(walk(0, root.leaf_count))


@dataclass(frozen=True)
class InclusionProofV1:
    profile: TreeProfileV1
    root: TreeRoot
    leaf_index: int
    leaf_byte_length: int
    steps: tuple[InclusionStepV1, ...] = ()

    def __post_init__(self) -> None:
        if self.profile != DEFAULT_PROFILE or self.root.profile != self.profile:
            raise ValueError("inclusion proof profile/root profile mismatch")
        if self.root.leaf_count == 0:
            raise ValueError("empty tree has no inclusion proof")
        if isinstance(self.leaf_index, bool) or not isinstance(self.leaf_index, int):
            raise TypeError("leaf_index must be int")
        if not 0 <= self.leaf_index < self.root.leaf_count:
            raise ValueError("leaf index is outside the TreeRoot")
        if isinstance(self.leaf_byte_length, bool) or not isinstance(self.leaf_byte_length, int):
            raise TypeError("leaf_byte_length must be int")
        expected_leaf_length = _leaf_byte_length(self.root, self.leaf_index)
        if self.leaf_byte_length != expected_leaf_length:
            raise ValueError("proof leaf length does not match TreeRoot geometry")
        if not isinstance(self.steps, tuple) or not all(
            isinstance(step, InclusionStepV1) for step in self.steps
        ):
            raise TypeError("inclusion proof steps must be an immutable tuple")
        if len(self.steps) > MAX_INCLUSION_STEPS:
            raise ValueError("inclusion proof has too many steps")

        expected = inclusion_geometry(self.root, self.leaf_index)
        if len(self.steps) != len(expected):
            raise ValueError("inclusion proof path length is not canonical")
        for step, (side, start, count, byte_length) in zip(self.steps, expected, strict=True):
            sibling = step.sibling
            if step.side is not side:
                raise ValueError("inclusion proof sibling orientation is non-canonical")
            if (
                sibling.start_leaf != start
                or sibling.leaf_count != count
                or sibling.byte_length != byte_length
                or sibling.height != _expected_height(count)
            ):
                raise ValueError("inclusion proof sibling geometry is non-canonical")

    def to_bytes(self) -> bytes:
        return record(
            TREE_INCLUSION_PROOF_MAGIC,
            (
                (1, self.profile.to_bytes()),
                (2, self.root.to_bytes()),
                (3, u64(self.leaf_index)),
                (4, u32(self.leaf_byte_length)),
                (
                    5,
                    encode_items(
                        (step.to_bytes() for step in self.steps),
                        max_items=MAX_INCLUSION_STEPS,
                    ),
                ),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "InclusionProofV1":
        fields = parse_record(
            data,
            magic=TREE_INCLUSION_PROOF_MAGIC,
            allowed=frozenset({1, 2, 3, 4, 5}),
        )
        try:
            profile = TreeProfileV1.from_bytes(fields[1])
            root = TreeRoot.from_bytes(fields[2])
            steps = tuple(
                InclusionStepV1.from_bytes(item)
                for item in decode_items(fields[5], max_items=MAX_INCLUSION_STEPS)
            )
            return cls(
                profile,
                root,
                decode_uint(fields[3], 8),
                decode_uint(fields[4], 4),
                steps,
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid inclusion proof: {exc}") from exc


def range_witness_geometry(
    root: TreeRoot,
    first_leaf: int,
    last_leaf_exclusive: int,
) -> tuple[tuple[int, int, int], ...]:
    """Unique maximal canonical subtrees covering leaves outside the target span."""
    if not isinstance(root, TreeRoot):
        raise TypeError("root must be TreeRoot")
    if root.leaf_count == 0:
        raise ValueError("empty tree has no range proofs")
    if not (0 <= first_leaf < last_leaf_exclusive <= root.leaf_count):
        raise ValueError("target leaf span is outside the TreeRoot")

    result: list[tuple[int, int, int]] = []

    def walk(start: int, count: int) -> None:
        end = start + count
        if end <= first_leaf or start >= last_leaf_exclusive:
            result.append((start, count, _span_byte_length(root, start, count)))
            return
        if count == 1:
            return
        left_count = _largest_power_strictly_less(count)
        walk(start, left_count)
        walk(start + left_count, count - left_count)

    walk(0, root.leaf_count)
    return tuple(result)


def _validate_raw_range(total_bytes: int, start: int, length: int) -> None:
    if isinstance(total_bytes, bool) or not isinstance(total_bytes, int) or total_bytes < 0:
        raise TypeError("total_bytes must be a non-negative int")
    for name, value in (("start", start), ("length", length)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"range {name} must be int")
        if value < 0 or value >= 1 << 64:
            raise ValueError(f"range {name} is outside u64")
    if length == 0:
        raise ValueError("range length must be positive")
    end = start + length
    if end >= 1 << 64:
        raise ValueError("range end exceeds u64")
    if start >= total_bytes or end > total_bytes:
        raise ValueError("range is outside source byte bounds")


def _range_geometry(root: TreeRoot, start: int, length: int) -> tuple[int, int, int, int]:
    if not isinstance(root, TreeRoot):
        raise TypeError("root must be TreeRoot")
    if root.leaf_count == 0:
        raise ValueError("empty tree has no non-empty byte ranges")
    for name, value in (("start", start), ("length", length)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"range {name} must be int")
        if value < 0 or value >= 1 << 64:
            raise ValueError(f"range {name} is outside u64")
    if length == 0:
        raise ValueError("range length must be positive")
    end = start + length
    if end >= 1 << 64:
        raise ValueError("range end exceeds u64")
    if start >= root.byte_length or end > root.byte_length:
        raise ValueError("range is outside TreeRoot byte bounds")

    first_leaf = start // root.profile.chunk_size
    last_leaf = (end - 1) // root.profile.chunk_size
    prefix_length = start - first_leaf * root.profile.chunk_size
    last_leaf_length = _leaf_byte_length(root, last_leaf)
    suffix_length = last_leaf_length - (end - last_leaf * root.profile.chunk_size)
    return first_leaf, last_leaf + 1, prefix_length, suffix_length


@dataclass(frozen=True)
class RangeProofV1:
    profile: TreeProfileV1
    root: TreeRoot
    start: int
    length: int
    prefix: bytes = b""
    suffix: bytes = b""
    witnesses: tuple[TreeNode, ...] = ()

    def __post_init__(self) -> None:
        if self.profile != DEFAULT_PROFILE or self.root.profile != self.profile:
            raise ValueError("range proof profile/root profile mismatch")
        first_leaf, last_leaf_exclusive, prefix_length, suffix_length = _range_geometry(
            self.root, self.start, self.length
        )
        if not isinstance(self.prefix, bytes) or not isinstance(self.suffix, bytes):
            raise TypeError("range edge complements must be bytes")
        if len(self.prefix) != prefix_length:
            raise ValueError("range proof prefix length is not canonical")
        if len(self.suffix) != suffix_length:
            raise ValueError("range proof suffix length is not canonical")
        if not isinstance(self.witnesses, tuple) or not all(
            isinstance(node, TreeNode) for node in self.witnesses
        ):
            raise TypeError("range witnesses must be an immutable tuple of TreeNode values")
        if len(self.witnesses) > MAX_RANGE_WITNESS_NODES:
            raise ValueError("range proof has too many witness nodes")

        expected = range_witness_geometry(self.root, first_leaf, last_leaf_exclusive)
        if len(self.witnesses) != len(expected):
            raise ValueError("range witness cover cardinality is non-canonical")
        for node, (start, count, byte_length) in zip(
            self.witnesses, expected, strict=True
        ):
            if (
                node.start_leaf != start
                or node.leaf_count != count
                or node.byte_length != byte_length
                or node.height != _expected_height(count)
            ):
                raise ValueError("range witness geometry is non-canonical")

    def to_bytes(self) -> bytes:
        return record(
            TREE_RANGE_PROOF_MAGIC,
            (
                (1, self.profile.to_bytes()),
                (2, self.root.to_bytes()),
                (3, u64(self.start)),
                (4, u64(self.length)),
                (5, self.prefix),
                (6, self.suffix),
                (
                    7,
                    encode_items(
                        (node.to_bytes() for node in self.witnesses),
                        max_items=MAX_RANGE_WITNESS_NODES,
                    ),
                ),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "RangeProofV1":
        fields = parse_record(
            data,
            magic=TREE_RANGE_PROOF_MAGIC,
            allowed=frozenset({1, 2, 3, 4, 5, 6, 7}),
        )
        try:
            profile = TreeProfileV1.from_bytes(fields[1])
            root = TreeRoot.from_bytes(fields[2])
            witnesses = tuple(
                TreeNode.from_bytes(item)
                for item in decode_items(
                    fields[7], max_items=MAX_RANGE_WITNESS_NODES
                )
            )
            return cls(
                profile,
                root,
                decode_uint(fields[3], 8),
                decode_uint(fields[4], 8),
                fields[5],
                fields[6],
                witnesses,
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, TreeDecodeError):
                raise
            raise TreeDecodeError(f"invalid range proof: {exc}") from exc


@dataclass
class TreeProofIndex:
    """Ephemeral proof-generation index; never part of Sigma Tree V1 identity."""

    data: bytes
    profile: TreeProfileV1 = DEFAULT_PROFILE
    _leaves: tuple[memoryview, ...] = field(init=False, repr=False)
    _leaf_nodes: tuple[TreeNode, ...] = field(init=False, repr=False)
    _nodes: dict[tuple[int, int], TreeNode] = field(init=False, repr=False)
    root: TreeRoot = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("proof index data must be bytes")
        if self.profile != DEFAULT_PROFILE:
            raise ValueError("unsupported proof index profile")
        view = memoryview(self.data)
        leaves = tuple(
            view[offset : offset + self.profile.chunk_size]
            for offset in range(0, len(self.data), self.profile.chunk_size)
        )
        self._leaves = leaves
        self._leaf_nodes = tuple(
            _leaf_node_buffer(
                self.profile,
                index,
                index * self.profile.chunk_size,
                raw,
            )
            for index, raw in enumerate(leaves)
        )
        self._nodes = {}
        if not leaves:
            self.root = empty_root(self.profile)
            return
        node = self._node(0, len(leaves))
        self.root = TreeRoot(
            self.profile,
            len(self.data),
            len(leaves),
            node.digests,
        )

    def _node(self, start: int, count: int) -> TreeNode:
        key = (start, count)
        cached = self._nodes.get(key)
        if cached is not None:
            return cached
        if count == 1:
            node = self._leaf_nodes[start]
        else:
            left_count = _largest_power_strictly_less(count)
            node = combine_nodes(
                self.profile,
                self._node(start, left_count),
                self._node(start + left_count, count - left_count),
            )
        self._nodes[key] = node
        return node

    def prove_leaf(self, leaf_index: int) -> InclusionProofV1:
        geometry = inclusion_geometry(self.root, leaf_index)
        steps = tuple(
            InclusionStepV1(side, self._node(start, count))
            for side, start, count, _ in geometry
        )
        return InclusionProofV1(
            self.profile,
            self.root,
            leaf_index,
            _leaf_byte_length(self.root, leaf_index),
            steps,
        )

    def prove_range(self, start: int, length: int) -> RangeProofV1:
        first_leaf, last_leaf_exclusive, prefix_length, suffix_length = _range_geometry(
            self.root, start, length
        )
        end = start + length
        first_leaf_start = first_leaf * self.profile.chunk_size
        last_leaf = last_leaf_exclusive - 1
        last_leaf_end = last_leaf * self.profile.chunk_size + _leaf_byte_length(
            self.root, last_leaf
        )
        prefix = self.data[first_leaf_start:start] if prefix_length else b""
        suffix = self.data[end:last_leaf_end] if suffix_length else b""
        witnesses = tuple(
            self._node(witness_start, witness_count)
            for witness_start, witness_count, _ in range_witness_geometry(
                self.root, first_leaf, last_leaf_exclusive
            )
        )
        return RangeProofV1(
            self.profile,
            self.root,
            start,
            length,
            prefix,
            suffix,
            witnesses,
        )


def _streaming_geometry_root(
    data: bytes,
    profile: TreeProfileV1 = DEFAULT_PROFILE,
) -> TreeRoot:
    if not isinstance(data, bytes):
        raise TypeError("streaming proof source must be bytes")
    if profile != DEFAULT_PROFILE:
        raise ValueError("unsupported streaming proof profile")
    if not data:
        raise ValueError("empty tree has no selective proofs")
    leaf_count = (len(data) + profile.chunk_size - 1) // profile.chunk_size
    return TreeRoot(
        profile,
        len(data),
        leaf_count,
        (b"\x00" * 64,) * len(profile.algorithms),
    )


def _subtree_node_from_view(
    view: memoryview,
    profile: TreeProfileV1,
    start: int,
    count: int,
    total_leaf_count: int,
    total_bytes: int,
) -> TreeNode:
    if count == 1:
        leaf_start = start * profile.chunk_size
        leaf_end = min(leaf_start + profile.chunk_size, total_bytes)
        return _leaf_node_buffer(
            profile,
            start,
            leaf_start,
            view[leaf_start:leaf_end],
        )
    left_count = _largest_power_strictly_less(count)
    return combine_nodes(
        profile,
        _subtree_node_from_view(
            view,
            profile,
            start,
            left_count,
            total_leaf_count,
            total_bytes,
        ),
        _subtree_node_from_view(
            view,
            profile,
            start + left_count,
            count - left_count,
            total_leaf_count,
            total_bytes,
        ),
    )


def prove_leaf_streaming(data: bytes, leaf_index: int) -> InclusionProofV1:
    """Generate an inclusion proof with O(log N) auxiliary memory and no full index."""
    geometry_root = _streaming_geometry_root(data)
    geometry = inclusion_geometry(geometry_root, leaf_index)
    view = memoryview(data)
    steps = tuple(
        InclusionStepV1(
            side,
            _subtree_node_from_view(
                view,
                DEFAULT_PROFILE,
                start,
                count,
                geometry_root.leaf_count,
                geometry_root.byte_length,
            ),
        )
        for side, start, count, _ in geometry
    )
    leaf_start = leaf_index * DEFAULT_PROFILE.chunk_size
    leaf_end = min(leaf_start + DEFAULT_PROFILE.chunk_size, len(data))
    node = _leaf_node_buffer(
        DEFAULT_PROFILE,
        leaf_index,
        leaf_start,
        view[leaf_start:leaf_end],
    )
    for step in steps:
        node = (
            combine_nodes(DEFAULT_PROFILE, step.sibling, node)
            if step.side is ProofSide.LEFT
            else combine_nodes(DEFAULT_PROFILE, node, step.sibling)
        )
    root = TreeRoot(
        DEFAULT_PROFILE,
        len(data),
        geometry_root.leaf_count,
        node.digests,
    )
    return InclusionProofV1(
        DEFAULT_PROFILE,
        root,
        leaf_index,
        leaf_end - leaf_start,
        steps,
    )


def prove_range_streaming(data: bytes, start: int, length: int) -> RangeProofV1:
    """Generate a range proof without retaining a full TreeProofIndex."""
    if not isinstance(data, bytes):
        raise TypeError("range proof source must be bytes")
    _validate_raw_range(len(data), start, length)
    geometry_root = _streaming_geometry_root(data)
    first_leaf, last_leaf_exclusive, prefix_length, suffix_length = _range_geometry(
        geometry_root,
        start,
        length,
    )
    view = memoryview(data)
    witnesses = tuple(
        _subtree_node_from_view(
            view,
            DEFAULT_PROFILE,
            witness_start,
            witness_count,
            geometry_root.leaf_count,
            geometry_root.byte_length,
        )
        for witness_start, witness_count, _ in range_witness_geometry(
            geometry_root,
            first_leaf,
            last_leaf_exclusive,
        )
    )
    components: dict[tuple[int, int], TreeNode] = {
        (node.start_leaf, node.leaf_count): node for node in witnesses
    }
    for leaf_index in range(first_leaf, last_leaf_exclusive):
        leaf_start = leaf_index * DEFAULT_PROFILE.chunk_size
        leaf_end = min(leaf_start + DEFAULT_PROFILE.chunk_size, len(data))
        components[(leaf_index, 1)] = _leaf_node_buffer(
            DEFAULT_PROFILE,
            leaf_index,
            leaf_start,
            view[leaf_start:leaf_end],
        )

    node = _reconstruct_from_components(
        DEFAULT_PROFILE,
        0,
        geometry_root.leaf_count,
        components,
    )
    root = TreeRoot(
        DEFAULT_PROFILE,
        len(data),
        geometry_root.leaf_count,
        node.digests,
    )
    end = start + length
    first_leaf_start = first_leaf * DEFAULT_PROFILE.chunk_size
    last_leaf = last_leaf_exclusive - 1
    last_leaf_end = min(
        last_leaf * DEFAULT_PROFILE.chunk_size + DEFAULT_PROFILE.chunk_size,
        len(data),
    )
    prefix = data[first_leaf_start:start] if prefix_length else b""
    suffix = data[end:last_leaf_end] if suffix_length else b""
    return RangeProofV1(
        DEFAULT_PROFILE,
        root,
        start,
        length,
        prefix,
        suffix,
        witnesses,
    )


def prove_leaf(data: bytes, leaf_index: int) -> InclusionProofV1:
    return TreeProofIndex(data).prove_leaf(leaf_index)


def prove_range(data: bytes, start: int, length: int) -> RangeProofV1:
    if not isinstance(data, bytes):
        raise TypeError("range proof source must be bytes")
    _validate_raw_range(len(data), start, length)
    return TreeProofIndex(data).prove_range(start, length)


def verify_inclusion(leaf: bytes, proof: InclusionProofV1) -> bool:
    if not isinstance(leaf, bytes):
        raise TypeError("inclusion leaf must be bytes")
    if not isinstance(proof, InclusionProofV1):
        raise TypeError("proof must be InclusionProofV1")
    if len(leaf) != proof.leaf_byte_length:
        return False

    node = leaf_node(
        proof.profile,
        proof.leaf_index,
        proof.leaf_index * proof.profile.chunk_size,
        leaf,
    )
    for step in proof.steps:
        node = (
            combine_nodes(proof.profile, step.sibling, node)
            if step.side is ProofSide.LEFT
            else combine_nodes(proof.profile, node, step.sibling)
        )
    reconstructed = TreeRoot(
        proof.profile,
        node.byte_length,
        node.leaf_count,
        node.digests,
    )
    return hmac.compare_digest(reconstructed.to_bytes(), proof.root.to_bytes())


def _reconstruct_from_components(
    profile: TreeProfileV1,
    start: int,
    count: int,
    components: dict[tuple[int, int], TreeNode],
) -> TreeNode:
    existing = components.get((start, count))
    if existing is not None:
        return existing
    if count == 1:
        raise ValueError("range proof is missing a target leaf component")
    left_count = _largest_power_strictly_less(count)
    left = _reconstruct_from_components(profile, start, left_count, components)
    right = _reconstruct_from_components(
        profile, start + left_count, count - left_count, components
    )
    return combine_nodes(profile, left, right)


def verify_range(range_bytes: bytes, proof: RangeProofV1) -> bool:
    """Verify an exact byte interval using only range bytes plus proof evidence."""
    if not isinstance(range_bytes, bytes):
        raise TypeError("range_bytes must be bytes")
    if not isinstance(proof, RangeProofV1):
        raise TypeError("proof must be RangeProofV1")
    if len(range_bytes) != proof.length:
        return False

    # All bounds/cover checks happen in RangeProofV1 before any leaf hashing.
    first_leaf, last_leaf_exclusive, _, _ = _range_geometry(
        proof.root, proof.start, proof.length
    )
    target_bytes = proof.prefix + range_bytes + proof.suffix
    expected_target_bytes = (
        last_leaf_exclusive * proof.profile.chunk_size
        if last_leaf_exclusive < proof.root.leaf_count
        else proof.root.byte_length
    ) - first_leaf * proof.profile.chunk_size
    if len(target_bytes) != expected_target_bytes:
        return False

    components: dict[tuple[int, int], TreeNode] = {
        (node.start_leaf, node.leaf_count): node for node in proof.witnesses
    }
    cursor = 0
    for leaf_index in range(first_leaf, last_leaf_exclusive):
        leaf_length = _leaf_byte_length(proof.root, leaf_index)
        raw = target_bytes[cursor : cursor + leaf_length]
        if len(raw) != leaf_length:
            return False
        components[(leaf_index, 1)] = leaf_node(
            proof.profile,
            leaf_index,
            leaf_index * proof.profile.chunk_size,
            raw,
        )
        cursor += leaf_length
    if cursor != len(target_bytes):
        return False

    node = _reconstruct_from_components(
        proof.profile,
        0,
        proof.root.leaf_count,
        components,
    )
    reconstructed = TreeRoot(
        proof.profile,
        node.byte_length,
        node.leaf_count,
        node.digests,
    )
    return hmac.compare_digest(reconstructed.to_bytes(), proof.root.to_bytes())
