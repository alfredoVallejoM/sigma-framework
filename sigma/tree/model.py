"""Canonical Sigma Tree V1 data model and wire records."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import TreeDecodeError, decode_items, decode_uint, encode_items, parse_record, record, u16, u32, u64
from .ids import (
    DEFAULT_TREE_ALGORITHMS,
    DEFAULT_TREE_CHUNK_SIZE,
    MAX_TREE_FRONTIER_NODES,
    TREE_DIGEST_SIZE,
    TREE_FRONTIER_MAGIC,
    TREE_NODE_MAGIC,
    TREE_PROFILE_MAGIC,
    TREE_ROOT_MAGIC,
    TreeAlgorithmId,
    TreeProfileId,
)


@dataclass(frozen=True)
class TreeProfileV1:
    profile_id: TreeProfileId = TreeProfileId.CANONICAL_V1
    chunk_size: int = DEFAULT_TREE_CHUNK_SIZE
    algorithms: tuple[TreeAlgorithmId, ...] = DEFAULT_TREE_ALGORITHMS

    def __post_init__(self) -> None:
        if self.profile_id is not TreeProfileId.CANONICAL_V1:
            raise ValueError("unsupported Sigma Tree profile")
        if self.chunk_size != DEFAULT_TREE_CHUNK_SIZE:
            raise ValueError("Sigma Tree V1 fixes the canonical chunk size")
        if self.algorithms != DEFAULT_TREE_ALGORITHMS:
            raise ValueError("Sigma Tree V1 fixes the canonical algorithm order")

    def to_bytes(self) -> bytes:
        algorithms = u16(len(self.algorithms)) + b"".join(u16(int(a)) for a in self.algorithms)
        return record(
            TREE_PROFILE_MAGIC,
            ((1, u16(int(self.profile_id))), (2, u32(self.chunk_size)), (3, algorithms)),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TreeProfileV1":
        fields = parse_record(data, magic=TREE_PROFILE_MAGIC, allowed=frozenset({1, 2, 3}))
        try:
            profile_id = TreeProfileId(decode_uint(fields[1], 2))
        except ValueError as exc:
            raise TreeDecodeError("unknown Sigma Tree profile") from exc
        chunk_size = decode_uint(fields[2], 4)
        encoded = fields[3]
        if len(encoded) < 2:
            raise TreeDecodeError("truncated algorithm vector")
        count = decode_uint(encoded[:2], 2)
        if len(encoded) != 2 + 2 * count:
            raise TreeDecodeError("algorithm vector length mismatch")
        try:
            algorithms = tuple(
                TreeAlgorithmId(decode_uint(encoded[i : i + 2], 2))
                for i in range(2, len(encoded), 2)
            )
        except ValueError as exc:
            raise TreeDecodeError("unknown Sigma Tree algorithm") from exc
        try:
            return cls(profile_id, chunk_size, algorithms)
        except ValueError as exc:
            raise TreeDecodeError(f"invalid Sigma Tree profile: {exc}") from exc


DEFAULT_PROFILE = TreeProfileV1()


def validate_digests(digests: tuple[bytes, ...], profile: TreeProfileV1 = DEFAULT_PROFILE) -> None:
    if len(digests) != len(profile.algorithms):
        raise ValueError("digest vector does not match profile algorithm count")
    if any(not isinstance(d, bytes) or len(d) != TREE_DIGEST_SIZE for d in digests):
        raise ValueError("each Sigma Tree digest must be exactly 64 bytes")


@dataclass(frozen=True)
class TreeNode:
    start_leaf: int
    leaf_count: int
    byte_length: int
    height: int
    digests: tuple[bytes, ...]

    def __post_init__(self) -> None:
        for name, value in (("start_leaf", self.start_leaf), ("leaf_count", self.leaf_count), ("byte_length", self.byte_length), ("height", self.height)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.leaf_count <= 0:
            raise ValueError("TreeNode must contain at least one leaf")
        validate_digests(self.digests)

    @property
    def end_leaf(self) -> int:
        return self.start_leaf + self.leaf_count

    @property
    def is_perfect(self) -> bool:
        return self.leaf_count == (1 << self.height)

    def to_bytes(self) -> bytes:
        return record(TREE_NODE_MAGIC, ((1, u64(self.start_leaf)), (2, u64(self.leaf_count)), (3, u64(self.byte_length)), (4, u32(self.height)), (5, encode_items(self.digests, max_items=4))))

    @classmethod
    def from_bytes(cls, data: bytes) -> "TreeNode":
        fields = parse_record(data, magic=TREE_NODE_MAGIC, allowed=frozenset({1, 2, 3, 4, 5}))
        try:
            return cls(decode_uint(fields[1], 8), decode_uint(fields[2], 8), decode_uint(fields[3], 8), decode_uint(fields[4], 4), decode_items(fields[5], max_items=4))
        except ValueError as exc:
            raise TreeDecodeError(f"invalid Sigma Tree node: {exc}") from exc


@dataclass(frozen=True)
class TreeRoot:
    profile: TreeProfileV1
    byte_length: int
    leaf_count: int
    digests: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if self.profile != DEFAULT_PROFILE:
            raise ValueError("unsupported TreeRoot profile")
        if isinstance(self.byte_length, bool) or not isinstance(self.byte_length, int):
            raise TypeError("byte_length must be int")
        if isinstance(self.leaf_count, bool) or not isinstance(self.leaf_count, int):
            raise TypeError("leaf_count must be int")
        if not 0 <= self.byte_length < 1 << 64 or not 0 <= self.leaf_count < 1 << 64:
            raise ValueError("TreeRoot counters are outside u64 range")
        validate_digests(self.digests, self.profile)
        if (self.byte_length == 0) != (self.leaf_count == 0):
            raise ValueError("empty byte/root leaf accounting mismatch")

    def to_bytes(self) -> bytes:
        return record(TREE_ROOT_MAGIC, ((1, self.profile.to_bytes()), (2, u64(self.byte_length)), (3, u64(self.leaf_count)), (4, encode_items(self.digests, max_items=4))))

    @classmethod
    def from_bytes(cls, data: bytes) -> "TreeRoot":
        fields = parse_record(data, magic=TREE_ROOT_MAGIC, allowed=frozenset({1, 2, 3, 4}))
        profile = TreeProfileV1.from_bytes(fields[1])
        try:
            return cls(profile, decode_uint(fields[2], 8), decode_uint(fields[3], 8), decode_items(fields[4], max_items=4))
        except (TypeError, ValueError) as exc:
            raise TreeDecodeError(f"invalid Sigma Tree root: {exc}") from exc


def canonical_frontier_heights(leaf_count: int) -> tuple[int, ...]:
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        raise TypeError("leaf_count must be int")
    if not 0 <= leaf_count < 1 << 64:
        raise ValueError("leaf_count outside Sigma Tree range")
    return tuple(h for h in range(leaf_count.bit_length() - 1, -1, -1) if leaf_count & (1 << h))


@dataclass(frozen=True)
class TreeFrontier:
    """Canonical left-to-right frontier of perfect subtrees."""

    nodes: tuple[TreeNode, ...] = ()

    def __post_init__(self) -> None:
        if len(self.nodes) > MAX_TREE_FRONTIER_NODES:
            raise ValueError("frontier contains too many nodes")
        end = 0
        previous_height: int | None = None
        for node in self.nodes:
            if not node.is_perfect:
                raise ValueError("frontier nodes must be perfect subtrees")
            if node.start_leaf != end:
                raise ValueError("frontier nodes must be contiguous from leaf zero")
            if previous_height is not None and node.height >= previous_height:
                raise ValueError("frontier heights must be strictly decreasing")
            end = node.end_leaf
            previous_height = node.height
        if tuple(n.height for n in self.nodes) != canonical_frontier_heights(end):
            raise ValueError("frontier does not match the unique binary decomposition")

    @property
    def leaf_count(self) -> int:
        return sum(n.leaf_count for n in self.nodes)

    @property
    def byte_length(self) -> int:
        return sum(n.byte_length for n in self.nodes)

    def to_bytes(self) -> bytes:
        return record(TREE_FRONTIER_MAGIC, ((1, DEFAULT_PROFILE.to_bytes()), (2, encode_items((n.to_bytes() for n in self.nodes), max_items=MAX_TREE_FRONTIER_NODES))))

    @classmethod
    def from_bytes(cls, data: bytes) -> "TreeFrontier":
        fields = parse_record(data, magic=TREE_FRONTIER_MAGIC, allowed=frozenset({1, 2}))
        if TreeProfileV1.from_bytes(fields[1]) != DEFAULT_PROFILE:
            raise TreeDecodeError("frontier profile is unsupported")
        try:
            return cls(tuple(TreeNode.from_bytes(x) for x in decode_items(fields[2], max_items=MAX_TREE_FRONTIER_NODES)))
        except ValueError as exc:
            raise TreeDecodeError(f"invalid Sigma Tree frontier: {exc}") from exc
