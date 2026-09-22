"""Single semantic authority for Sigma Tree V1 construction."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from .codec import domain_tag, record, u16, u32, u64
from .ids import TREE_DIGEST_SIZE, TreeAlgorithmId, TreeDomainId
from .model import DEFAULT_PROFILE, TreeFrontier, TreeNode, TreeProfileV1, TreeRoot, validate_digests


def _hash(algorithm: TreeAlgorithmId, payload: bytes) -> bytes:
    if algorithm is TreeAlgorithmId.SHA512:
        return hashlib.sha512(payload).digest()
    if algorithm is TreeAlgorithmId.SHA3_512:
        return hashlib.sha3_512(payload).digest()
    if algorithm is TreeAlgorithmId.BLAKE2B_512:
        return hashlib.blake2b(payload, digest_size=TREE_DIGEST_SIZE).digest()
    if algorithm is TreeAlgorithmId.SHAKE256_512:
        return hashlib.shake_256(payload).digest(TREE_DIGEST_SIZE)
    raise ValueError("unsupported Sigma Tree algorithm")  # pragma: no cover


def leaf_node(profile: TreeProfileV1, index: int, offset: int, leaf: bytes) -> TreeNode:
    if not isinstance(leaf, bytes):
        raise TypeError("leaf must be bytes")
    if not 1 <= len(leaf) <= profile.chunk_size:
        raise ValueError("leaf length is outside profile bounds")
    if offset != index * profile.chunk_size:
        raise ValueError("canonical leaf offset does not match its index")
    frame = record(b"SIGTLEAF", ((1, profile.to_bytes()), (2, u64(index)), (3, u64(offset)), (4, u32(len(leaf))), (5, leaf)))
    return TreeNode(index, 1, len(leaf), 0, tuple(_hash(a, domain_tag(TreeDomainId.LEAF) + frame) for a in profile.algorithms))


def combine_nodes(profile: TreeProfileV1, left: TreeNode, right: TreeNode, *, require_equal_perfect: bool = False) -> TreeNode:
    if left.end_leaf != right.start_leaf:
        raise ValueError("tree nodes are not adjacent")
    if left.byte_length != left.leaf_count * profile.chunk_size:
        raise ValueError("left subtree must be full before a right sibling")
    if require_equal_perfect and not (left.is_perfect and right.is_perfect and left.height == right.height):
        raise ValueError("frontier carry requires equal perfect subtrees")
    height = max(left.height, right.height) + 1
    count = left.leaf_count + right.leaf_count
    length = left.byte_length + right.byte_length
    digests = []
    for algorithm, x, y in zip(profile.algorithms, left.digests, right.digests, strict=True):
        frame = record(b"SIGTJOIN", ((1, profile.to_bytes()), (2, u16(int(algorithm))), (3, u32(height)), (4, u64(left.start_leaf)), (5, u64(count)), (6, u64(length)), (7, x), (8, y)))
        digests.append(_hash(algorithm, domain_tag(TreeDomainId.NODE) + frame))
    return TreeNode(left.start_leaf, count, length, height, tuple(digests))


def empty_root(profile: TreeProfileV1 = DEFAULT_PROFILE) -> TreeRoot:
    digests = []
    for algorithm in profile.algorithms:
        frame = record(b"SIGTEMPT", ((1, profile.to_bytes()), (2, u16(int(algorithm))), (3, u64(0))))
        digests.append(_hash(algorithm, domain_tag(TreeDomainId.EMPTY) + frame))
    return TreeRoot(profile, 0, 0, tuple(digests))


class TreeBuilder:
    def __init__(self, profile: TreeProfileV1 = DEFAULT_PROFILE) -> None:
        if profile != DEFAULT_PROFILE:
            raise ValueError("unsupported Sigma Tree profile")
        self.profile = profile
        self._buffer = bytearray()
        self._nodes: list[TreeNode] = []
        self._byte_length = 0
        self._leaf_count = 0
        self._finalized = False

    @property
    def frontier(self) -> TreeFrontier:
        return TreeFrontier(tuple(self._nodes))

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("Sigma Tree builder is finalized")
        if not isinstance(data, bytes):
            raise TypeError("tree input chunks must be bytes")
        if self._byte_length + len(data) >= 1 << 64:
            raise ValueError("Sigma Tree input exceeds u64 byte length")
        self._byte_length += len(data)
        offset = 0
        if self._buffer:
            take = min(self.profile.chunk_size - len(self._buffer), len(data))
            self._buffer.extend(data[:take])
            offset = take
            if len(self._buffer) == self.profile.chunk_size:
                self._push_leaf(bytes(self._buffer))
                self._buffer.clear()
        while len(data) - offset >= self.profile.chunk_size:
            end = offset + self.profile.chunk_size
            self._push_leaf(data[offset:end])
            offset = end
        self._buffer.extend(data[offset:])

    def _integrate_leaf_node(self, node: TreeNode) -> None:
        if node.start_leaf != self._leaf_count or node.leaf_count != 1 or node.height != 0:
            raise ValueError("prehashed leaf node does not match the next canonical leaf")
        while self._nodes and self._nodes[-1].height == node.height:
            node = combine_nodes(self.profile, self._nodes.pop(), node, require_equal_perfect=True)
        self._nodes.append(node)
        self._leaf_count += 1
        TreeFrontier(tuple(self._nodes))

    def _push_leaf(self, leaf: bytes) -> None:
        self._integrate_leaf_node(leaf_node(self.profile, self._leaf_count, self._leaf_count * self.profile.chunk_size, leaf))

    @classmethod
    def from_prehashed_leaves(cls, leaves: Iterable[tuple[tuple[bytes, ...], int]], profile: TreeProfileV1 = DEFAULT_PROFILE) -> TreeRoot:
        """Backend-neutral reducer; only the final canonical leaf may be short."""
        builder = cls(profile)
        short_seen = False
        for digests, byte_length in leaves:
            if short_seen:
                raise ValueError("only the final canonical leaf may be short")
            if not 1 <= byte_length <= profile.chunk_size:
                raise ValueError("prehashed leaf length is outside profile bounds")
            validate_digests(digests, profile)
            builder._integrate_leaf_node(TreeNode(builder._leaf_count, 1, byte_length, 0, tuple(digests)))
            builder._byte_length += byte_length
            short_seen = byte_length < profile.chunk_size
        return builder.finalize()

    def finalize(self) -> TreeRoot:
        if self._finalized:
            raise RuntimeError("Sigma Tree builder is finalized")
        self._finalized = True
        if self._buffer:
            self._push_leaf(bytes(self._buffer))
            self._buffer.clear()
        if not self._nodes:
            if self._byte_length != 0:
                raise RuntimeError("empty frontier with non-empty input")
            return empty_root(self.profile)
        node = self._nodes[-1]
        for left in reversed(self._nodes[:-1]):
            node = combine_nodes(self.profile, left, node)
        if node.start_leaf != 0 or node.leaf_count != self._leaf_count or node.byte_length != self._byte_length:
            raise RuntimeError("Sigma Tree accounting invariant failed")
        return TreeRoot(self.profile, self._byte_length, self._leaf_count, node.digests)


def build_tree(data: bytes, profile: TreeProfileV1 = DEFAULT_PROFILE) -> TreeRoot:
    builder = TreeBuilder(profile)
    builder.update(data)
    return builder.finalize()


def build_tree_chunks(chunks: Iterable[bytes], profile: TreeProfileV1 = DEFAULT_PROFILE) -> TreeRoot:
    builder = TreeBuilder(profile)
    for chunk in chunks:
        builder.update(chunk)
    return builder.finalize()
