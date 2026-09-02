"""Canonical Sigma Tree v2 anchor with O(log N) frontier storage."""

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import AlgorithmId, AnchorProfileId, DomainId
from sigma.suites.registry import get_suite

from .base import AnchorEvidence
from .branches import hash_once


@dataclass(frozen=True)
class _TreeNode:
    digest: bytes
    start: int
    leaf_count: int
    byte_length: int
    height: int


class TreeWide:
    """Rechunk arbitrary updates into suite-fixed leaves and build four trees."""

    def __init__(self, context: SigmaContextV2):
        self.context = context
        self.suite = get_suite(context.suite_id)
        self.suite.validate_context(context)
        if context.anchor_profile is not AnchorProfileId.TREE_WIDE:
            raise ValueError("TreeWide requires the TREE_WIDE anchor profile")
        self._buffer = bytearray()
        self._frontiers: List[List[_TreeNode]] = [[] for _ in context.branches]
        self._message_length = 0
        self._leaf_count = 0
        self._finalized = False

    @property
    def frontier_node_count(self) -> int:
        return sum(len(frontier) for frontier in self._frontiers)

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("TreeWide is already finalized")
        if not isinstance(data, bytes):
            raise TypeError("message chunks must be bytes")
        new_length = self._message_length + len(data)
        if new_length >= 1 << 64:
            raise ValueError("message length exceeds the v2 limit")
        self._message_length = new_length
        offset = 0
        if self._buffer:
            needed = self.context.chunk_size - len(self._buffer)
            taken = min(needed, len(data))
            self._buffer.extend(data[:taken])
            offset = taken
            if len(self._buffer) == self.context.chunk_size:
                self._push_leaf(bytes(self._buffer))
                self._buffer.clear()
        while len(data) - offset >= self.context.chunk_size:
            end = offset + self.context.chunk_size
            self._push_leaf(data[offset:end])
            offset = end
        self._buffer.extend(data[offset:])

    @staticmethod
    def leaf_digest(
        context: SigmaContextV2,
        index: int,
        algorithm: AlgorithmId,
        leaf: bytes,
    ) -> bytes:
        framed = encode_tlv(
            (
                (1, context.to_bytes()),
                (2, encode_uint(algorithm, 2)),
                (3, encode_uint(index, 8)),
                (4, encode_uint(len(leaf), 4)),
                (5, leaf),
            )
        )
        return hash_once(algorithm, domain_tag(DomainId.TREE_LEAF) + framed)

    def _parent(self, algorithm, left: _TreeNode, right: _TreeNode) -> _TreeNode:
        if left.start + left.leaf_count != right.start:
            raise ValueError("tree nodes are not adjacent")
        height = max(left.height, right.height) + 1
        leaf_count = left.leaf_count + right.leaf_count
        byte_length = left.byte_length + right.byte_length
        framed = encode_tlv(
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(algorithm, 2)),
                (3, encode_uint(height, 4)),
                (4, encode_uint(left.start, 8)),
                (5, encode_uint(leaf_count, 8)),
                (6, encode_uint(byte_length, 8)),
                (7, left.digest),
                (8, right.digest),
            )
        )
        digest = hash_once(algorithm, domain_tag(DomainId.TREE_NODE) + framed)
        return _TreeNode(digest, left.start, leaf_count, byte_length, height)

    def _push_leaf(self, leaf: bytes) -> None:
        digests = tuple(
            self.leaf_digest(self.context, self._leaf_count, algorithm, leaf)
            for algorithm in self.context.branches
        )
        self._push_prehashed_leaf(digests, len(leaf))

    def _push_prehashed_leaf(self, digests: Sequence[bytes], byte_length: int) -> None:
        if len(digests) != len(self.context.branches):
            raise ValueError("prehashed leaf does not contain every branch")
        if not 1 <= byte_length <= self.context.chunk_size:
            raise ValueError("prehashed leaf length is outside suite limits")
        for branch_index, (algorithm, digest) in enumerate(
            zip(self.context.branches, digests, strict=False)
        ):
            if not isinstance(digest, bytes) or len(digest) != 64:
                raise ValueError("prehashed branch digest must contain 64 bytes")
            node = _TreeNode(digest, self._leaf_count, 1, byte_length, 0)
            frontier = self._frontiers[branch_index]
            while frontier and frontier[-1].leaf_count == node.leaf_count:
                node = self._parent(algorithm, frontier.pop(), node)
            frontier.append(node)
        self._leaf_count += 1

    def _empty_root(self, algorithm) -> bytes:
        framed = encode_tlv(
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(algorithm, 2)),
                (3, encode_uint(0, 8)),
            )
        )
        return hash_once(algorithm, domain_tag(DomainId.TREE_EMPTY) + framed)

    def finalize(self) -> AnchorEvidence:
        if self._finalized:
            raise RuntimeError("TreeWide is already finalized")
        self._finalized = True
        if self._buffer:
            self._push_leaf(bytes(self._buffer))
            self._buffer.clear()
        roots = []
        for algorithm, frontier in zip(self.context.branches, self._frontiers, strict=False):
            if not frontier:
                roots.append(self._empty_root(algorithm))
                continue
            node = frontier[-1]
            for left in reversed(frontier[:-1]):
                node = self._parent(algorithm, left, node)
            if node.byte_length != self._message_length:
                raise RuntimeError("tree accounting invariant failed")
            roots.append(node.digest)
        return AnchorEvidence(
            self.context.branches, tuple(roots), self._message_length, self.context.suite_id
        )

    @classmethod
    def compute(cls, context: SigmaContextV2, chunks: Iterable[bytes]) -> AnchorEvidence:
        engine = cls(context)
        for chunk in chunks:
            engine.update(chunk)
        return engine.finalize()

    @classmethod
    def from_prehashed_leaves(
        cls,
        context: SigmaContextV2,
        leaves: Iterable[Tuple[Sequence[bytes], int]],
    ) -> AnchorEvidence:
        """Reduce ordered backend results using the canonical serial reducer."""

        engine = cls(context)
        short_leaf_seen = False
        total_length = 0
        for digests, byte_length in leaves:
            if short_leaf_seen:
                raise ValueError("only the final canonical leaf may be short")
            engine._push_prehashed_leaf(digests, byte_length)
            total_length += byte_length
            short_leaf_seen = byte_length < context.chunk_size
        engine._message_length = total_length
        return engine.finalize()
