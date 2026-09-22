"""Persistent derived Tree index sidecar for PX0.

The sidecar is never part of TreeRoot or ArtifactId. It persists only canonical
TreeNode summaries plus optional operational source hints.
"""

from __future__ import annotations

import hashlib
import hmac
import mmap
import os
import tempfile
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterable

from sigma.version import PERSISTENT_TREE_INDEX_FORMAT_VERSION

from .checkpoint import (
    TreeSourceHintV1,
    source_hint_from_path,
    source_hint_matches_path,
)
from .core import combine_nodes, empty_root, leaf_node
from .delta import TreeDeltaIndex, TreeEditV1, TreeUpdateResultV1
from .model import DEFAULT_PROFILE, TreeFrontier, TreeNode, TreeProfileV1, TreeRoot
from .proofs import (
    InclusionProofV1,
    InclusionStepV1,
    RangeProofV1,
    _leaf_byte_length,
    _range_geometry,
    inclusion_geometry,
    range_witness_geometry,
)

_INDEX_MAGIC = b"SIGTIDX1"
_INDEX_INTEGRITY_DOMAIN = b"SIGMA-PERSISTENT-TREE-INDEX-V1\x00"
_MAX_INDEX_NODES = 1 << 20
_MAX_INDEX_BYTES = 512 << 20
_MAX_NODE_WIRE = 1 << 20
_U32_MAX = (1 << 32) - 1


class PersistentTreeIndexDecodeError(ValueError):
    """Raised when a persistent Tree index sidecar is malformed."""


class PersistentSourceValidationV1(IntEnum):
    FULL = 1
    LENGTH_ONLY = 2


class PersistentIndexSourceUnverified(ValueError):
    """Raised when a source-dependent operation lacks cryptographic source binding."""


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _read_uint(view: memoryview, offset: int, width: int) -> tuple[int, int]:
    end = offset + width
    if end > len(view):
        raise PersistentTreeIndexDecodeError("truncated persistent index integer")
    return int.from_bytes(view[offset:end], "big"), end


def _read_blob(
    view: memoryview,
    offset: int,
    *,
    max_length: int,
    name: str,
) -> tuple[bytes, int]:
    length, offset = _read_uint(view, offset, 4)
    if length > max_length:
        raise PersistentTreeIndexDecodeError(f"{name} exceeds persistent index limit")
    end = offset + length
    if end > len(view):
        raise PersistentTreeIndexDecodeError(f"truncated persistent index {name}")
    return bytes(view[offset:end]), end


def _split(count: int) -> int:
    if count <= 1:
        raise ValueError("cannot split singleton subtree")
    return 1 << ((count - 1).bit_length() - 1)


def _canonical_keys(total: int) -> tuple[tuple[int, int], ...]:
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise TypeError("total leaf count must be a non-negative int")
    keys: list[tuple[int, int]] = []

    def walk(start: int, count: int) -> None:
        if count <= 0:
            return
        keys.append((start, count))
        if count == 1:
            return
        left = _split(count)
        walk(start, left)
        walk(start + left, count - left)

    walk(0, total)
    return tuple(sorted(keys))


def _node_map(nodes: tuple[TreeNode, ...]) -> dict[tuple[int, int], TreeNode]:
    return {(node.start_leaf, node.leaf_count): node for node in nodes}


def _build_from_leaf_nodes(
    leaf_nodes: tuple[TreeNode, ...],
    total_bytes: int,
    profile: TreeProfileV1,
) -> tuple[TreeRoot, tuple[TreeNode, ...]]:
    if not leaf_nodes:
        return empty_root(profile), ()

    nodes: dict[tuple[int, int], TreeNode] = {
        (node.start_leaf, node.leaf_count): node for node in leaf_nodes
    }

    def build(start: int, count: int) -> TreeNode:
        key = (start, count)
        existing = nodes.get(key)
        if existing is not None:
            return existing
        left_count = _split(count)
        node = combine_nodes(
            profile,
            build(start, left_count),
            build(start + left_count, count - left_count),
        )
        nodes[key] = node
        return node

    root_node = build(0, len(leaf_nodes))
    root = TreeRoot(
        profile,
        total_bytes,
        len(leaf_nodes),
        root_node.digests,
    )
    ordered = tuple(nodes[key] for key in _canonical_keys(len(leaf_nodes)))
    return root, ordered


@dataclass(frozen=True)
class TreePersistentIndexV1:
    root: TreeRoot
    nodes: tuple[TreeNode, ...]
    source_hint: TreeSourceHintV1 | None = None
    profile: TreeProfileV1 = DEFAULT_PROFILE
    _nodes: dict[tuple[int, int], TreeNode] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.profile != DEFAULT_PROFILE or self.root.profile != self.profile:
            raise ValueError("persistent index profile/root profile mismatch")
        if not isinstance(self.nodes, tuple) or any(
            not isinstance(node, TreeNode) for node in self.nodes
        ):
            raise TypeError("persistent index nodes must be tuple[TreeNode,...]")
        if len(self.nodes) > _MAX_INDEX_NODES:
            raise ValueError("persistent index has too many nodes")
        if self.source_hint is not None:
            if not isinstance(self.source_hint, TreeSourceHintV1):
                raise TypeError("source_hint must be TreeSourceHintV1 or None")
            if self.source_hint.size != self.root.byte_length:
                raise ValueError("source hint size differs from TreeRoot")

        keys = tuple((node.start_leaf, node.leaf_count) for node in self.nodes)
        expected_keys = _canonical_keys(self.root.leaf_count)
        if keys != expected_keys:
            raise ValueError("persistent index node ordering/coverage is non-canonical")
        if len(set(keys)) != len(keys):
            raise ValueError("persistent index contains duplicate node keys")
        node_map = _node_map(self.nodes)
        object.__setattr__(self, "_nodes", node_map)

        if self.root.leaf_count == 0:
            if self.nodes:
                raise ValueError("empty TreeRoot must have no persistent nodes")
            if self.root != empty_root(self.profile):
                raise ValueError("persistent empty TreeRoot is non-canonical")
            return

        expected_node_count = 2 * self.root.leaf_count - 1
        if len(self.nodes) != expected_node_count:
            raise ValueError("persistent index node cardinality is non-canonical")

        for index in range(self.root.leaf_count):
            leaf = node_map[(index, 1)]
            expected_length = _leaf_byte_length(self.root, index)
            if (
                leaf.start_leaf != index
                or leaf.leaf_count != 1
                or leaf.height != 0
                or leaf.byte_length != expected_length
            ):
                raise ValueError("persistent leaf geometry differs from TreeRoot")

        def validate(start: int, count: int) -> TreeNode:
            stored = node_map[(start, count)]
            if count == 1:
                return stored
            left_count = _split(count)
            expected = combine_nodes(
                self.profile,
                validate(start, left_count),
                validate(start + left_count, count - left_count),
            )
            if expected.to_bytes() != stored.to_bytes():
                raise ValueError("persistent internal node does not match its children")
            return stored

        root_node = validate(0, self.root.leaf_count)
        if (
            root_node.byte_length != self.root.byte_length
            or root_node.leaf_count != self.root.leaf_count
            or root_node.digests != self.root.digests
        ):
            raise ValueError("persistent root node differs from TreeRoot")

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def index_checksum(self) -> bytes:
        payload = self._payload_without_checksum()
        return hashlib.sha256(_INDEX_INTEGRITY_DOMAIN + payload).digest()

    @property
    def frontier(self) -> TreeFrontier:
        if self.root.leaf_count == 0:
            return TreeFrontier()
        values: list[TreeNode] = []
        start = 0
        remaining = self.root.leaf_count
        while remaining:
            height = remaining.bit_length() - 1
            count = 1 << height
            values.append(self._nodes[(start, count)])
            start += count
            remaining -= count
        return TreeFrontier(tuple(values))

    def node(self, start: int, count: int) -> TreeNode:
        try:
            return self._nodes[(start, count)]
        except KeyError as exc:
            raise ValueError("requested span is not canonical in persistent index") from exc

    def prove_leaf(self, leaf_index: int) -> InclusionProofV1:
        geometry = inclusion_geometry(self.root, leaf_index)
        steps = tuple(
            InclusionStepV1(side, self.node(start, count))
            for side, start, count, _ in geometry
        )
        return InclusionProofV1(
            self.profile,
            self.root,
            leaf_index,
            _leaf_byte_length(self.root, leaf_index),
            steps,
        )

    def source_hint_matches(self, path: str | os.PathLike[str]) -> bool:
        """Operational hint only; never cryptographic source validation."""
        if self.source_hint is None:
            return False
        return source_hint_matches_path(self.source_hint, path)

    def validate_source(self, data: bytes) -> bool:
        if not isinstance(data, bytes):
            raise TypeError("persistent index source must be bytes")
        if len(data) != self.root.byte_length:
            return False
        from .core import build_tree

        return hmac.compare_digest(
            build_tree(data, self.profile).to_bytes(),
            self.root.to_bytes(),
        )

    def bind_source(
        self,
        data: bytes,
        *,
        validation: PersistentSourceValidationV1 = PersistentSourceValidationV1.FULL,
    ) -> "BoundPersistentTreeIndexV1":
        if not isinstance(validation, PersistentSourceValidationV1):
            raise TypeError("validation must be PersistentSourceValidationV1")
        if not isinstance(data, bytes):
            raise TypeError("persistent index source must be bytes")
        if len(data) != self.root.byte_length:
            raise ValueError("source byte length differs from persistent TreeRoot")
        verified = False
        if validation is PersistentSourceValidationV1.FULL:
            if not self.validate_source(data):
                raise ValueError("source does not match persistent TreeRoot")
            verified = True
        return BoundPersistentTreeIndexV1(self, data, verified)

    @classmethod
    def from_delta_index(
        cls,
        delta: TreeDeltaIndex,
        *,
        source_hint: TreeSourceHintV1 | None = None,
    ) -> "TreePersistentIndexV1":
        if not isinstance(delta, TreeDeltaIndex):
            raise TypeError("delta must be TreeDeltaIndex")
        nodes = tuple(
            delta.node(start, count)
            for start, count in _canonical_keys(delta.leaf_count)
        )
        return cls(delta.root, nodes, source_hint, delta.profile)

    def _payload_without_checksum(self) -> bytes:
        profile_wire = self.profile.to_bytes()
        root_wire = self.root.to_bytes()
        hint_wire = b"" if self.source_hint is None else self.source_hint.to_bytes()
        out = bytearray()
        out.extend(_INDEX_MAGIC)
        out.extend(_u16(PERSISTENT_TREE_INDEX_FORMAT_VERSION))
        out.extend(_u32(len(profile_wire)))
        out.extend(profile_wire)
        out.extend(_u32(len(root_wire)))
        out.extend(root_wire)
        out.extend(_u32(len(hint_wire)))
        out.extend(hint_wire)
        out.extend(_u64(len(self.nodes)))
        for node in self.nodes:
            raw = node.to_bytes()
            if len(raw) > _MAX_NODE_WIRE:
                raise ValueError("persistent TreeNode wire exceeds sidecar limit")
            out.extend(_u32(len(raw)))
            out.extend(raw)
        if len(out) + 32 > _MAX_INDEX_BYTES:
            raise ValueError("persistent index exceeds sidecar size limit")
        return bytes(out)

    def to_bytes(self) -> bytes:
        payload = self._payload_without_checksum()
        return payload + hashlib.sha256(
            _INDEX_INTEGRITY_DOMAIN + payload
        ).digest()

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        max_nodes: int = _MAX_INDEX_NODES,
    ) -> "TreePersistentIndexV1":
        if not isinstance(data, bytes):
            raise TypeError("persistent index wire must be bytes")
        return cls._from_buffer(memoryview(data), max_nodes=max_nodes)

    @classmethod
    def _from_buffer(
        cls,
        view: memoryview,
        *,
        max_nodes: int,
    ) -> "TreePersistentIndexV1":
        if (
            isinstance(max_nodes, bool)
            or not isinstance(max_nodes, int)
            or not 0 <= max_nodes <= _MAX_INDEX_NODES
        ):
            raise ValueError("max_nodes is outside supported persistent-index range")
        if len(view) < 8 + 2 + 4 + 4 + 4 + 8 + 32:
            raise PersistentTreeIndexDecodeError("persistent index is truncated")
        if len(view) > _MAX_INDEX_BYTES:
            raise PersistentTreeIndexDecodeError("persistent index exceeds size limit")
        if bytes(view[:8]) != _INDEX_MAGIC:
            raise PersistentTreeIndexDecodeError("invalid persistent index magic")
        version = int.from_bytes(view[8:10], "big")
        if version != PERSISTENT_TREE_INDEX_FORMAT_VERSION:
            raise PersistentTreeIndexDecodeError(
                f"unsupported persistent index format version: {version}"
            )
        payload_end = len(view) - 32
        expected_checksum = bytes(view[payload_end:])
        actual_checksum = hashlib.sha256(
            _INDEX_INTEGRITY_DOMAIN + view[:payload_end]
        ).digest()
        if not hmac.compare_digest(expected_checksum, actual_checksum):
            raise PersistentTreeIndexDecodeError("persistent index checksum mismatch")

        offset = 10
        profile_wire, offset = _read_blob(
            view,
            offset,
            max_length=1 << 20,
            name="profile",
        )
        root_wire, offset = _read_blob(
            view,
            offset,
            max_length=1 << 20,
            name="root",
        )
        hint_wire, offset = _read_blob(
            view,
            offset,
            max_length=1 << 20,
            name="source hint",
        )
        node_count, offset = _read_uint(view, offset, 8)
        if node_count > max_nodes:
            raise PersistentTreeIndexDecodeError(
                "persistent index node count exceeds parser limit"
            )

        nodes: list[TreeNode] = []
        for _ in range(node_count):
            raw, offset = _read_blob(
                view,
                offset,
                max_length=_MAX_NODE_WIRE,
                name="TreeNode",
            )
            nodes.append(TreeNode.from_bytes(raw))
        if offset != payload_end:
            raise PersistentTreeIndexDecodeError(
                "persistent index has trailing or truncated node payload"
            )

        try:
            profile = TreeProfileV1.from_bytes(profile_wire)
            root = TreeRoot.from_bytes(root_wire)
            source_hint = (
                None if not hint_wire else TreeSourceHintV1.from_bytes(hint_wire)
            )
            return cls(root, tuple(nodes), source_hint, profile)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, PersistentTreeIndexDecodeError):
                raise
            raise PersistentTreeIndexDecodeError(
                f"invalid persistent index semantics: {exc}"
            ) from exc


@dataclass
class BoundPersistentTreeIndexV1:
    index: TreePersistentIndexV1
    source: bytes
    source_verified: bool

    def __post_init__(self) -> None:
        if not isinstance(self.index, TreePersistentIndexV1):
            raise TypeError("index must be TreePersistentIndexV1")
        if not isinstance(self.source, bytes):
            raise TypeError("source must be bytes")
        if not isinstance(self.source_verified, bool):
            raise TypeError("source_verified must be bool")
        if len(self.source) != self.index.root.byte_length:
            raise ValueError("bound source length differs from persistent TreeRoot")

    def verify_source(self) -> bool:
        self.source_verified = self.index.validate_source(self.source)
        return self.source_verified

    def _require_verified(self) -> None:
        if not self.source_verified:
            raise PersistentIndexSourceUnverified(
                "source-dependent persistent-index operation requires FULL validation"
            )

    def prove_range(self, start: int, length: int) -> RangeProofV1:
        self._require_verified()
        first_leaf, last_leaf_exclusive, prefix_length, suffix_length = _range_geometry(
            self.index.root,
            start,
            length,
        )
        end = start + length
        first_leaf_start = first_leaf * self.index.profile.chunk_size
        last_leaf = last_leaf_exclusive - 1
        last_leaf_end = (
            last_leaf * self.index.profile.chunk_size
            + _leaf_byte_length(self.index.root, last_leaf)
        )
        prefix = self.source[first_leaf_start:start] if prefix_length else b""
        suffix = self.source[end:last_leaf_end] if suffix_length else b""
        witnesses = tuple(
            self.index.node(witness_start, witness_count)
            for witness_start, witness_count, _ in range_witness_geometry(
                self.index.root,
                first_leaf,
                last_leaf_exclusive,
            )
        )
        return RangeProofV1(
            self.index.profile,
            self.index.root,
            start,
            length,
            prefix,
            suffix,
            witnesses,
        )

    def delta_index(self) -> TreeDeltaIndex:
        self._require_verified()
        return TreeDeltaIndex.from_precomputed_state(
            self.source,
            self.index.root,
            self.index._nodes,
            self.index.profile,
        )

    def apply_delta(
        self,
        edits: tuple[TreeEditV1, ...] | list[TreeEditV1],
    ) -> "PersistentTreeMutationResultV1":
        delta = self.delta_index()
        update = delta.apply_delta(edits)
        new_data = delta.materialize()
        new_index = TreePersistentIndexV1.from_delta_index(delta)
        return PersistentTreeMutationResultV1(new_data, new_index, update)

    def append(self, suffix: bytes) -> "PersistentTreeMutationResultV1":
        delta = self.delta_index()
        update = delta.append(suffix)
        new_data = delta.materialize()
        new_index = TreePersistentIndexV1.from_delta_index(delta)
        return PersistentTreeMutationResultV1(new_data, new_index, update)


@dataclass(frozen=True)
class PersistentTreeMutationResultV1:
    data: bytes
    index: TreePersistentIndexV1
    update: TreeUpdateResultV1

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("persistent mutation data must be bytes")
        if not isinstance(self.index, TreePersistentIndexV1):
            raise TypeError("persistent mutation index must be TreePersistentIndexV1")
        if not isinstance(self.update, TreeUpdateResultV1):
            raise TypeError("persistent mutation update must be TreeUpdateResultV1")
        if self.index.root != self.update.root:
            raise ValueError("persistent mutation index/root mismatch")


def build_persistent_index_chunks(
    chunks: Iterable[bytes],
    *,
    profile: TreeProfileV1 = DEFAULT_PROFILE,
    source_hint: TreeSourceHintV1 | None = None,
) -> TreePersistentIndexV1:
    if profile != DEFAULT_PROFILE:
        raise ValueError("unsupported persistent index profile")
    buffer = bytearray()
    leaf_nodes: list[TreeNode] = []
    total_bytes = 0

    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("persistent index chunks must be bytes")
        if total_bytes + len(chunk) >= 1 << 64:
            raise ValueError("persistent index source exceeds u64 byte length")
        total_bytes += len(chunk)
        offset = 0
        if buffer:
            take = min(profile.chunk_size - len(buffer), len(chunk))
            buffer.extend(chunk[:take])
            offset = take
            if len(buffer) == profile.chunk_size:
                index = len(leaf_nodes)
                leaf_nodes.append(
                    leaf_node(
                        profile,
                        index,
                        index * profile.chunk_size,
                        bytes(buffer),
                    )
                )
                buffer.clear()
        while len(chunk) - offset >= profile.chunk_size:
            end = offset + profile.chunk_size
            raw = chunk[offset:end]
            index = len(leaf_nodes)
            leaf_nodes.append(
                leaf_node(
                    profile,
                    index,
                    index * profile.chunk_size,
                    raw,
                )
            )
            offset = end
        buffer.extend(chunk[offset:])

    if buffer:
        index = len(leaf_nodes)
        leaf_nodes.append(
            leaf_node(
                profile,
                index,
                index * profile.chunk_size,
                bytes(buffer),
            )
        )

    root, nodes = _build_from_leaf_nodes(tuple(leaf_nodes), total_bytes, profile)
    return TreePersistentIndexV1(root, nodes, source_hint, profile)


def build_persistent_index(
    data: bytes,
    *,
    profile: TreeProfileV1 = DEFAULT_PROFILE,
    source_hint: TreeSourceHintV1 | None = None,
) -> TreePersistentIndexV1:
    if not isinstance(data, bytes):
        raise TypeError("persistent index source must be bytes")
    return build_persistent_index_chunks(
        (data,),
        profile=profile,
        source_hint=source_hint,
    )


def build_persistent_index_file(
    path: str | os.PathLike[str],
    *,
    profile: TreeProfileV1 = DEFAULT_PROFILE,
) -> TreePersistentIndexV1:
    source = Path(path)
    before = source_hint_from_path(source)

    def chunks() -> Iterable[bytes]:
        with source.open("rb") as handle:
            while True:
                raw = handle.read(profile.chunk_size)
                if not raw:
                    break
                yield raw

    index = build_persistent_index_chunks(
        chunks(),
        profile=profile,
        source_hint=before,
    )
    after = source_hint_from_path(source)
    if before != after:
        raise RuntimeError("source changed while persistent index was being built")
    return index


def write_persistent_index_atomic(
    path: str | os.PathLike[str],
    index: TreePersistentIndexV1,
) -> None:
    if not isinstance(index, TreePersistentIndexV1):
        raise TypeError("index must be TreePersistentIndexV1")
    destination = Path(path)
    parent = destination.parent
    if not parent.exists():
        raise FileNotFoundError(f"persistent index parent does not exist: {parent}")
    payload = index.to_bytes()
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_persistent_index(
    path: str | os.PathLike[str],
    *,
    use_mmap: bool = False,
    max_nodes: int = _MAX_INDEX_NODES,
) -> TreePersistentIndexV1:
    source = Path(path)
    if not use_mmap:
        return TreePersistentIndexV1.from_bytes(
            source.read_bytes(),
            max_nodes=max_nodes,
        )
    with source.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            view = memoryview(mapped)
            try:
                return TreePersistentIndexV1._from_buffer(
                    view,
                    max_nodes=max_nodes,
                )
            finally:
                view.release()


__all__ = [
    "BoundPersistentTreeIndexV1",
    "PersistentIndexSourceUnverified",
    "PersistentSourceValidationV1",
    "PersistentTreeIndexDecodeError",
    "PersistentTreeMutationResultV1",
    "TreePersistentIndexV1",
    "build_persistent_index",
    "build_persistent_index_chunks",
    "build_persistent_index_file",
    "read_persistent_index",
    "write_persistent_index_atomic",
]
