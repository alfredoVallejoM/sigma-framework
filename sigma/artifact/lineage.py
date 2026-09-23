"""PX2 deterministic lineage graph over identity-bound ArtifactId parents."""

from __future__ import annotations

import heapq
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable, Mapping, Sequence

from .record import SigmaArtifactV1
from .store import (
    ArtifactStoreCorruptionError,
    ArtifactStoreError,
    LocalArtifactStoreV1,
)

_DEFAULT_MAX_ARTIFACTS = 100_000
_DEFAULT_MAX_EDGES = 1_000_000
_DEFAULT_MAX_TOTAL_WIRE_BYTES = 512 * 1024 * 1024
_DEFAULT_MAX_TRAVERSAL_NODES = 100_000


class LineageError(RuntimeError):
    """Base PX2 lineage error."""


class LineageResourceLimitError(LineageError):
    """A bounded PX2 graph/traversal resource policy was exceeded."""


class LineageUnknownArtifactError(LineageError):
    """A query references an ID outside the accepted lineage universe."""


class LineageParentResolutionError(LineageError):
    """Missing-parent declarations do not satisfy the selected policy."""

    def __init__(self, message: str, parent_ids: tuple[bytes, ...] = ()) -> None:
        super().__init__(message)
        self.parent_ids = parent_ids


class LineageCycleError(LineageError):
    """The local stored lineage relation contains a directed cycle."""

    def __init__(self, cycle_path: tuple[bytes, ...]) -> None:
        super().__init__("lineage graph contains a cycle")
        self.cycle_path = cycle_path


class ParentResolutionPolicyV1(IntEnum):
    """How absent identity-bound parent IDs are interpreted."""

    STRICT = 0x0001
    EXTERNAL = 0x0002
    UNRESOLVED = 0x0003


class LineageCyclePolicyV1(IntEnum):
    """Whether cycle analysis raises or reports a rejected snapshot."""

    REJECT = 0x0001
    REPORT = 0x0002


class LineageIdStatusV1(IntEnum):
    """Resolution state of an ID in one accepted lineage graph."""

    STORED = 0x0001
    EXTERNAL = 0x0002
    UNRESOLVED = 0x0003


@dataclass(frozen=True)
class LineageResourceLimitsV1:
    max_artifacts: int = _DEFAULT_MAX_ARTIFACTS
    max_edges: int = _DEFAULT_MAX_EDGES
    max_total_artifact_wire_bytes: int = _DEFAULT_MAX_TOTAL_WIRE_BYTES
    max_traversal_nodes: int = _DEFAULT_MAX_TRAVERSAL_NODES

    def __post_init__(self) -> None:
        for name in (
            "max_artifacts",
            "max_edges",
            "max_total_artifact_wire_bytes",
            "max_traversal_nodes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.max_artifacts == 0:
            raise ValueError("max_artifacts must be positive")
        if self.max_traversal_nodes == 0:
            raise ValueError("max_traversal_nodes must be positive")


def _validate_id(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must contain exactly 32 bytes")
    return value


def _canonical_id_tuple(
    name: str,
    values: Iterable[bytes],
    *,
    max_items: int,
) -> tuple[bytes, ...]:
    materialized: list[bytes] = []
    for value in values:
        _validate_id(name, value)
        materialized.append(value)
        if len(materialized) > max_items:
            raise LineageResourceLimitError(
                f"{name} declarations exceed configured resource bound"
            )
    return tuple(sorted(set(materialized)))


@dataclass(frozen=True)
class LineageNodeV1:
    """Identity projection used by PX2.

    Product-authoritative nodes should be produced with from_artifact.
    Direct construction remains available for adapter validation and
    cycle-adversarial testing.
    """

    artifact_id: bytes
    parent_artifact_ids: tuple[bytes, ...]

    def __post_init__(self) -> None:
        _validate_id("artifact_id", self.artifact_id)
        if not isinstance(self.parent_artifact_ids, tuple):
            raise TypeError("parent_artifact_ids must be tuple")
        for parent in self.parent_artifact_ids:
            _validate_id("parent ArtifactId", parent)
        if tuple(sorted(set(self.parent_artifact_ids))) != self.parent_artifact_ids:
            raise ValueError("parent ArtifactIds must be sorted and unique")

    @classmethod
    def from_artifact(cls, artifact: SigmaArtifactV1) -> "LineageNodeV1":
        if not isinstance(artifact, SigmaArtifactV1):
            raise TypeError("artifact must be SigmaArtifactV1")
        return cls(artifact.artifact_id, artifact.parent_artifact_ids)


@dataclass(frozen=True)
class LineageInspectionV1:
    accepted: bool
    parent_policy: ParentResolutionPolicyV1
    cycle_policy: LineageCyclePolicyV1
    stored_artifact_ids: tuple[bytes, ...]
    external_parent_ids: tuple[bytes, ...]
    unresolved_parent_ids: tuple[bytes, ...]
    missing_parent_ids: tuple[bytes, ...]
    cycle_path: tuple[bytes, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise TypeError("accepted must be bool")
        if not isinstance(self.parent_policy, ParentResolutionPolicyV1):
            raise TypeError("parent_policy must be ParentResolutionPolicyV1")
        if not isinstance(self.cycle_policy, LineageCyclePolicyV1):
            raise TypeError("cycle_policy must be LineageCyclePolicyV1")


def _canonical_cycle(path: Sequence[bytes]) -> tuple[bytes, ...]:
    values = tuple(path)
    if len(values) < 2 or values[0] != values[-1]:
        raise ValueError("cycle path must close on its first ID")
    ring = values[:-1]
    candidates = tuple(
        ring[offset:] + ring[:offset]
        for offset in range(len(ring))
    )
    best = min(candidates)
    return best + (best[0],)


def _children_index(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
) -> dict[bytes, tuple[bytes, ...]]:
    mutable: dict[bytes, list[bytes]] = {}
    for child in sorted(parent_map):
        for parent in parent_map[child]:
            mutable.setdefault(parent, []).append(child)
    return {
        parent: tuple(sorted(children))
        for parent, children in mutable.items()
    }


def _topological_or_cycle(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    stored = frozenset(parent_map)
    children = _children_index(parent_map)
    indegree = {
        artifact_id: sum(parent in stored for parent in parents)
        for artifact_id, parents in parent_map.items()
    }
    heap = [artifact_id for artifact_id, degree in indegree.items() if degree == 0]
    heapq.heapify(heap)
    order: list[bytes] = []
    while heap:
        parent = heapq.heappop(heap)
        order.append(parent)
        for child in children.get(parent, ()):
            if child not in stored:
                continue
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(heap, child)
    if len(order) == len(parent_map):
        return tuple(order), ()

    remaining = frozenset(
        artifact_id for artifact_id, degree in indegree.items() if degree > 0
    )

    # Kahn's remainder has at least one remaining local parent per node.
    # Following the lexicographically first such parent is a bounded functional
    # walk and must eventually repeat, yielding a cycle without Python recursion.
    current = min(remaining)
    walk: list[bytes] = []
    position: dict[bytes, int] = {}
    while current not in position:
        position[current] = len(walk)
        walk.append(current)
        local_parents = tuple(
            parent
            for parent in parent_map[current]
            if parent in remaining
        )
        if not local_parents:
            raise AssertionError(
                "Kahn cycle remainder contains node without remaining parent"
            )
        current = min(local_parents)

    start = position[current]
    reverse_ring = tuple(walk[start:])
    forward_ring = tuple(reversed(reverse_ring))
    return tuple(order), _canonical_cycle(forward_ring + (forward_ring[0],))


def _resolve_missing(
    *,
    stored: frozenset[bytes],
    parent_map: Mapping[bytes, tuple[bytes, ...]],
    parent_policy: ParentResolutionPolicyV1,
    declared_external_ids: tuple[bytes, ...],
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    missing = tuple(
        sorted(
            {
                parent
                for parents in parent_map.values()
                for parent in parents
                if parent not in stored
            }
        )
    )
    missing_set = frozenset(missing)
    external_set = frozenset(declared_external_ids)

    stale_external = tuple(sorted(external_set - missing_set))
    if stale_external:
        raise LineageParentResolutionError(
            "declared external IDs are stored or unreferenced",
            stale_external,
        )

    if parent_policy is ParentResolutionPolicyV1.STRICT:
        if missing:
            raise LineageParentResolutionError(
                "STRICT lineage requires every identity-bound parent to be stored",
                missing,
            )
        return missing, (), ()

    if parent_policy is ParentResolutionPolicyV1.EXTERNAL:
        undeclared = tuple(sorted(missing_set - external_set))
        if undeclared:
            raise LineageParentResolutionError(
                "EXTERNAL lineage requires every missing parent to be explicitly declared",
                undeclared,
            )
        return missing, tuple(sorted(external_set)), ()

    if parent_policy is ParentResolutionPolicyV1.UNRESOLVED:
        return (
            missing,
            tuple(sorted(external_set)),
            tuple(sorted(missing_set - external_set)),
        )

    raise TypeError("unsupported ParentResolutionPolicyV1")


class ArtifactLineageGraphV1:
    """Accepted immutable PX2 DAG with explicit boundary-parent resolution."""

    def __init__(
        self,
        *,
        parent_map: Mapping[bytes, tuple[bytes, ...]],
        external_parent_ids: tuple[bytes, ...],
        unresolved_parent_ids: tuple[bytes, ...],
        parent_policy: ParentResolutionPolicyV1,
        topological_order: tuple[bytes, ...],
        limits: LineageResourceLimitsV1,
    ) -> None:
        self._parents = {
            artifact_id: tuple(parents)
            for artifact_id, parents in sorted(parent_map.items())
        }
        self._children = _children_index(self._parents)
        self._stored = frozenset(self._parents)
        self._external = frozenset(external_parent_ids)
        self._unresolved = frozenset(unresolved_parent_ids)
        self._topological = tuple(topological_order)
        self._limits = limits
        self.parent_policy = parent_policy

    @property
    def artifact_ids(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._stored))

    @property
    def external_parent_ids(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._external))

    @property
    def unresolved_parent_ids(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._unresolved))

    @property
    def edge_count(self) -> int:
        return sum(len(parents) for parents in self._parents.values())

    @property
    def local_edge_count(self) -> int:
        return sum(
            parent in self._stored
            for parents in self._parents.values()
            for parent in parents
        )

    def status(self, artifact_id: bytes) -> LineageIdStatusV1:
        _validate_id("artifact_id", artifact_id)
        if artifact_id in self._stored:
            return LineageIdStatusV1.STORED
        if artifact_id in self._external:
            return LineageIdStatusV1.EXTERNAL
        if artifact_id in self._unresolved:
            return LineageIdStatusV1.UNRESOLVED
        raise LineageUnknownArtifactError(
            f"ArtifactId is outside lineage snapshot: {artifact_id.hex()}"
        )

    def _known(self, artifact_id: bytes) -> bool:
        return (
            artifact_id in self._stored
            or artifact_id in self._external
            or artifact_id in self._unresolved
        )

    def parents(self, artifact_id: bytes) -> tuple[bytes, ...]:
        _validate_id("artifact_id", artifact_id)
        if artifact_id not in self._stored:
            if self._known(artifact_id):
                return ()
            raise LineageUnknownArtifactError(
                f"ArtifactId is outside lineage snapshot: {artifact_id.hex()}"
            )
        return self._parents[artifact_id]

    def children(self, artifact_id: bytes) -> tuple[bytes, ...]:
        _validate_id("artifact_id", artifact_id)
        if not self._known(artifact_id):
            raise LineageUnknownArtifactError(
                f"ArtifactId is outside lineage snapshot: {artifact_id.hex()}"
            )
        return self._children.get(artifact_id, ())

    def roots(self) -> tuple[bytes, ...]:
        """Stored artifacts whose canonical identity has no parent ArtifactIds."""
        return tuple(
            artifact_id
            for artifact_id in sorted(self._stored)
            if not self._parents[artifact_id]
        )

    def local_entrypoints(self) -> tuple[bytes, ...]:
        """Stored nodes with no stored parents, including boundary-rooted nodes."""
        return tuple(
            artifact_id
            for artifact_id in sorted(self._stored)
            if not any(
                parent in self._stored for parent in self._parents[artifact_id]
            )
        )

    def topological_order(self) -> tuple[bytes, ...]:
        return self._topological

    def _traversal_limit(self, max_nodes: int | None) -> int:
        if max_nodes is None:
            return self._limits.max_traversal_nodes
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
            raise ValueError("max_nodes must be a positive integer")
        return min(max_nodes, self._limits.max_traversal_nodes)

    def ancestors(
        self,
        artifact_id: bytes,
        *,
        max_nodes: int | None = None,
    ) -> tuple[bytes, ...]:
        _validate_id("artifact_id", artifact_id)
        if not self._known(artifact_id):
            raise LineageUnknownArtifactError(
                f"ArtifactId is outside lineage snapshot: {artifact_id.hex()}"
            )
        limit = self._traversal_limit(max_nodes)
        seen: set[bytes] = set()
        queue: deque[bytes] = deque(self.parents(artifact_id))
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            if len(seen) > limit:
                raise LineageResourceLimitError(
                    "ancestor traversal exceeds max_nodes"
                )
            if current in self._stored:
                queue.extend(self._parents[current])
        return tuple(sorted(seen))

    def descendants(
        self,
        artifact_id: bytes,
        *,
        max_nodes: int | None = None,
    ) -> tuple[bytes, ...]:
        _validate_id("artifact_id", artifact_id)
        if not self._known(artifact_id):
            raise LineageUnknownArtifactError(
                f"ArtifactId is outside lineage snapshot: {artifact_id.hex()}"
            )
        limit = self._traversal_limit(max_nodes)
        seen: set[bytes] = set()
        queue: deque[bytes] = deque(self._children.get(artifact_id, ()))
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            if len(seen) > limit:
                raise LineageResourceLimitError(
                    "descendant traversal exceeds max_nodes"
                )
            queue.extend(self._children.get(current, ()))
        return tuple(sorted(seen))

    def explain_path(
        self,
        ancestor_id: bytes,
        descendant_id: bytes,
        *,
        max_nodes: int | None = None,
    ) -> tuple[bytes, ...] | None:
        """Return the deterministic shortest parent-to-child path, if any."""
        _validate_id("ancestor_id", ancestor_id)
        _validate_id("descendant_id", descendant_id)
        if not self._known(ancestor_id):
            raise LineageUnknownArtifactError(
                f"ancestor ArtifactId is outside lineage snapshot: {ancestor_id.hex()}"
            )
        if not self._known(descendant_id):
            raise LineageUnknownArtifactError(
                f"descendant ArtifactId is outside lineage snapshot: {descendant_id.hex()}"
            )
        if ancestor_id == descendant_id:
            return (ancestor_id,)

        limit = self._traversal_limit(max_nodes)
        predecessor: dict[bytes, bytes | None] = {ancestor_id: None}
        queue: deque[bytes] = deque((ancestor_id,))
        while queue:
            current = queue.popleft()
            for child in self._children.get(current, ()):
                if child in predecessor:
                    continue
                predecessor[child] = current
                if len(predecessor) - 1 > limit:
                    raise LineageResourceLimitError(
                        "path traversal exceeds max_nodes"
                    )
                if child == descendant_id:
                    path = [child]
                    cursor = current
                    while cursor is not None:
                        path.append(cursor)
                        cursor = predecessor[cursor]
                    path.reverse()
                    return tuple(path)
                queue.append(child)
        return None


@dataclass(frozen=True)
class LineageBuildResultV1:
    inspection: LineageInspectionV1
    graph: ArtifactLineageGraphV1 | None

    @property
    def accepted(self) -> bool:
        return self.inspection.accepted

    def require_graph(self) -> ArtifactLineageGraphV1:
        if self.graph is None:
            if self.inspection.cycle_path:
                raise LineageCycleError(self.inspection.cycle_path)
            raise LineageError(
                self.inspection.reason or "lineage snapshot was rejected"
            )
        return self.graph


def build_lineage_graph_v1(
    nodes: Iterable[LineageNodeV1],
    *,
    parent_policy: ParentResolutionPolicyV1,
    external_parent_ids: Iterable[bytes] = (),
    cycle_policy: LineageCyclePolicyV1 = LineageCyclePolicyV1.REJECT,
    limits: LineageResourceLimitsV1 | None = None,
) -> LineageBuildResultV1:
    """Validate identity projections and build an accepted deterministic DAG."""
    if not isinstance(parent_policy, ParentResolutionPolicyV1):
        raise TypeError("parent_policy must be ParentResolutionPolicyV1")
    if not isinstance(cycle_policy, LineageCyclePolicyV1):
        raise TypeError("cycle_policy must be LineageCyclePolicyV1")
    limits = LineageResourceLimitsV1() if limits is None else limits
    if not isinstance(limits, LineageResourceLimitsV1):
        raise TypeError("limits must be LineageResourceLimitsV1")

    values: list[LineageNodeV1] = []
    for node in nodes:
        if not isinstance(node, LineageNodeV1):
            raise TypeError("nodes must contain only LineageNodeV1 values")
        values.append(node)
        if len(values) > limits.max_artifacts:
            raise LineageResourceLimitError("lineage exceeds max_artifacts")

    parent_map: dict[bytes, tuple[bytes, ...]] = {}
    edge_count = 0
    for node in values:
        if node.artifact_id in parent_map:
            raise ValueError("duplicate ArtifactId in lineage input")
        parent_map[node.artifact_id] = node.parent_artifact_ids
        edge_count += len(node.parent_artifact_ids)
        if edge_count > limits.max_edges:
            raise LineageResourceLimitError("lineage exceeds max_edges")

    stored = frozenset(parent_map)
    declared_external = _canonical_id_tuple(
        "external parent ArtifactId",
        external_parent_ids,
        max_items=limits.max_edges,
    )
    missing, external, unresolved = _resolve_missing(
        stored=stored,
        parent_map=parent_map,
        parent_policy=parent_policy,
        declared_external_ids=declared_external,
    )
    topological, cycle = _topological_or_cycle(parent_map)
    if cycle:
        inspection = LineageInspectionV1(
            accepted=False,
            parent_policy=parent_policy,
            cycle_policy=cycle_policy,
            stored_artifact_ids=tuple(sorted(stored)),
            external_parent_ids=external,
            unresolved_parent_ids=unresolved,
            missing_parent_ids=missing,
            cycle_path=cycle,
            reason="stored lineage contains a directed cycle",
        )
        if cycle_policy is LineageCyclePolicyV1.REJECT:
            raise LineageCycleError(cycle)
        return LineageBuildResultV1(inspection, None)

    inspection = LineageInspectionV1(
        accepted=True,
        parent_policy=parent_policy,
        cycle_policy=cycle_policy,
        stored_artifact_ids=tuple(sorted(stored)),
        external_parent_ids=external,
        unresolved_parent_ids=unresolved,
        missing_parent_ids=missing,
    )
    graph = ArtifactLineageGraphV1(
        parent_map=parent_map,
        external_parent_ids=external,
        unresolved_parent_ids=unresolved,
        parent_policy=parent_policy,
        topological_order=topological,
        limits=limits,
    )
    return LineageBuildResultV1(inspection, graph)


def lineage_from_artifacts_v1(
    artifacts: Iterable[SigmaArtifactV1],
    *,
    parent_policy: ParentResolutionPolicyV1,
    external_parent_ids: Iterable[bytes] = (),
    cycle_policy: LineageCyclePolicyV1 = LineageCyclePolicyV1.REJECT,
    limits: LineageResourceLimitsV1 | None = None,
) -> LineageBuildResultV1:
    def nodes() -> Iterable[LineageNodeV1]:
        for artifact in artifacts:
            if not isinstance(artifact, SigmaArtifactV1):
                raise TypeError("artifacts must contain only SigmaArtifactV1 values")
            yield LineageNodeV1.from_artifact(artifact)

    return build_lineage_graph_v1(
        nodes(),
        parent_policy=parent_policy,
        external_parent_ids=external_parent_ids,
        cycle_policy=cycle_policy,
        limits=limits,
    )


def lineage_from_store_v1(
    store: LocalArtifactStoreV1,
    *,
    parent_policy: ParentResolutionPolicyV1,
    external_parent_ids: Iterable[bytes] = (),
    cycle_policy: LineageCyclePolicyV1 = LineageCyclePolicyV1.REJECT,
    limits: LineageResourceLimitsV1 | None = None,
) -> LineageBuildResultV1:
    """Build a bounded snapshot from canonical store bytes, not SQLite edges alone."""
    if not isinstance(store, LocalArtifactStoreV1):
        raise TypeError("store must be LocalArtifactStoreV1")
    limits = LineageResourceLimitsV1() if limits is None else limits
    if not isinstance(limits, LineageResourceLimitsV1):
        raise TypeError("limits must be LineageResourceLimitsV1")

    try:
        payloads = store._lineage_snapshot_wires(
            max_artifacts=limits.max_artifacts,
            max_edges=limits.max_edges,
            max_total_wire_bytes=limits.max_total_artifact_wire_bytes,
        )
    except ArtifactStoreCorruptionError:
        raise
    except ArtifactStoreError as exc:
        raise LineageResourceLimitError(str(exc)) from exc

    artifacts = tuple(SigmaArtifactV1.from_bytes(payload) for payload in payloads)

    return lineage_from_artifacts_v1(
        artifacts,
        parent_policy=parent_policy,
        external_parent_ids=external_parent_ids,
        cycle_policy=cycle_policy,
        limits=limits,
    )


__all__ = [
    "ArtifactLineageGraphV1",
    "LineageBuildResultV1",
    "LineageCycleError",
    "LineageCyclePolicyV1",
    "LineageError",
    "LineageIdStatusV1",
    "LineageInspectionV1",
    "LineageNodeV1",
    "LineageParentResolutionError",
    "LineageResourceLimitError",
    "LineageResourceLimitsV1",
    "LineageUnknownArtifactError",
    "ParentResolutionPolicyV1",
    "build_lineage_graph_v1",
    "lineage_from_artifacts_v1",
    "lineage_from_store_v1",
]
