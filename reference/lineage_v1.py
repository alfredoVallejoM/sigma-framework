"""Stdlib-only PX2 lineage oracle used by differential closure tests."""

from __future__ import annotations

import heapq
from collections import deque
from typing import Mapping


def _children(parent_map: Mapping[bytes, tuple[bytes, ...]]) -> dict[bytes, tuple[bytes, ...]]:
    out: dict[bytes, list[bytes]] = {}
    for child, parents in parent_map.items():
        for parent in parents:
            out.setdefault(parent, []).append(child)
    return {key: tuple(sorted(value)) for key, value in out.items()}


def roots(parent_map: Mapping[bytes, tuple[bytes, ...]]) -> tuple[bytes, ...]:
    return tuple(sorted(key for key, parents in parent_map.items() if not parents))


def topological_order(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
) -> tuple[bytes, ...]:
    stored = set(parent_map)
    reverse = _children(parent_map)
    indegree = {
        child: sum(parent in stored for parent in parents)
        for child, parents in parent_map.items()
    }
    heap = [child for child, degree in indegree.items() if degree == 0]
    heapq.heapify(heap)
    order: list[bytes] = []
    while heap:
        current = heapq.heappop(heap)
        order.append(current)
        for child in reverse.get(current, ()):
            if child not in stored:
                continue
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(heap, child)
    if len(order) != len(parent_map):
        raise ValueError("cycle")
    return tuple(order)


def ancestors(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
    artifact_id: bytes,
) -> tuple[bytes, ...]:
    seen: set[bytes] = set()
    queue: deque[bytes] = deque(parent_map.get(artifact_id, ()))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        if current in parent_map:
            queue.extend(parent_map[current])
    return tuple(sorted(seen))


def descendants(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
    artifact_id: bytes,
) -> tuple[bytes, ...]:
    reverse = _children(parent_map)
    seen: set[bytes] = set()
    queue: deque[bytes] = deque(reverse.get(artifact_id, ()))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        queue.extend(reverse.get(current, ()))
    return tuple(sorted(seen))


def explain_path(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
    ancestor_id: bytes,
    descendant_id: bytes,
) -> tuple[bytes, ...] | None:
    if ancestor_id == descendant_id:
        return (ancestor_id,)
    reverse = _children(parent_map)
    predecessor: dict[bytes, bytes | None] = {ancestor_id: None}
    queue: deque[bytes] = deque((ancestor_id,))
    while queue:
        current = queue.popleft()
        for child in reverse.get(current, ()):
            if child in predecessor:
                continue
            predecessor[child] = current
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


def missing_parents(
    parent_map: Mapping[bytes, tuple[bytes, ...]],
) -> tuple[bytes, ...]:
    stored = set(parent_map)
    return tuple(
        sorted(
            {
                parent
                for parents in parent_map.values()
                for parent in parents
                if parent not in stored
            }
        )
    )
