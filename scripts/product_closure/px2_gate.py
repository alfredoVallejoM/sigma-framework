"""Reproducible PX2 closure gate for artifact lineage DAG semantics."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import tempfile
from pathlib import Path

from reference.lineage_v1 import (
    ancestors as reference_ancestors,
    descendants as reference_descendants,
    explain_path as reference_explain_path,
    missing_parents as reference_missing_parents,
    roots as reference_roots,
    topological_order as reference_topological_order,
)
from sigma.artifact import (
    ArtifactLineageGraphV1,
    ArtifactProfileV1,
    LineageCycleError,
    LineageCyclePolicyV1,
    LineageIdStatusV1,
    LineageNodeV1,
    LineageParentResolutionError,
    LineageResourceLimitError,
    LineageResourceLimitsV1,
    LocalArtifactStoreV1,
    ParentResolutionPolicyV1,
    build_lineage_graph_v1,
    create_artifact_v1,
    lineage_from_store_v1,
)
from sigma.tree import build_tree

MIN_DAG_CASES = 300
MIN_QUERY_CASES = 1_000
MIN_BOUNDARY_CASES = 300
MIN_CYCLE_CASES = 200
MIN_STORE_CASES = 80


def _random_id(rng: random.Random, domain: bytes, index: int) -> bytes:
    return hashlib.sha256(
        domain + index.to_bytes(8, "big") + rng.randbytes(16)
    ).digest()


def _tree_artifact(data: bytes, parents: tuple[bytes, ...] = ()):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(data),
        parent_artifact_ids=parents,
    )


def _random_dag(
    rng: random.Random,
    *,
    nodes: int,
    domain: bytes,
) -> tuple[tuple[LineageNodeV1, ...], dict[bytes, tuple[bytes, ...]]]:
    ids = [_random_id(rng, domain, index) for index in range(nodes)]
    values: list[LineageNodeV1] = []
    parent_map: dict[bytes, tuple[bytes, ...]] = {}
    for index, artifact_id in enumerate(ids):
        candidates = ids[:index]
        max_count = min(4, len(candidates))
        count = rng.randrange(max_count + 1)
        parents = tuple(sorted(rng.sample(candidates, count))) if count else ()
        node = LineageNodeV1(artifact_id, parents)
        values.append(node)
        parent_map[artifact_id] = parents
    rng.shuffle(values)
    return tuple(values), parent_map


def _cyclic_nodes(rng: random.Random, case: int) -> tuple[LineageNodeV1, ...]:
    size = rng.randrange(2, 10)
    ids = [
        hashlib.sha256(
            b"PX2-CYCLE"
            + case.to_bytes(4, "big")
            + index.to_bytes(2, "big")
        ).digest()
        for index in range(size)
    ]
    nodes = [
        LineageNodeV1(ids[index], (ids[index - 1],))
        for index in range(size)
    ]
    rng.shuffle(nodes)
    return tuple(nodes)


def run_gate(
    *,
    dag_cases: int,
    query_cases: int,
    boundary_cases: int,
    cycle_cases: int,
    store_cases: int,
) -> dict[str, object]:
    if dag_cases < MIN_DAG_CASES:
        raise ValueError("PX2 DAG campaign too small")
    if query_cases < MIN_QUERY_CASES:
        raise ValueError("PX2 query campaign too small")
    if boundary_cases < MIN_BOUNDARY_CASES:
        raise ValueError("PX2 boundary campaign too small")
    if cycle_cases < MIN_CYCLE_CASES:
        raise ValueError("PX2 cycle campaign too small")
    if store_cases < MIN_STORE_CASES:
        raise ValueError("PX2 store campaign too small")

    rng = random.Random(0x50583247415445)
    graph_stream = hashlib.sha256()
    query_stream = hashlib.sha256()
    boundary_stream = hashlib.sha256()
    cycle_stream = hashlib.sha256()
    store_stream = hashlib.sha256()

    dag_nodes_checked = 0
    dag_edges_checked = 0
    queries_checked = 0
    strict_missing_rejections = 0
    external_acceptances = 0
    unresolved_acceptances = 0
    cycle_rejections = 0
    cycle_reports = 0
    store_artifacts_checked = 0

    graph_fixtures: list[
        tuple[ArtifactLineageGraphV1, dict[bytes, tuple[bytes, ...]]]
    ] = []

    for case in range(dag_cases):
        node_count = rng.randrange(1, 65)
        nodes, parent_map = _random_dag(
            rng,
            nodes=node_count,
            domain=b"PX2-DAG" + case.to_bytes(4, "big"),
        )
        result = build_lineage_graph_v1(
            nodes,
            parent_policy=ParentResolutionPolicyV1.STRICT,
        )
        graph = result.require_graph()

        if graph.artifact_ids != tuple(sorted(parent_map)):
            raise AssertionError(f"PX2 node set divergence at DAG case {case}")
        for artifact_id in graph.artifact_ids:
            if graph.parents(artifact_id) != parent_map[artifact_id]:
                raise AssertionError(
                    f"PX2 identity parent divergence at DAG case {case}"
                )

        expected_roots = reference_roots(parent_map)
        expected_topological = reference_topological_order(parent_map)
        if graph.roots() != expected_roots:
            raise AssertionError(f"PX2 roots divergence at DAG case {case}")
        if graph.topological_order() != expected_topological:
            raise AssertionError(
                f"PX2 topological-order divergence at DAG case {case}"
            )

        dag_nodes_checked += len(parent_map)
        dag_edges_checked += sum(len(value) for value in parent_map.values())
        graph_stream.update(
            hashlib.sha256(b"".join(graph.artifact_ids)).digest()
            + hashlib.sha256(b"".join(graph.topological_order())).digest()
        )
        graph_fixtures.append((graph, parent_map))

    for case in range(query_cases):
        graph, parent_map = graph_fixtures[case % len(graph_fixtures)]
        artifact_ids = tuple(sorted(parent_map))
        target = artifact_ids[rng.randrange(len(artifact_ids))]
        ancestor = artifact_ids[rng.randrange(len(artifact_ids))]

        actual_ancestors = graph.ancestors(target)
        actual_descendants = graph.descendants(ancestor)
        actual_path = graph.explain_path(ancestor, target)

        expected_ancestors = reference_ancestors(parent_map, target)
        expected_descendants = reference_descendants(parent_map, ancestor)
        expected_path = reference_explain_path(parent_map, ancestor, target)
        if actual_ancestors != expected_ancestors:
            raise AssertionError(f"PX2 ancestor divergence at query {case}")
        if actual_descendants != expected_descendants:
            raise AssertionError(f"PX2 descendant divergence at query {case}")
        if actual_path != expected_path:
            raise AssertionError(f"PX2 explain-path divergence at query {case}")

        query_stream.update(
            hashlib.sha256(b"".join(actual_ancestors)).digest()
            + hashlib.sha256(b"".join(actual_descendants)).digest()
            + hashlib.sha256(
                b"" if actual_path is None else b"".join(actual_path)
            ).digest()
        )
        queries_checked += 3

    for case in range(boundary_cases):
        local_id = _random_id(rng, b"PX2-BOUNDARY", case)
        missing_count = rng.randrange(1, 5)
        missing = tuple(
            sorted(
                _random_id(
                    rng,
                    b"PX2-MISSING" + case.to_bytes(4, "big"),
                    index,
                )
                for index in range(missing_count)
            )
        )
        node = LineageNodeV1(local_id, missing)
        parent_map = {local_id: missing}

        if reference_missing_parents(parent_map) != missing:
            raise AssertionError("PX2 boundary oracle fixture mismatch")

        try:
            build_lineage_graph_v1(
                (node,),
                parent_policy=ParentResolutionPolicyV1.STRICT,
            )
        except LineageParentResolutionError as exc:
            if exc.parent_ids != missing:
                raise AssertionError("PX2 STRICT missing-parent report diverged")
            strict_missing_rejections += 1
        else:
            raise AssertionError("PX2 STRICT accepted missing parent")

        external = build_lineage_graph_v1(
            (node,),
            parent_policy=ParentResolutionPolicyV1.EXTERNAL,
            external_parent_ids=missing,
        ).require_graph()
        if external.external_parent_ids != missing:
            raise AssertionError("PX2 EXTERNAL boundary set diverged")
        if external.unresolved_parent_ids:
            raise AssertionError("PX2 EXTERNAL created unresolved boundary")
        for parent in missing:
            if external.status(parent) is not LineageIdStatusV1.EXTERNAL:
                raise AssertionError("PX2 EXTERNAL status divergence")
            if external.children(parent) != (local_id,):
                raise AssertionError("PX2 EXTERNAL reverse edge was dropped")
        external_acceptances += 1

        split = rng.randrange(missing_count + 1)
        declared_external = missing[:split]
        unresolved = build_lineage_graph_v1(
            (node,),
            parent_policy=ParentResolutionPolicyV1.UNRESOLVED,
            external_parent_ids=declared_external,
        ).require_graph()
        expected_unresolved = missing[split:]
        if unresolved.external_parent_ids != declared_external:
            raise AssertionError("PX2 UNRESOLVED external subset diverged")
        if unresolved.unresolved_parent_ids != expected_unresolved:
            raise AssertionError("PX2 unresolved boundary set diverged")
        if unresolved.parents(local_id) != missing:
            raise AssertionError("PX2 unresolved parent IDs were silently dropped")
        unresolved_acceptances += 1

        boundary_stream.update(
            hashlib.sha256(local_id + b"".join(missing)).digest()
        )

    for case in range(cycle_cases):
        nodes = _cyclic_nodes(rng, case)
        try:
            build_lineage_graph_v1(
                nodes,
                parent_policy=ParentResolutionPolicyV1.STRICT,
                cycle_policy=LineageCyclePolicyV1.REJECT,
            )
        except LineageCycleError as exc:
            if not exc.cycle_path or exc.cycle_path[0] != exc.cycle_path[-1]:
                raise AssertionError("PX2 cycle rejection lacks closed witness")
            rejected_cycle = exc.cycle_path
            cycle_rejections += 1
        else:
            raise AssertionError("PX2 REJECT accepted cyclic lineage")

        report = build_lineage_graph_v1(
            reversed(nodes),
            parent_policy=ParentResolutionPolicyV1.STRICT,
            cycle_policy=LineageCyclePolicyV1.REPORT,
        )
        if report.accepted or report.graph is not None:
            raise AssertionError("PX2 REPORT accepted cyclic lineage")
        if report.inspection.cycle_path != rejected_cycle:
            raise AssertionError("PX2 cycle witness is input-order dependent")
        cycle_reports += 1
        cycle_stream.update(hashlib.sha256(b"".join(rejected_cycle)).digest())

    for case in range(store_cases):
        with tempfile.TemporaryDirectory(prefix=f"sigma-px2-{case}-") as temp:
            store = LocalArtifactStoreV1(Path(temp) / "cas")
            count = rng.randrange(2, 24)
            artifacts = []
            parent_map: dict[bytes, tuple[bytes, ...]] = {}

            for index in range(count):
                candidates = artifacts[:]
                max_count = min(3, len(candidates))
                parent_count = rng.randrange(max_count + 1)
                selected = (
                    rng.sample(candidates, parent_count)
                    if parent_count
                    else []
                )
                parents = tuple(
                    sorted(artifact.artifact_id for artifact in selected)
                )
                data = (
                    case.to_bytes(4, "big")
                    + index.to_bytes(4, "big")
                    + rng.randbytes(rng.randrange(0, 1025))
                )
                artifact = _tree_artifact(data, parents)
                artifacts.append(artifact)
                parent_map[artifact.artifact_id] = parents

            shuffled = list(artifacts)
            rng.shuffle(shuffled)
            for artifact in shuffled:
                store.put_artifact(artifact)

            graph = lineage_from_store_v1(
                store,
                parent_policy=ParentResolutionPolicyV1.STRICT,
                limits=LineageResourceLimitsV1(
                    max_artifacts=count + 1,
                    max_edges=sum(len(v) for v in parent_map.values()) + 1,
                    max_total_artifact_wire_bytes=64 * 1024 * 1024,
                    max_traversal_nodes=count + 1,
                ),
            ).require_graph()

            if graph.topological_order() != reference_topological_order(parent_map):
                raise AssertionError(f"PX2 store topology divergence at case {case}")
            for artifact in artifacts:
                if graph.parents(artifact.artifact_id) != artifact.parent_artifact_ids:
                    raise AssertionError(
                        f"PX2 store identity-parent divergence at case {case}"
                    )
                store_artifacts_checked += 1
            store_stream.update(
                hashlib.sha256(b"".join(graph.topological_order())).digest()
            )

    # Explicit bounded-traversal negative check.
    chain = tuple(
        LineageNodeV1(
            index.to_bytes(32, "big"),
            () if index == 1 else ((index - 1).to_bytes(32, "big"),),
        )
        for index in range(1, 12)
    )
    bounded = build_lineage_graph_v1(
        chain,
        parent_policy=ParentResolutionPolicyV1.STRICT,
        limits=LineageResourceLimitsV1(max_traversal_nodes=3),
    ).require_graph()
    try:
        bounded.ancestors((11).to_bytes(32, "big"))
    except LineageResourceLimitError:
        traversal_bound_rejected = True
    else:
        raise AssertionError("PX2 traversal bound did not fail closed")

    return {
        "schema": "sigma-px2-artifact-lineage-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "dag_cases": dag_cases,
        "dag_nodes_checked": dag_nodes_checked,
        "dag_edges_checked": dag_edges_checked,
        "query_cases": query_cases,
        "query_results_checked": queries_checked,
        "boundary_cases": boundary_cases,
        "strict_missing_rejections": strict_missing_rejections,
        "external_acceptances": external_acceptances,
        "unresolved_acceptances": unresolved_acceptances,
        "cycle_cases": cycle_cases,
        "cycle_rejections": cycle_rejections,
        "cycle_reports": cycle_reports,
        "store_cases": store_cases,
        "store_artifacts_checked": store_artifacts_checked,
        "traversal_bound_rejected": traversal_bound_rejected,
        "graph_stream_sha256": graph_stream.hexdigest(),
        "query_stream_sha256": query_stream.hexdigest(),
        "boundary_stream_sha256": boundary_stream.hexdigest(),
        "cycle_stream_sha256": cycle_stream.hexdigest(),
        "store_stream_sha256": store_stream.hexdigest(),
        "sqlite_parent_index_is_lineage_authority": False,
        "artifact_identity_parents_are_lineage_authority": True,
        "accepted_snapshot_allows_local_cycles": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dag-cases", type=int, default=MIN_DAG_CASES)
    parser.add_argument("--query-cases", type=int, default=MIN_QUERY_CASES)
    parser.add_argument("--boundary-cases", type=int, default=MIN_BOUNDARY_CASES)
    parser.add_argument("--cycle-cases", type=int, default=MIN_CYCLE_CASES)
    parser.add_argument("--store-cases", type=int, default=MIN_STORE_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        dag_cases=args.dag_cases,
        query_cases=args.query_cases,
        boundary_cases=args.boundary_cases,
        cycle_cases=args.cycle_cases,
        store_cases=args.store_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
