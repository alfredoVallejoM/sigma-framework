from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from sigma.artifact import (
    ArtifactProfileV1,
    ArtifactStoreCorruptionError,
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
    lineage_from_artifacts_v1,
    lineage_from_store_v1,
)
from sigma.tree import build_tree


def _id(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _artifact(
    payload: bytes,
    *,
    parents: tuple[bytes, ...] = (),
):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(payload),
        parent_artifact_ids=parents,
    )


def _diamond_nodes() -> tuple[LineageNodeV1, ...]:
    return (
        LineageNodeV1(_id(1), ()),
        LineageNodeV1(_id(2), (_id(1),)),
        LineageNodeV1(_id(3), (_id(1),)),
        LineageNodeV1(_id(4), (_id(2), _id(3))),
    )


def test_px2_exact_parent_relation_and_deterministic_queries():
    result = build_lineage_graph_v1(
        reversed(_diamond_nodes()),
        parent_policy=ParentResolutionPolicyV1.STRICT,
    )
    graph = result.require_graph()

    assert result.accepted
    assert graph.artifact_ids == (_id(1), _id(2), _id(3), _id(4))
    assert graph.parents(_id(4)) == (_id(2), _id(3))
    assert graph.children(_id(1)) == (_id(2), _id(3))
    assert graph.roots() == (_id(1),)
    assert graph.local_entrypoints() == (_id(1),)
    assert graph.topological_order() == (_id(1), _id(2), _id(3), _id(4))
    assert graph.ancestors(_id(4)) == (_id(1), _id(2), _id(3))
    assert graph.descendants(_id(1)) == (_id(2), _id(3), _id(4))
    assert graph.explain_path(_id(1), _id(4)) == (_id(1), _id(2), _id(4))
    assert graph.explain_path(_id(4), _id(1)) is None


def test_px2_artifact_builder_uses_identity_bound_parents_exactly():
    root = _artifact(b"root")
    left = _artifact(b"left", parents=(root.artifact_id,))
    right = _artifact(b"right", parents=(root.artifact_id,))
    leaf = _artifact(
        b"leaf",
        parents=tuple(sorted((left.artifact_id, right.artifact_id))),
    )

    graph = lineage_from_artifacts_v1(
        (leaf, right, root, left),
        parent_policy=ParentResolutionPolicyV1.STRICT,
    ).require_graph()

    assert graph.parents(root.artifact_id) == root.parent_artifact_ids
    assert graph.parents(left.artifact_id) == left.parent_artifact_ids
    assert graph.parents(right.artifact_id) == right.parent_artifact_ids
    assert graph.parents(leaf.artifact_id) == leaf.parent_artifact_ids
    assert graph.children(root.artifact_id) == tuple(
        sorted((left.artifact_id, right.artifact_id))
    )


def test_px2_strict_external_and_unresolved_policies_are_distinct():
    external_a = _id(90)
    external_b = _id(91)
    node = LineageNodeV1(_id(10), (external_a, external_b))

    with pytest.raises(LineageParentResolutionError) as strict:
        build_lineage_graph_v1(
            (node,),
            parent_policy=ParentResolutionPolicyV1.STRICT,
        )
    assert strict.value.parent_ids == (external_a, external_b)

    with pytest.raises(LineageParentResolutionError) as incomplete_external:
        build_lineage_graph_v1(
            (node,),
            parent_policy=ParentResolutionPolicyV1.EXTERNAL,
            external_parent_ids=(external_a,),
        )
    assert incomplete_external.value.parent_ids == (external_b,)

    external_graph = build_lineage_graph_v1(
        (node,),
        parent_policy=ParentResolutionPolicyV1.EXTERNAL,
        external_parent_ids=(external_b, external_a),
    ).require_graph()
    assert external_graph.external_parent_ids == (external_a, external_b)
    assert external_graph.unresolved_parent_ids == ()
    assert external_graph.status(external_a) is LineageIdStatusV1.EXTERNAL
    assert external_graph.parents(external_a) == ()
    assert external_graph.children(external_a) == (_id(10),)
    assert external_graph.roots() == ()
    assert external_graph.local_entrypoints() == (_id(10),)

    unresolved_graph = build_lineage_graph_v1(
        (node,),
        parent_policy=ParentResolutionPolicyV1.UNRESOLVED,
        external_parent_ids=(external_a,),
    ).require_graph()
    assert unresolved_graph.external_parent_ids == (external_a,)
    assert unresolved_graph.unresolved_parent_ids == (external_b,)
    assert unresolved_graph.status(external_b) is LineageIdStatusV1.UNRESOLVED
    assert unresolved_graph.ancestors(_id(10)) == (external_a, external_b)


def test_px2_external_declarations_must_be_referenced_and_absent():
    node = LineageNodeV1(_id(1), ())
    with pytest.raises(LineageParentResolutionError, match="stored or unreferenced"):
        build_lineage_graph_v1(
            (node,),
            parent_policy=ParentResolutionPolicyV1.EXTERNAL,
            external_parent_ids=(_id(2),),
        )


def test_px2_cycle_reject_and_report_are_explicit_and_deterministic():
    nodes = (
        LineageNodeV1(_id(1), (_id(3),)),
        LineageNodeV1(_id(2), (_id(1),)),
        LineageNodeV1(_id(3), (_id(2),)),
        LineageNodeV1(_id(4), (_id(3),)),
    )

    with pytest.raises(LineageCycleError) as rejected:
        build_lineage_graph_v1(
            nodes,
            parent_policy=ParentResolutionPolicyV1.STRICT,
            cycle_policy=LineageCyclePolicyV1.REJECT,
        )
    assert rejected.value.cycle_path == (_id(1), _id(2), _id(3), _id(1))

    report = build_lineage_graph_v1(
        reversed(nodes),
        parent_policy=ParentResolutionPolicyV1.STRICT,
        cycle_policy=LineageCyclePolicyV1.REPORT,
    )
    assert not report.accepted
    assert report.graph is None
    assert report.inspection.cycle_path == rejected.value.cycle_path
    with pytest.raises(LineageCycleError):
        report.require_graph()


def test_px2_topological_order_is_parent_before_child_for_every_local_edge():
    graph = build_lineage_graph_v1(
        _diamond_nodes(),
        parent_policy=ParentResolutionPolicyV1.STRICT,
    ).require_graph()
    order = graph.topological_order()
    position = {artifact_id: index for index, artifact_id in enumerate(order)}
    for child in graph.artifact_ids:
        for parent in graph.parents(child):
            assert position[parent] < position[child]


def test_px2_transitive_queries_fail_closed_on_resource_bound():
    chain = tuple(
        LineageNodeV1(
            _id(index),
            () if index == 1 else (_id(index - 1),),
        )
        for index in range(1, 10)
    )
    graph = build_lineage_graph_v1(
        chain,
        parent_policy=ParentResolutionPolicyV1.STRICT,
        limits=LineageResourceLimitsV1(max_traversal_nodes=4),
    ).require_graph()

    with pytest.raises(LineageResourceLimitError, match="ancestor"):
        graph.ancestors(_id(9))
    with pytest.raises(LineageResourceLimitError, match="descendant"):
        graph.descendants(_id(1))
    with pytest.raises(LineageResourceLimitError, match="path"):
        graph.explain_path(_id(1), _id(9))


def test_px2_build_limits_artifacts_and_edges_before_graph_acceptance():
    nodes = _diamond_nodes()
    with pytest.raises(LineageResourceLimitError, match="max_artifacts"):
        build_lineage_graph_v1(
            nodes,
            parent_policy=ParentResolutionPolicyV1.STRICT,
            limits=LineageResourceLimitsV1(max_artifacts=3),
        )
    with pytest.raises(LineageResourceLimitError, match="max_edges"):
        build_lineage_graph_v1(
            nodes,
            parent_policy=ParentResolutionPolicyV1.STRICT,
            limits=LineageResourceLimitsV1(max_edges=2),
        )


def test_px2_store_snapshot_reconstructs_from_canonical_artifact_bytes(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    root = _artifact(b"store-root")
    child = _artifact(b"store-child", parents=(root.artifact_id,))
    store.put_artifact(child)
    store.put_artifact(root)

    graph = lineage_from_store_v1(
        store,
        parent_policy=ParentResolutionPolicyV1.STRICT,
    ).require_graph()
    assert graph.parents(child.artifact_id) == (root.artifact_id,)
    assert graph.children(root.artifact_id) == (child.artifact_id,)


def test_px2_store_snapshot_detects_sql_parent_index_divergence(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    root = _artifact(b"sql-root")
    child = _artifact(b"sql-child", parents=(root.artifact_id,))
    store.put_artifact(root)
    store.put_artifact(child)

    connection = sqlite3.connect(store.database_path)
    try:
        connection.execute(
            "DELETE FROM artifact_parents WHERE child_id=?",
            (child.artifact_id,),
        )
        connection.execute(
            "INSERT INTO artifact_parents(child_id, parent_id) VALUES(?, ?)",
            (child.artifact_id, _id(222)),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ArtifactStoreCorruptionError, match="metadata differs"):
        lineage_from_store_v1(
            store,
            parent_policy=ParentResolutionPolicyV1.UNRESOLVED,
        )


def test_px2_store_wire_budget_is_enforced(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _artifact(b"wire-budget")
    store.put_artifact(artifact)

    with pytest.raises(LineageResourceLimitError, match="wire"):
        lineage_from_store_v1(
            store,
            parent_policy=ParentResolutionPolicyV1.STRICT,
            limits=LineageResourceLimitsV1(max_total_artifact_wire_bytes=1),
        )


def test_px2_unresolved_parent_is_never_silently_dropped():
    missing = hashlib.sha256(b"not-local").digest()
    artifact = _artifact(b"child-of-missing", parents=(missing,))

    result = lineage_from_artifacts_v1(
        (artifact,),
        parent_policy=ParentResolutionPolicyV1.UNRESOLVED,
    )
    graph = result.require_graph()

    assert result.inspection.missing_parent_ids == (missing,)
    assert result.inspection.unresolved_parent_ids == (missing,)
    assert graph.parents(artifact.artifact_id) == (missing,)
    assert graph.children(missing) == (artifact.artifact_id,)
    assert graph.ancestors(artifact.artifact_id) == (missing,)
