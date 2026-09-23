from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import sigma.artifact.store as store_module
from sigma.artifact import (
    ArtifactProfileV1,
    ArtifactStoreConflictError,
    ArtifactStoreCorruptionError,
    ArtifactStoreIdentityError,
    ArtifactStoreNotFound,
    LocalArtifactStoreV1,
    SigmaArtifactV1,
    create_artifact_v1,
    manifest_identity_v1,
)
from sigma.tree import ManifestV1, build_persistent_index, build_tree


def _artifact(
    data: bytes,
    *,
    parents: tuple[bytes, ...] = (),
    manifest: ManifestV1 | None = None,
) -> SigmaArtifactV1:
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(data),
        manifest=manifest,
        parent_artifact_ids=parents,
    )


def test_px1_put_get_recomputes_id_and_preserves_exact_wire(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _artifact(b"px1-roundtrip")
    wire = artifact.to_bytes()

    first = store.put_artifact_bytes(wire, expected_artifact_id=artifact.artifact_id)
    second = store.put_artifact(artifact)

    assert first.object_id == artifact.artifact_id
    assert first.created
    assert second.object_id == artifact.artifact_id
    assert not second.created
    assert store.has_artifact(artifact.artifact_id)
    assert store.get_artifact_bytes(artifact.artifact_id) == wire
    assert store.get_artifact(artifact.artifact_id) == artifact
    assert store.verify_artifact(artifact.artifact_id)

    with pytest.raises(ArtifactStoreIdentityError, match="expected ArtifactId"):
        store.put_artifact_bytes(wire, expected_artifact_id=b"\xff" * 32)

    mutated = bytearray(wire)
    mutated[20] ^= 1
    with pytest.raises(ValueError):
        store.put_artifact_bytes(bytes(mutated))

    assert store.get_artifact_bytes(artifact.artifact_id) == wire


def test_px1_concurrent_identical_put_is_idempotent(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _artifact(b"concurrent-idempotency" * 4096)

    def put_once(_index: int):
        return store.put_artifact(artifact)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(put_once, range(32)))

    assert sum(result.created for result in results) == 1
    assert {result.object_id for result in results} == {artifact.artifact_id}
    assert store.get_artifact(artifact.artifact_id) == artifact


def test_px1_crash_after_blob_replace_is_not_visible_and_is_recoverable(tmp_path: Path):
    fail = True

    def injector(point: str) -> None:
        nonlocal fail
        if fail and point == "artifact_publish:after_replace":
            fail = False
            raise RuntimeError("injected crash after replace")

    root = tmp_path / "store"
    artifact = _artifact(b"crash-recovery")
    store = LocalArtifactStoreV1(root, _failure_injector=injector)

    with pytest.raises(RuntimeError, match="injected crash"):
        store.put_artifact(artifact)

    assert not store.has_artifact(artifact.artifact_id)
    with pytest.raises(ArtifactStoreNotFound):
        store.get_artifact(artifact.artifact_id)

    reopened = LocalArtifactStoreV1(root)
    recovered = reopened.put_artifact(artifact)
    assert recovered.created
    assert reopened.get_artifact(artifact.artifact_id) == artifact


def test_px1_replace_failure_leaves_no_visible_metadata(tmp_path: Path, monkeypatch):
    root = tmp_path / "store"
    store = LocalArtifactStoreV1(root)
    artifact = _artifact(b"rename-failure")

    def fail_replace(src, dst):
        raise OSError("injected replace failure")

    monkeypatch.setattr(store_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected replace"):
        store.put_artifact(artifact)

    assert not store.has_artifact(artifact.artifact_id)
    assert not list((root / "objects" / "artifacts").rglob("*.tmp"))
    assert not list((root / "objects" / "artifacts").rglob("*.sigart"))


def test_px1_failure_before_metadata_commit_is_not_visible(tmp_path: Path):
    def injector(point: str) -> None:
        if point == "artifact_publish:before_commit":
            raise RuntimeError("injected precommit crash")

    root = tmp_path / "store"
    artifact = _artifact(b"metadata-crash")
    store = LocalArtifactStoreV1(root, _failure_injector=injector)
    with pytest.raises(RuntimeError, match="precommit"):
        store.put_artifact(artifact)

    assert not store.has_artifact(artifact.artifact_id)

    recovered = LocalArtifactStoreV1(root).put_artifact(artifact)
    assert recovered.created


def test_px1_parent_child_queries_and_safe_delete(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    parent = _artifact(b"parent")
    child = _artifact(b"child", parents=(parent.artifact_id,))

    store.put_artifact(child)
    store.put_artifact(parent)

    assert store.parents(child.artifact_id) == (parent.artifact_id,)
    assert store.children(parent.artifact_id) == (child.artifact_id,)

    with pytest.raises(ArtifactStoreConflictError, match="referenced"):
        store.delete_artifact(parent.artifact_id)
    assert store.delete_artifact(parent.artifact_id, force=True)
    assert store.parents(child.artifact_id) == (parent.artifact_id,)
    assert not store.has_artifact(parent.artifact_id)


def test_px1_manifest_tree_index_and_evidence_are_separate_from_artifact_id(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    data = b"auxiliary-surfaces" * 1000
    manifest = ManifestV1()
    artifact = _artifact(data, manifest=manifest)
    original_id = artifact.artifact_id

    manifest_result = store.put_manifest(manifest)
    assert manifest_result.object_id == manifest_identity_v1(manifest)
    assert store.get_manifest(manifest_result.object_id) == manifest

    index = build_persistent_index(data)
    cache_result = store.put_tree_index(index)
    restored = store.get_tree_index(index.root.to_bytes())
    assert restored.root == index.root
    assert restored.source_hint is None

    store.put_artifact(artifact)
    evidence = store.attach_evidence(
        artifact.artifact_id,
        "trajectory-audit-v3",
        b"auxiliary-evidence",
    )
    assert store.get_evidence(artifact.artifact_id, evidence.object_id) == b"auxiliary-evidence"
    assert store.list_evidence(artifact.artifact_id) == (
        (evidence.object_id, "trajectory-audit-v3"),
    )
    assert store.get_artifact(artifact.artifact_id).artifact_id == original_id
    assert store.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()
    assert cache_result.object_id != original_id


def test_px1_same_artifact_id_different_envelope_is_conflict_not_overwrite(
    tmp_path: Path,
):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _artifact(b"no-overwrite")
    store.put_artifact(artifact)

    path = store._artifact_path(artifact.artifact_id)
    original = path.read_bytes()
    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))

    with pytest.raises((ArtifactStoreConflictError, ArtifactStoreCorruptionError, ValueError)):
        store.put_artifact(artifact)


def test_px1_gc_preserves_transitive_parents_and_reachable_derived_objects(
    tmp_path: Path,
):
    store = LocalArtifactStoreV1(tmp_path / "store")

    manifest_keep = ManifestV1()
    from sigma.tree import ManifestEntryKind, ManifestEntryV1

    dropped_data = b"dropped-manifest-payload"
    dropped_root = build_tree(dropped_data)
    manifest_drop = ManifestV1(
        (
            ManifestEntryV1(
                "drop.bin",
                ManifestEntryKind.FILE,
                len(dropped_data),
                dropped_root,
            ),
        )
    )

    grandparent_data = b"grandparent"
    parent_data = b"parent"
    root_data = b"declared-root"
    orphan_data = b"orphan"

    grandparent = _artifact(grandparent_data)
    parent = _artifact(parent_data, parents=(grandparent.artifact_id,))
    root_artifact = _artifact(
        root_data,
        parents=(parent.artifact_id,),
        manifest=manifest_keep,
    )
    orphan = _artifact(
        orphan_data,
        manifest=manifest_drop,
    )

    for artifact in (root_artifact, orphan, parent, grandparent):
        store.put_artifact(artifact)
        assert store.put_tree_index(
            build_persistent_index(
                {
                    root_artifact.artifact_id: root_data,
                    orphan.artifact_id: orphan_data,
                    parent.artifact_id: parent_data,
                    grandparent.artifact_id: grandparent_data,
                }[artifact.artifact_id]
            )
        ).object_id

    store.put_manifest(manifest_keep)
    dropped_manifest_id = store.put_manifest(manifest_drop).object_id
    orphan_evidence = store.attach_evidence(
        orphan.artifact_id,
        "test-evidence",
        b"remove-me",
    )

    result = store.garbage_collect((root_artifact.artifact_id,))

    assert result.declared_roots == 1
    assert result.reachable_artifacts == 3
    assert result.removed_artifacts == 1
    assert result.removed_manifests == 1
    assert result.removed_tree_indexes == 1
    assert result.removed_evidence == 1
    assert result.reclaimed_payload_bytes > 0

    for artifact in (root_artifact, parent, grandparent):
        assert store.has_artifact(artifact.artifact_id)
        assert store.get_tree_index(artifact.tree_root.to_bytes()).root == artifact.tree_root
    assert not store.has_artifact(orphan.artifact_id)
    with pytest.raises(ArtifactStoreNotFound):
        store.get_manifest(dropped_manifest_id)
    with pytest.raises(ArtifactStoreNotFound):
        store.get_evidence(orphan.artifact_id, orphan_evidence.object_id)


def test_px1_gc_is_bounded_and_missing_roots_fail_closed(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _artifact(b"bounded-gc")
    store.put_artifact(artifact)

    with pytest.raises(ArtifactStoreNotFound, match="declared GC root"):
        store.garbage_collect((b"\xaa" * 32,))
    with pytest.raises(ValueError, match="max_artifacts"):
        store.garbage_collect((artifact.artifact_id,), max_artifacts=0)


def test_px1_list_is_bounded_and_paginated(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifacts = [_artifact(f"item-{index}".encode()) for index in range(7)]
    for artifact in artifacts:
        store.put_artifact(artifact)

    expected = sorted(artifact.artifact_id for artifact in artifacts)
    first = store.list_artifact_ids(limit=3)
    second = store.list_artifact_ids(limit=3, after=first[-1])
    third = store.list_artifact_ids(limit=3, after=second[-1])

    assert list(first + second + third) == expected
    with pytest.raises(ValueError, match="limit"):
        store.list_artifact_ids(limit=0)


def test_px1_external_blob_corruption_fails_closed(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _artifact(b"corrupt-me")
    store.put_artifact(artifact)
    path = store._artifact_path(artifact.artifact_id)
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(bytes(raw))

    assert not store.verify_artifact(artifact.artifact_id)
    with pytest.raises(ArtifactStoreCorruptionError):
        store.get_artifact(artifact.artifact_id)
