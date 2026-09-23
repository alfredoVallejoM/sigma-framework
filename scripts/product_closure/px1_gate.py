"""Reproducible PX1 closure gate for the local Artifact CAS/store."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import sigma.artifact.store as store_module
from sigma.artifact import (
    ArtifactProfileV1,
    ArtifactStoreConflictError,
    ArtifactStoreIdentityError,
    LocalArtifactStoreV1,
    create_artifact_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import TrajectoryAuditModeV3, audit_from_evaluation_v3
from sigma.tree import ManifestV1, build_persistent_index, build_tree
from sigma.v3 import evaluate_v3

MIN_STORE_CASES = 300
MIN_IDEMPOTENCY_CASES = 200
MIN_WRONG_KEY_CASES = 200
MIN_CRASH_CASES = 90
MIN_GC_GRAPHS = 120
CONCURRENT_PUTS = 64


def _tree_artifact(
    data: bytes,
    *,
    parents: tuple[bytes, ...] = (),
    manifest: ManifestV1 | None = None,
):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(data),
        manifest=manifest,
        parent_artifact_ids=parents,
    )


def _reachable(
    roots: tuple[bytes, ...],
    parents_by_child: dict[bytes, tuple[bytes, ...]],
    stored: set[bytes],
) -> set[bytes]:
    result = set(roots)
    stack = list(roots)
    while stack:
        child = stack.pop()
        for parent in parents_by_child.get(child, ()):
            if parent in stored and parent not in result:
                result.add(parent)
                stack.append(parent)
    return result


def _dual_audit_conflict(store: LocalArtifactStoreV1) -> bool:
    message = b"px1-audit-envelope-conflict"
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"px1",
        challenge=b"store",
        application_context=b"gate/px1",
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    digest = digest_from_evaluation_v3(evaluation)
    compact = audit_from_evaluation_v3(
        evaluation,
        mode=TrajectoryAuditModeV3.COMPACT,
    )
    full = audit_from_evaluation_v3(
        evaluation,
        mode=TrajectoryAuditModeV3.FULL,
    )
    common = dict(
        profile=ArtifactProfileV1.DUAL,
        tree_root=build_tree(message),
        trajectory_digest=digest,
    )
    compact_artifact = create_artifact_v1(
        **common,
        trajectory_audit=compact,
    )
    full_artifact = create_artifact_v1(
        **common,
        trajectory_audit=full,
    )
    if compact_artifact.artifact_id != full_artifact.artifact_id:
        raise AssertionError("SA0 auxiliary audit unexpectedly changed ArtifactId")
    if compact_artifact.to_bytes() == full_artifact.to_bytes():
        raise AssertionError("PX1 conflict fixture did not create distinct envelopes")

    store.put_artifact(compact_artifact)
    try:
        store.put_artifact(full_artifact)
    except ArtifactStoreConflictError:
        pass
    else:
        raise AssertionError("PX1 silently overwrote same-ArtifactId alternate envelope")

    attached = store.attach_evidence(
        full_artifact.artifact_id,
        "trajectory-audit-v3",
        full.to_bytes(),
    )
    if store.get_evidence(full_artifact.artifact_id, attached.object_id) != full.to_bytes():
        raise AssertionError("PX1 auxiliary evidence round-trip diverged")
    if store.get_artifact_bytes(compact_artifact.artifact_id) != compact_artifact.to_bytes():
        raise AssertionError("PX1 alternate evidence changed authoritative envelope")
    return True


def run_gate(
    *,
    store_cases: int,
    idempotency_cases: int,
    wrong_key_cases: int,
    crash_cases: int,
    gc_graphs: int,
) -> dict[str, object]:
    if store_cases < MIN_STORE_CASES:
        raise ValueError("PX1 store campaign too small")
    if idempotency_cases < MIN_IDEMPOTENCY_CASES:
        raise ValueError("PX1 idempotency campaign too small")
    if wrong_key_cases < MIN_WRONG_KEY_CASES:
        raise ValueError("PX1 wrong-key campaign too small")
    if crash_cases < MIN_CRASH_CASES:
        raise ValueError("PX1 crash campaign too small")
    if gc_graphs < MIN_GC_GRAPHS:
        raise ValueError("PX1 GC campaign too small")

    rng = random.Random(0x50583147415445)
    artifact_stream = hashlib.sha256()
    gc_stream = hashlib.sha256()
    exact_roundtrips = 0
    idempotent_reuses = 0
    wrong_key_rejections = 0
    crash_invisible = 0
    crash_recoveries = 0
    gc_reachable_checked = 0
    gc_removed_checked = 0

    with tempfile.TemporaryDirectory(prefix="sigma-px1-store-") as temp:
        store = LocalArtifactStoreV1(Path(temp) / "cas")

        artifacts = []
        for case in range(store_cases):
            size = rng.randrange(0, 4 * 65_536 + 257)
            data = rng.randbytes(size)
            parents = ()
            if artifacts and case % 3 == 0:
                sample = artifacts[max(0, len(artifacts) - 3) :]
                parents = tuple(sorted(item.artifact_id for item in sample[:2]))
            artifact = _tree_artifact(data, parents=parents)
            result = store.put_artifact_bytes(
                artifact.to_bytes(),
                expected_artifact_id=artifact.artifact_id,
            )
            if not result.created:
                raise AssertionError(f"unexpected PX1 duplicate at store case {case}")
            recovered = store.get_artifact_bytes(artifact.artifact_id)
            if recovered != artifact.to_bytes():
                raise AssertionError(f"PX1 byte round-trip divergence at case {case}")
            if not store.verify_artifact(artifact.artifact_id):
                raise AssertionError(f"PX1 verification failed at case {case}")
            artifact_stream.update(
                artifact.artifact_id + hashlib.sha256(recovered).digest()
            )
            artifacts.append(artifact)
            exact_roundtrips += 1

        for case in range(idempotency_cases):
            artifact = artifacts[case % len(artifacts)]
            result = store.put_artifact(artifact)
            if result.created or result.object_id != artifact.artifact_id:
                raise AssertionError(f"PX1 idempotent put failed at case {case}")
            idempotent_reuses += 1

        for case in range(wrong_key_cases):
            artifact = artifacts[case % len(artifacts)]
            wrong = bytearray(artifact.artifact_id)
            wrong[case % 32] ^= 1
            try:
                store.put_artifact_bytes(
                    artifact.to_bytes(),
                    expected_artifact_id=bytes(wrong),
                )
            except ArtifactStoreIdentityError:
                wrong_key_rejections += 1
            else:
                raise AssertionError(f"PX1 wrong-key put accepted at case {case}")

        alternate_envelope_conflict = _dual_audit_conflict(store)

        concurrent_artifact = _tree_artifact(rng.randbytes(3 * 65_536 + 17))

        def concurrent_put(_index: int):
            return store.put_artifact(concurrent_artifact)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(concurrent_put, range(CONCURRENT_PUTS))
            )
        if sum(item.created for item in results) != 1:
            raise AssertionError("PX1 concurrent identical put created more than once")
        if any(item.object_id != concurrent_artifact.artifact_id for item in results):
            raise AssertionError("PX1 concurrent put returned inconsistent ArtifactIds")

    for case in range(crash_cases):
        with tempfile.TemporaryDirectory(prefix=f"sigma-px1-crash-{case}-") as temp:
            root = Path(temp) / "cas"
            artifact = _tree_artifact(rng.randbytes(rng.randrange(1, 65_537)))
            mode = case % 3

            if mode in (0, 2):
                point = (
                    "artifact_publish:before_replace"
                    if mode == 0
                    else "artifact_publish:before_commit"
                )
                fired = False

                def injector(observed: str) -> None:
                    nonlocal fired
                    if not fired and observed == point:
                        fired = True
                        raise RuntimeError("PX1 injected publication crash")

                crash_store = LocalArtifactStoreV1(
                    root,
                    _failure_injector=injector,
                )
                try:
                    crash_store.put_artifact(artifact)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("PX1 injected crash did not abort put")
            else:
                crash_store = LocalArtifactStoreV1(root)
                original_replace = store_module.os.replace

                def fail_replace(src, dst):
                    raise OSError("PX1 injected rename failure")

                store_module.os.replace = fail_replace
                try:
                    try:
                        crash_store.put_artifact(artifact)
                    except OSError:
                        pass
                    else:
                        raise AssertionError("PX1 injected rename failure did not abort put")
                finally:
                    store_module.os.replace = original_replace

            reopened = LocalArtifactStoreV1(root)
            if reopened.has_artifact(artifact.artifact_id):
                raise AssertionError("PX1 interrupted artifact became visible")
            crash_invisible += 1
            recovery = reopened.put_artifact(artifact)
            if not recovery.created:
                raise AssertionError("PX1 interrupted artifact was not recoverable")
            if reopened.get_artifact_bytes(artifact.artifact_id) != artifact.to_bytes():
                raise AssertionError("PX1 recovery changed artifact bytes")
            crash_recoveries += 1

    for graph_index in range(gc_graphs):
        with tempfile.TemporaryDirectory(prefix=f"sigma-px1-gc-{graph_index}-") as temp:
            store = LocalArtifactStoreV1(Path(temp) / "cas")
            node_count = rng.randrange(8, 33)
            nodes = []
            parent_map: dict[bytes, tuple[bytes, ...]] = {}

            for node_index in range(node_count):
                available = nodes[:node_index]
                max_parent_count = min(3, len(available))
                parent_count = rng.randrange(max_parent_count + 1)
                selected = (
                    rng.sample(available, parent_count)
                    if parent_count
                    else []
                )
                parents = tuple(sorted(item.artifact_id for item in selected))
                payload = (
                    graph_index.to_bytes(4, "big")
                    + node_index.to_bytes(4, "big")
                    + rng.randbytes(rng.randrange(0, 2049))
                )
                artifact = _tree_artifact(payload, parents=parents)
                nodes.append(artifact)
                parent_map[artifact.artifact_id] = parents
                store.put_artifact(artifact)
                if node_index % 4 == 0:
                    store.put_tree_index(build_persistent_index(payload))

            root_count = rng.randrange(1, min(4, node_count) + 1)
            roots = tuple(
                item.artifact_id for item in rng.sample(nodes, root_count)
            )
            stored = {item.artifact_id for item in nodes}
            expected = _reachable(roots, parent_map, stored)
            result = store.garbage_collect(
                roots,
                max_artifacts=node_count + 1,
                max_edges=sum(len(value) for value in parent_map.values()) + 1,
            )
            if result.reachable_artifacts != len(expected):
                raise AssertionError("PX1 GC reachable count diverged from oracle")
            for artifact in nodes:
                observed = store.has_artifact(artifact.artifact_id)
                should_survive = artifact.artifact_id in expected
                if observed != should_survive:
                    raise AssertionError(
                        f"PX1 GC reachability divergence graph={graph_index}"
                    )
                if should_survive:
                    if store.get_artifact(artifact.artifact_id) != artifact:
                        raise AssertionError("PX1 GC changed reachable artifact")
                    gc_reachable_checked += 1
                else:
                    gc_removed_checked += 1
            gc_stream.update(
                hashlib.sha256(b"".join(sorted(expected))).digest()
                + result.removed_artifacts.to_bytes(4, "big")
            )

    return {
        "schema": "sigma-px1-local-artifact-store-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "store_roundtrip_cases": exact_roundtrips,
        "idempotent_reuse_cases": idempotent_reuses,
        "wrong_key_cases": wrong_key_cases,
        "wrong_key_rejections": wrong_key_rejections,
        "concurrent_identical_puts": CONCURRENT_PUTS,
        "alternate_envelope_conflict_rejected": alternate_envelope_conflict,
        "crash_cases": crash_cases,
        "crash_invisible_cases": crash_invisible,
        "crash_recovery_cases": crash_recoveries,
        "gc_graphs": gc_graphs,
        "gc_reachable_artifacts_checked": gc_reachable_checked,
        "gc_removed_artifacts_checked": gc_removed_checked,
        "artifact_stream_sha256": artifact_stream.hexdigest(),
        "gc_stream_sha256": gc_stream.hexdigest(),
        "sqlite_is_identity_authority": False,
        "filesystem_blob_is_canonical_wire_authority": True,
        "tree_index_cache_part_of_artifact_identity": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store-cases", type=int, default=MIN_STORE_CASES)
    parser.add_argument(
        "--idempotency-cases",
        type=int,
        default=MIN_IDEMPOTENCY_CASES,
    )
    parser.add_argument(
        "--wrong-key-cases",
        type=int,
        default=MIN_WRONG_KEY_CASES,
    )
    parser.add_argument("--crash-cases", type=int, default=MIN_CRASH_CASES)
    parser.add_argument("--gc-graphs", type=int, default=MIN_GC_GRAPHS)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        store_cases=args.store_cases,
        idempotency_cases=args.idempotency_cases,
        wrong_key_cases=args.wrong_key_cases,
        crash_cases=args.crash_cases,
        gc_graphs=args.gc_graphs,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
