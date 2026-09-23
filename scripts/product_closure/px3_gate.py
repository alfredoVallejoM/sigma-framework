"""Reproducible PX3 closure gate for remote artifact storage semantics."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import tempfile
from pathlib import Path

from reference.artifact_v1 import (
    PROFILE_TREE,
    artifact_wire as reference_artifact_wire,
    descriptor_wire as reference_descriptor_wire,
    identity_wire as reference_identity_wire,
)
from scripts.product_closure.px3_fixtures import (
    GateMemoryRemoteBackend,
    GateOciTransport,
    GateS3Client,
    GateStaticMirrorTransport,
)
from sigma.artifact import (
    ArtifactDescriptorV1,
    ArtifactProfileV1,
    HttpReadOnlyMirrorBackendV1,
    OciRegistryBackendV1,
    RemoteArtifactRepositoryV1,
    RemoteIntegrityError,
    RemoteStoreError,
    RemoteTransferPolicyV1,
    RemoteTransferSourceV1,
    RemoteUploadCheckpointV1,
    S3CompatibleBackendV1,
    VerifiedRemoteArtifactCacheV1,
    artifact_remote_key_v1,
    create_artifact_v1,
)
from sigma.artifact.store import LocalArtifactStoreV1
from sigma.tree import build_tree

MIN_ROUNDTRIP_CASES = 300
MIN_RETRY_RESUME_CASES = 200
MIN_CORRUPTION_CASES = 200
MIN_CACHE_CASES = 100
MIN_HTTP_CASES = 80
MIN_S3_CASES = 80
MIN_OCI_CASES = 80


def _artifact(
    rng: random.Random,
    case: int,
    *,
    source_size: int | None = None,
):
    size = (
        rng.randrange(0, 8 * 65_536 + 257)
        if source_size is None
        else source_size
    )
    source = rng.randbytes(size)
    parent_count = rng.randrange(0, 4)
    parents = tuple(
        sorted(
            hashlib.sha256(
                b"PX3-PARENT"
                + case.to_bytes(8, "big")
                + index.to_bytes(2, "big")
            ).digest()
            for index in range(parent_count)
        )
    )
    descriptor = ArtifactDescriptorV1(
        logical_name=f"px3-case-{case}.bin",
        media_type="application/octet-stream",
    )
    artifact = create_artifact_v1(
        ArtifactProfileV1.TREE,
        descriptor=descriptor,
        tree_root=build_tree(source),
        parent_artifact_ids=parents,
    )
    reference_descriptor = reference_descriptor_wire(
        logical_name=descriptor.logical_name,
        media_type=descriptor.media_type,
    )
    reference_identity = reference_identity_wire(
        profile=PROFILE_TREE,
        descriptor=reference_descriptor,
        tree_root=artifact.tree_root.to_bytes(),
        parent_artifact_ids=artifact.parent_artifact_ids,
    )
    expected_wire = reference_artifact_wire(identity=reference_identity)
    if artifact.to_bytes() != expected_wire:
        raise AssertionError("PX3 fixture diverges from independent Artifact V1 oracle")
    return source, artifact, expected_wire


def _new_store(root: Path, name: str) -> LocalArtifactStoreV1:
    return LocalArtifactStoreV1(root / name)


def run_gate(
    *,
    roundtrip_cases: int,
    retry_resume_cases: int,
    corruption_cases: int,
    cache_cases: int,
    http_cases: int,
    s3_cases: int,
    oci_cases: int,
) -> dict[str, object]:
    for name, value, minimum in (
        ("roundtrip", roundtrip_cases, MIN_ROUNDTRIP_CASES),
        ("retry_resume", retry_resume_cases, MIN_RETRY_RESUME_CASES),
        ("corruption", corruption_cases, MIN_CORRUPTION_CASES),
        ("cache", cache_cases, MIN_CACHE_CASES),
        ("http", http_cases, MIN_HTTP_CASES),
        ("s3", s3_cases, MIN_S3_CASES),
        ("oci", oci_cases, MIN_OCI_CASES),
    ):
        if value < minimum:
            raise ValueError(f"PX3 {name} campaign too small")

    rng = random.Random(0x50583347415445)
    roundtrip_stream = hashlib.sha256()
    retry_stream = hashlib.sha256()
    corruption_stream = hashlib.sha256()
    cache_stream = hashlib.sha256()
    backend_stream = hashlib.sha256()

    roundtrips = 0
    duplicate_reuses = 0
    retry_accept_recoveries = 0
    checkpoint_ahead_recoveries = 0
    expired_session_restarts = 0
    download_resumes = 0
    corruption_rejections = 0
    cache_hits = 0
    cache_eviction_refetches = 0
    http_verified = 0
    s3_verified = 0
    oci_verified = 0
    credentials_identity_cases = 0

    with tempfile.TemporaryDirectory(prefix="sigma-px3-gate-") as temp:
        root = Path(temp)

        source_store = _new_store(root, "roundtrip-source")
        destination_store = _new_store(root, "roundtrip-destination")
        backend = GateMemoryRemoteBackend("px3-roundtrip-public")
        source_repo = RemoteArtifactRepositoryV1(
            source_store,
            backend,
            policy=RemoteTransferPolicyV1(chunk_size=47),
        )
        destination_repo = RemoteArtifactRepositoryV1(
            destination_store,
            backend,
            policy=RemoteTransferPolicyV1(chunk_size=31),
        )

        for case in range(roundtrip_cases):
            _, artifact, expected_wire = _artifact(rng, case)
            source_store.put_artifact(artifact)
            pushed = source_repo.push_artifact(artifact.artifact_id)
            key = artifact_remote_key_v1(artifact.artifact_id)
            if backend.objects.get(key) != expected_wire:
                raise AssertionError(f"PX3 remote wire divergence at case {case}")
            repeated = source_repo.push_artifact(artifact.artifact_id)
            if not repeated.remote_reused:
                raise AssertionError(f"PX3 duplicate put not reused at case {case}")
            pulled = destination_repo.pull_artifact(artifact.artifact_id)
            if destination_store.get_artifact_bytes(artifact.artifact_id) != expected_wire:
                raise AssertionError(f"PX3 local/remote byte divergence at case {case}")
            if pulled.source is not RemoteTransferSourceV1.REMOTE:
                raise AssertionError("PX3 fresh destination did not use remote source")
            roundtrip_stream.update(
                artifact.artifact_id
                + hashlib.sha256(expected_wire).digest()
                + pushed.retry_count.to_bytes(4, "big")
            )
            roundtrips += 1
            duplicate_reuses += 1

        for case in range(retry_resume_cases):
            case_root = root / f"retry-{case}"
            local = _new_store(case_root, "source")
            _, artifact, expected_wire = _artifact(
                rng,
                10_000 + case,
                source_size=rng.randrange(1, 4097),
            )
            local.put_artifact(artifact)
            backend = GateMemoryRemoteBackend(f"px3-retry-{case}")
            repo = RemoteArtifactRepositoryV1(
                local,
                backend,
                policy=RemoteTransferPolicyV1(
                    chunk_size=32,
                    max_retries=3,
                    retry_backoff_seconds=0,
                ),
            )
            mode = case % 4
            checkpoint = case_root / "upload.json"

            if mode == 0:
                backend.retryable_accept_offset = 0
                result = repo.push_artifact(artifact.artifact_id)
                if result.retry_count < 1:
                    raise AssertionError("PX3 accepted-response-loss did not retry")
                retry_accept_recoveries += 1
            elif mode == 1:
                backend.fatal_accept_offset = 32
                try:
                    repo.push_artifact(
                        artifact.artifact_id,
                        checkpoint_path=checkpoint,
                    )
                except RemoteStoreError:
                    pass
                else:
                    raise AssertionError("PX3 fatal interruption fixture did not stop")
                record = RemoteUploadCheckpointV1.from_bytes(checkpoint.read_bytes())
                if record.session.accepted_offset != 32:
                    raise AssertionError("PX3 upload checkpoint did not retain safe offset")
                result = repo.push_artifact(
                    artifact.artifact_id,
                    checkpoint_path=checkpoint,
                )
                if result.resumed_from < 64:
                    raise AssertionError(
                        "PX3 did not reconcile provider-ahead upload session"
                    )
                checkpoint_ahead_recoveries += 1
            elif mode == 2:
                backend.fatal_accept_offset = 32
                try:
                    repo.push_artifact(
                        artifact.artifact_id,
                        checkpoint_path=checkpoint,
                    )
                except RemoteStoreError:
                    pass
                else:
                    raise AssertionError("PX3 expiry fixture did not interrupt")
                record = RemoteUploadCheckpointV1.from_bytes(checkpoint.read_bytes())
                backend.sessions.pop(record.session.token, None)
                backend.session_meta.pop(record.session.token, None)
                result = repo.push_artifact(
                    artifact.artifact_id,
                    checkpoint_path=checkpoint,
                )
                if result.resumed_from != 0:
                    raise AssertionError("PX3 expired session did not restart")
                expired_session_restarts += 1
            else:
                key = artifact_remote_key_v1(artifact.artifact_id)
                backend.seed(key, expected_wire)
                destination = _new_store(case_root, "destination")
                pull_repo = RemoteArtifactRepositoryV1(
                    destination,
                    backend,
                    policy=RemoteTransferPolicyV1(chunk_size=32),
                )
                download_checkpoint = case_root / "download.json"
                partial = case_root / "download.part"
                backend.download_fail_offset = 32
                try:
                    pull_repo.pull_artifact(
                        artifact.artifact_id,
                        checkpoint_path=download_checkpoint,
                        partial_path=partial,
                    )
                except RemoteStoreError:
                    pass
                else:
                    raise AssertionError("PX3 download interruption did not stop")
                if destination.has_artifact(artifact.artifact_id):
                    raise AssertionError(
                        "PX3 interrupted download published partial local artifact"
                    )
                result = pull_repo.pull_artifact(
                    artifact.artifact_id,
                    checkpoint_path=download_checkpoint,
                    partial_path=partial,
                )
                if result.resumed_from != 32:
                    raise AssertionError("PX3 download resume offset diverged")
                download_resumes += 1

            if backend.objects.get(artifact_remote_key_v1(artifact.artifact_id)) != expected_wire:
                raise AssertionError("PX3 retry/resume changed remote canonical bytes")
            retry_stream.update(
                artifact.artifact_id
                + mode.to_bytes(1, "big")
                + hashlib.sha256(expected_wire).digest()
            )

        for case in range(corruption_cases):
            case_root = root / f"corrupt-{case}"
            _, artifact, expected_wire = _artifact(
                rng,
                20_000 + case,
                source_size=rng.randrange(0, 8193),
            )
            backend = GateMemoryRemoteBackend(f"px3-corrupt-{case}")
            corrupt = bytearray(expected_wire)
            position = case % len(corrupt)
            corrupt[position] ^= 1 << (case % 8)
            backend.seed(
                artifact_remote_key_v1(artifact.artifact_id),
                bytes(corrupt),
            )
            destination = _new_store(case_root, "destination")
            try:
                RemoteArtifactRepositoryV1(
                    destination,
                    backend,
                    policy=RemoteTransferPolicyV1(chunk_size=29),
                ).pull_artifact(artifact.artifact_id)
            except RemoteIntegrityError:
                corruption_rejections += 1
            else:
                raise AssertionError("PX3 corrupted remote artifact was accepted")
            if destination.has_artifact(artifact.artifact_id):
                raise AssertionError("PX3 corrupt remote artifact reached PX1 publication")
            corruption_stream.update(
                artifact.artifact_id + hashlib.sha256(bytes(corrupt)).digest()
            )

        for case in range(cache_cases):
            case_root = root / f"cache-{case}"
            _, artifact, expected_wire = _artifact(
                rng,
                30_000 + case,
                source_size=rng.randrange(0, 2049),
            )
            backend = GateMemoryRemoteBackend(f"px3-cache-{case}")
            backend.seed(artifact_remote_key_v1(artifact.artifact_id), expected_wire)
            local = _new_store(case_root, "local")
            cache = VerifiedRemoteArtifactCacheV1(case_root / "cache")
            repo = RemoteArtifactRepositoryV1(local, backend, cache=cache)

            first = repo.pull_artifact(artifact.artifact_id)
            if first.source is not RemoteTransferSourceV1.REMOTE:
                raise AssertionError("PX3 first cache case did not fetch remote")
            local.delete_artifact(artifact.artifact_id)
            second = repo.pull_artifact(artifact.artifact_id)
            if second.source is not RemoteTransferSourceV1.VERIFIED_CACHE:
                raise AssertionError("PX3 verified cache was not reused")
            cache_hits += 1

            local.delete_artifact(artifact.artifact_id)
            cache.evict(artifact.artifact_id)
            third = repo.pull_artifact(artifact.artifact_id)
            if third.source is not RemoteTransferSourceV1.REMOTE:
                raise AssertionError("PX3 cache eviction changed remote fallback semantics")
            if local.get_artifact_bytes(artifact.artifact_id) != expected_wire:
                raise AssertionError("PX3 cache eviction changed accepted bytes")
            cache_eviction_refetches += 1
            cache_stream.update(
                artifact.artifact_id + hashlib.sha256(expected_wire).digest()
            )

        for case in range(http_cases):
            case_root = root / f"http-{case}"
            _, artifact, expected_wire = _artifact(
                rng,
                40_000 + case,
                source_size=rng.randrange(0, 4097),
            )
            key = artifact_remote_key_v1(artifact.artifact_id)
            base = "https://mirror.example/"
            objects = {key: expected_wire}
            transport = GateStaticMirrorTransport(
                base,
                objects,
                ignore_range=bool(case % 2),
            )
            backend_a = HttpReadOnlyMirrorBackendV1(
                base,
                transport=transport,
                headers={"Authorization": "Bearer secret-a"},
            )
            backend_b = HttpReadOnlyMirrorBackendV1(
                base,
                transport=transport,
                headers={"Authorization": "Bearer secret-b"},
            )
            if backend_a.fingerprint != backend_b.fingerprint:
                raise AssertionError("PX3 HTTP credentials entered backend fingerprint")
            credentials_identity_cases += 1
            local = _new_store(case_root, "local")
            RemoteArtifactRepositoryV1(
                local,
                backend_a,
                policy=RemoteTransferPolicyV1(chunk_size=23),
            ).pull_artifact(artifact.artifact_id)
            if local.get_artifact_bytes(artifact.artifact_id) != expected_wire:
                raise AssertionError("PX3 HTTP mirror byte divergence")
            http_verified += 1
            backend_stream.update(b"H" + artifact.artifact_id)

        for case in range(s3_cases):
            case_root = root / f"s3-{case}"
            _, artifact, expected_wire = _artifact(
                rng,
                50_000 + case,
                source_size=rng.randrange(0, 4097),
            )
            client = GateS3Client()
            backend_a = S3CompatibleBackendV1(
                client,
                "bucket",
                prefix="sigma-gate",
                endpoint_identity="s3.example",
                minimum_part_size=32,
            )
            backend_b = S3CompatibleBackendV1(
                GateS3Client(),
                "bucket",
                prefix="sigma-gate",
                endpoint_identity="s3.example",
                minimum_part_size=32,
            )
            if backend_a.fingerprint != backend_b.fingerprint:
                raise AssertionError("PX3 S3 client credentials/state entered fingerprint")
            credentials_identity_cases += 1
            source = _new_store(case_root, "source")
            source.put_artifact(artifact)
            RemoteArtifactRepositoryV1(
                source,
                backend_a,
                policy=RemoteTransferPolicyV1(chunk_size=17),
            ).push_artifact(artifact.artifact_id)
            destination = _new_store(case_root, "destination")
            RemoteArtifactRepositoryV1(
                destination,
                backend_a,
                policy=RemoteTransferPolicyV1(chunk_size=19),
            ).pull_artifact(artifact.artifact_id)
            if destination.get_artifact_bytes(artifact.artifact_id) != expected_wire:
                raise AssertionError("PX3 S3 byte divergence")
            s3_verified += 1
            backend_stream.update(b"S" + artifact.artifact_id)

        for case in range(oci_cases):
            case_root = root / f"oci-{case}"
            _, artifact, expected_wire = _artifact(
                rng,
                60_000 + case,
                source_size=rng.randrange(0, 4097),
            )
            transport = GateOciTransport()
            backend_a = OciRegistryBackendV1(
                "https://registry.example/",
                "demo",
                transport=transport,
                headers={"Authorization": "Bearer secret-a"},
            )
            backend_b = OciRegistryBackendV1(
                "https://registry.example/",
                "demo",
                transport=transport,
                headers={"Authorization": "Bearer secret-b"},
            )
            if backend_a.fingerprint != backend_b.fingerprint:
                raise AssertionError("PX3 OCI credentials entered backend fingerprint")
            credentials_identity_cases += 1
            source = _new_store(case_root, "source")
            source.put_artifact(artifact)
            RemoteArtifactRepositoryV1(
                source,
                backend_a,
                policy=RemoteTransferPolicyV1(chunk_size=41),
            ).push_artifact(artifact.artifact_id)
            destination = _new_store(case_root, "destination")
            RemoteArtifactRepositoryV1(
                destination,
                backend_a,
                policy=RemoteTransferPolicyV1(chunk_size=37),
            ).pull_artifact(artifact.artifact_id)
            if destination.get_artifact_bytes(artifact.artifact_id) != expected_wire:
                raise AssertionError("PX3 OCI byte divergence")
            oci_verified += 1
            backend_stream.update(b"O" + artifact.artifact_id)

    return {
        "schema": "sigma-px3-remote-storage-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "roundtrip_cases": roundtrip_cases,
        "roundtrips": roundtrips,
        "duplicate_remote_reuses": duplicate_reuses,
        "retry_resume_cases": retry_resume_cases,
        "retry_accept_recoveries": retry_accept_recoveries,
        "checkpoint_ahead_recoveries": checkpoint_ahead_recoveries,
        "expired_session_restarts": expired_session_restarts,
        "download_resumes": download_resumes,
        "corruption_cases": corruption_cases,
        "corruption_rejections_before_local_publication": corruption_rejections,
        "cache_cases": cache_cases,
        "verified_cache_hits": cache_hits,
        "cache_eviction_refetches": cache_eviction_refetches,
        "http_cases": http_cases,
        "http_verified": http_verified,
        "s3_cases": s3_cases,
        "s3_verified": s3_verified,
        "oci_cases": oci_cases,
        "oci_verified": oci_verified,
        "credentials_identity_cases": credentials_identity_cases,
        "roundtrip_stream_sha256": roundtrip_stream.hexdigest(),
        "retry_stream_sha256": retry_stream.hexdigest(),
        "corruption_stream_sha256": corruption_stream.hexdigest(),
        "cache_stream_sha256": cache_stream.hexdigest(),
        "backend_stream_sha256": backend_stream.hexdigest(),
        "remote_metadata_part_of_artifact_identity": False,
        "credentials_part_of_artifact_identity": False,
        "cache_state_part_of_artifact_identity": False,
        "local_publication_requires_canonical_validation": True,
        "github_actions_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roundtrip-cases", type=int, default=MIN_ROUNDTRIP_CASES)
    parser.add_argument(
        "--retry-resume-cases",
        type=int,
        default=MIN_RETRY_RESUME_CASES,
    )
    parser.add_argument("--corruption-cases", type=int, default=MIN_CORRUPTION_CASES)
    parser.add_argument("--cache-cases", type=int, default=MIN_CACHE_CASES)
    parser.add_argument("--http-cases", type=int, default=MIN_HTTP_CASES)
    parser.add_argument("--s3-cases", type=int, default=MIN_S3_CASES)
    parser.add_argument("--oci-cases", type=int, default=MIN_OCI_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        roundtrip_cases=args.roundtrip_cases,
        retry_resume_cases=args.retry_resume_cases,
        corruption_cases=args.corruption_cases,
        cache_cases=args.cache_cases,
        http_cases=args.http_cases,
        s3_cases=args.s3_cases,
        oci_cases=args.oci_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
