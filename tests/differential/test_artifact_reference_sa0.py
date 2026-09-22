from __future__ import annotations

import hashlib
import random

from reference import artifact_v1 as artifact_reference
from sigma.artifact import (
    ArtifactDescriptorV1,
    ArtifactProfileV1,
    create_artifact_v1,
    manifest_identity_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import TrajectoryAuditModeV3, audit_from_evaluation_v3
from sigma.tree import ManifestV1, build_tree
from sigma.v3 import evaluate_v3


def _evaluation(message: bytes, case: int):
    context = SigmaContextV3.for_suite(
        (
            SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
            SuiteIdV3.DEEP_HISTORY_V3,
            SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
        )[case % 3],
        salt=b"sa0-ref" + case.to_bytes(2, "big"),
        challenge=b"artifact",
        application_context=b"tests/differential/sa0",
    )
    return evaluate_v3(context, BytesSource(message))


def test_product_artifact_matches_independent_encoder_random_corpus():
    rng = random.Random(0x53413044494646)

    for case in range(120):
        message = rng.randbytes(rng.randrange(0, 2049))
        evaluation = _evaluation(message, case)
        tree = build_tree(message)
        digest = digest_from_evaluation_v3(evaluation)

        profile = (
            ArtifactProfileV1.TREE,
            ArtifactProfileV1.TRAJECTORY,
            ArtifactProfileV1.DUAL,
        )[case % 3]
        reference_profile = {
            ArtifactProfileV1.TREE: artifact_reference.PROFILE_TREE,
            ArtifactProfileV1.TRAJECTORY: artifact_reference.PROFILE_TRAJECTORY,
            ArtifactProfileV1.DUAL: artifact_reference.PROFILE_DUAL,
        }[profile]
        descriptor = ArtifactDescriptorV1(
            f"artifact-{case:03d}.bin",
            "application/octet-stream",
        )
        parents = tuple(
            sorted(
                {
                    hashlib.sha256(f"parent-{case}-{i}".encode()).digest()
                    for i in range(case % 4)
                }
            )
        )
        manifest = ManifestV1() if case % 5 == 0 else None
        audit = (
            audit_from_evaluation_v3(
                evaluation,
                mode=(
                    TrajectoryAuditModeV3.COMPACT
                    if case % 2
                    else TrajectoryAuditModeV3.FULL
                ),
            )
            if profile is not ArtifactProfileV1.TREE and case % 4 == 0
            else None
        )

        artifact = create_artifact_v1(
            profile,
            descriptor=descriptor,
            tree_root=tree if profile is not ArtifactProfileV1.TRAJECTORY else None,
            trajectory_digest=(
                digest if profile is not ArtifactProfileV1.TREE else None
            ),
            trajectory_audit=audit,
            manifest=manifest,
            parent_artifact_ids=parents,
        )

        descriptor_ref = artifact_reference.descriptor_wire(
            logical_name=descriptor.logical_name,
            media_type=descriptor.media_type,
        )
        manifest_ref = (
            b""
            if manifest is None
            else artifact_reference.manifest_id(manifest.to_bytes())
        )
        identity_ref = artifact_reference.identity_wire(
            profile=reference_profile,
            descriptor=descriptor_ref,
            tree_root=(
                b""
                if profile is ArtifactProfileV1.TRAJECTORY
                else tree.to_bytes()
            ),
            trajectory_digest=(
                b""
                if profile is ArtifactProfileV1.TREE
                else digest.to_bytes()
            ),
            manifest_id=manifest_ref,
            parent_artifact_ids=parents,
        )
        artifact_ref = artifact_reference.artifact_wire(
            identity=identity_ref,
            trajectory_audit=b"" if audit is None else audit.to_bytes(),
        )

        assert descriptor.to_bytes() == descriptor_ref
        assert artifact.identity.to_bytes() == identity_ref
        assert artifact.artifact_id == artifact_reference.artifact_id(identity_ref)
        assert artifact.to_bytes() == artifact_ref

        if manifest is not None:
            assert manifest_identity_v1(manifest) == manifest_ref
