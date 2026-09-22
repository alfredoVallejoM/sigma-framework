"""Generate/check frozen Sigma Artifact V1 SA0 vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference.artifact_v1 import (
    PROFILE_DUAL,
    PROFILE_TRAJECTORY,
    PROFILE_TREE,
    artifact_wire as reference_artifact_wire,
    descriptor_wire as reference_descriptor_wire,
    identity_wire as reference_identity_wire,
    manifest_id as reference_manifest_id,
)
from sigma.artifact import (
    ArtifactDescriptorV1,
    ArtifactProfileV1,
    create_artifact_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import TrajectoryAuditModeV3, audit_from_evaluation_v3
from sigma.tree import ManifestEntryKind, ManifestEntryV1, ManifestV1, build_tree
from sigma.v3 import evaluate_v3

DEFAULT_OUTPUT = Path("specification/test-vectors/sigma-artifact-v1-sa0.json")


def _evaluation(message: bytes, suite_id: SuiteIdV3, salt: bytes):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=salt,
        challenge=b"sa0-kat",
        application_context=b"scripts/product_closure/generate_sa0_vectors",
    )
    return evaluate_v3(context, BytesSource(message))


def _case(
    *,
    name: str,
    message: bytes,
    suite_id: SuiteIdV3,
    profile: ArtifactProfileV1,
    logical_name: str,
    media_type: str,
    parents: tuple[bytes, ...] = (),
    manifest: ManifestV1 | None = None,
    audit_mode: TrajectoryAuditModeV3 | None = None,
) -> dict[str, object]:
    evaluation = _evaluation(message, suite_id, name.encode())
    tree = build_tree(message)
    digest = digest_from_evaluation_v3(evaluation)
    descriptor = ArtifactDescriptorV1(logical_name, media_type)
    audit = (
        None
        if audit_mode is None
        else audit_from_evaluation_v3(evaluation, mode=audit_mode)
    )
    artifact = create_artifact_v1(
        profile,
        descriptor=descriptor,
        tree_root=tree if profile is not ArtifactProfileV1.TRAJECTORY else None,
        trajectory_digest=digest if profile is not ArtifactProfileV1.TREE else None,
        trajectory_audit=audit,
        manifest=manifest,
        parent_artifact_ids=parents,
    )

    reference_profile = {
        ArtifactProfileV1.TREE: PROFILE_TREE,
        ArtifactProfileV1.TRAJECTORY: PROFILE_TRAJECTORY,
        ArtifactProfileV1.DUAL: PROFILE_DUAL,
    }[profile]
    descriptor_ref = reference_descriptor_wire(
        logical_name=logical_name,
        media_type=media_type,
    )
    manifest_ref = b"" if manifest is None else reference_manifest_id(manifest.to_bytes())
    identity_ref = reference_identity_wire(
        profile=reference_profile,
        descriptor=descriptor_ref,
        tree_root=b"" if profile is ArtifactProfileV1.TRAJECTORY else tree.to_bytes(),
        trajectory_digest=b"" if profile is ArtifactProfileV1.TREE else digest.to_bytes(),
        manifest_id=manifest_ref,
        parent_artifact_ids=parents,
    )
    artifact_ref = reference_artifact_wire(
        identity=identity_ref,
        trajectory_audit=b"" if audit is None else audit.to_bytes(),
    )
    if descriptor.to_bytes() != descriptor_ref:
        raise AssertionError(f"{name}: descriptor reference divergence")
    if artifact.identity.to_bytes() != identity_ref:
        raise AssertionError(f"{name}: identity reference divergence")
    if artifact.to_bytes() != artifact_ref:
        raise AssertionError(f"{name}: artifact reference divergence")

    return {
        "name": name,
        "profile": profile.name,
        "message_length": len(message),
        "suite_id": f"0x{int(suite_id):04x}",
        "artifact_id": artifact.artifact_id.hex(),
        "descriptor_sha256": hashlib.sha256(descriptor.to_bytes()).hexdigest(),
        "identity_sha256": hashlib.sha256(artifact.identity.to_bytes()).hexdigest(),
        "artifact_wire_sha256": hashlib.sha256(artifact.to_bytes()).hexdigest(),
        "manifest_id": None if artifact.manifest_id is None else artifact.manifest_id.hex(),
        "parent_artifact_ids": [value.hex() for value in parents],
        "audit_mode": None if audit_mode is None else audit_mode.name,
    }


def render() -> bytes:
    file_root = build_tree(b"manifest-member")
    manifest = ManifestV1(
        (
            ManifestEntryV1(
                "member.bin",
                ManifestEntryKind.FILE,
                len(b"manifest-member"),
                file_root,
            ),
        )
    )
    p1 = bytes.fromhex("11" * 32)
    p2 = bytes.fromhex("22" * 32)

    cases = [
        _case(
            name="tree-empty",
            message=b"",
            suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
            profile=ArtifactProfileV1.TREE,
            logical_name="empty.bin",
            media_type="application/octet-stream",
        ),
        _case(
            name="tree-parents-manifest",
            message=b"tree-parented",
            suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
            profile=ArtifactProfileV1.TREE,
            logical_name="tree.bin",
            media_type="application/octet-stream",
            parents=(p1, p2),
            manifest=manifest,
        ),
        _case(
            name="trajectory",
            message=b"trajectory-only",
            suite_id=SuiteIdV3.DEEP_HISTORY_V3,
            profile=ArtifactProfileV1.TRAJECTORY,
            logical_name="trajectory.bin",
            media_type="application/octet-stream",
        ),
        _case(
            name="trajectory-compact-audit",
            message=b"trajectory-audit",
            suite_id=SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
            profile=ArtifactProfileV1.TRAJECTORY,
            logical_name="trajectory-audit.bin",
            media_type="application/octet-stream",
            audit_mode=TrajectoryAuditModeV3.COMPACT,
        ),
        _case(
            name="dual",
            message=b"dual-primary",
            suite_id=SuiteIdV3.DEEP_HISTORY_V3,
            profile=ArtifactProfileV1.DUAL,
            logical_name="dual.bin",
            media_type="application/octet-stream",
        ),
        _case(
            name="dual-full-audit-manifest-parents",
            message=b"dual-evidence-package",
            suite_id=SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
            profile=ArtifactProfileV1.DUAL,
            logical_name="dual-package.bin",
            media_type="application/octet-stream",
            parents=(p1, p2),
            manifest=manifest,
            audit_mode=TrajectoryAuditModeV3.FULL,
        ),
    ]
    return (
        json.dumps(
            {"schema": "sigma-artifact-v1-sa0-kat", "cases": cases},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = render()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != payload:
            parser.error("Sigma Artifact SA0 vector corpus is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(payload.decode("utf-8"), end="")
    print("corpus_sha256=" + hashlib.sha256(payload).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
