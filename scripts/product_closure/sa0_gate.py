"""Reproducible SA0 closure gate for canonical Sigma Artifact V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from reference import artifact_v1 as artifact_reference
from scripts.product_closure.generate_sa0_vectors import DEFAULT_OUTPUT, render
from sigma.artifact import (
    ArtifactDescriptorV1,
    ArtifactProfileV1,
    SigmaArtifactV1,
    create_artifact_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import TrajectoryAuditModeV3, audit_from_evaluation_v3
from sigma.tree import build_tree
from sigma.v3 import evaluate_v3

MIN_DIFFERENTIAL_CASES = 600
MIN_IDENTITY_MUTATIONS = 1_800
MIN_AUDIT_STABILITY_CASES = 200


def _evaluation(message: bytes, suite_id: SuiteIdV3, nonce: int):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=b"sa0-gate" + nonce.to_bytes(4, "big"),
        challenge=b"artifact",
        application_context=b"scripts/product_closure/sa0_gate",
    )
    return evaluate_v3(context, BytesSource(message))


def run_gate(
    *,
    differential_cases: int,
    identity_mutations: int,
    audit_stability_cases: int,
) -> dict[str, object]:
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(
            f"SA0 requires at least {MIN_DIFFERENTIAL_CASES} differential cases"
        )
    if identity_mutations < MIN_IDENTITY_MUTATIONS:
        raise ValueError(
            f"SA0 requires at least {MIN_IDENTITY_MUTATIONS} identity mutations"
        )
    if audit_stability_cases < MIN_AUDIT_STABILITY_CASES:
        raise ValueError(
            f"SA0 requires at least {MIN_AUDIT_STABILITY_CASES} audit-stability cases"
        )

    frozen = DEFAULT_OUTPUT.read_bytes()
    rendered = render()
    if frozen != rendered:
        raise AssertionError("frozen SA0 vector corpus is stale")

    rng = random.Random(0x53413047415445)
    suites = (
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        SuiteIdV3.DEEP_HISTORY_V3,
        SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
    )
    profiles = (
        ArtifactProfileV1.TREE,
        ArtifactProfileV1.TRAJECTORY,
        ArtifactProfileV1.DUAL,
    )

    artifact_id_stream = hashlib.sha256()
    artifact_wire_stream = hashlib.sha256()
    mutation_stream = hashlib.sha256()
    profile_counts = {profile.name: 0 for profile in profiles}
    mutation_count = 0
    audit_stability_count = 0
    parser_rejections = 0

    for case in range(differential_cases):
        size = 1 + rng.randrange(512)
        message = rng.randbytes(size)
        suite_id = suites[case % len(suites)]
        profile = profiles[case % len(profiles)]
        evaluation = _evaluation(message, suite_id, case)
        tree = build_tree(message)
        digest = digest_from_evaluation_v3(evaluation)
        descriptor = ArtifactDescriptorV1(
            f"case-{case:04d}.bin",
            "application/octet-stream",
        )
        parents = tuple(
            sorted(
                {
                    hashlib.sha256(f"sa0-parent-{case}-{i}".encode()).digest()
                    for i in range(case % 4)
                }
            )
        )
        manifest_id = (
            hashlib.sha256(f"sa0-manifest-{case}".encode()).digest()
            if case % 5 == 0
            else None
        )
        audit = (
            audit_from_evaluation_v3(
                evaluation,
                mode=(
                    TrajectoryAuditModeV3.COMPACT
                    if case % 2
                    else TrajectoryAuditModeV3.FULL
                ),
            )
            if profile is not ArtifactProfileV1.TREE and case % 7 == 0
            else None
        )

        artifact = create_artifact_v1(
            profile,
            descriptor=descriptor,
            tree_root=tree if profile is not ArtifactProfileV1.TRAJECTORY else None,
            trajectory_digest=digest if profile is not ArtifactProfileV1.TREE else None,
            trajectory_audit=audit,
            manifest_id=manifest_id,
            parent_artifact_ids=parents,
        )
        profile_counts[profile.name] += 1

        ref_profile = {
            ArtifactProfileV1.TREE: artifact_reference.PROFILE_TREE,
            ArtifactProfileV1.TRAJECTORY: artifact_reference.PROFILE_TRAJECTORY,
            ArtifactProfileV1.DUAL: artifact_reference.PROFILE_DUAL,
        }[profile]
        descriptor_ref = artifact_reference.descriptor_wire(
            logical_name=descriptor.logical_name,
            media_type=descriptor.media_type,
        )
        identity_ref = artifact_reference.identity_wire(
            profile=ref_profile,
            descriptor=descriptor_ref,
            tree_root=(
                b"" if profile is ArtifactProfileV1.TRAJECTORY else tree.to_bytes()
            ),
            trajectory_digest=(
                b"" if profile is ArtifactProfileV1.TREE else digest.to_bytes()
            ),
            manifest_id=b"" if manifest_id is None else manifest_id,
            parent_artifact_ids=parents,
        )
        artifact_ref = artifact_reference.artifact_wire(
            identity=identity_ref,
            trajectory_audit=b"" if audit is None else audit.to_bytes(),
        )
        if artifact.identity.to_bytes() != identity_ref:
            raise AssertionError(f"SA0 identity reference divergence at case {case}")
        if artifact.to_bytes() != artifact_ref:
            raise AssertionError(f"SA0 artifact reference divergence at case {case}")
        if artifact.artifact_id != artifact_reference.artifact_id(identity_ref):
            raise AssertionError(f"SA0 ArtifactId reference divergence at case {case}")
        if SigmaArtifactV1.from_bytes(artifact.to_bytes()) != artifact:
            raise AssertionError(f"SA0 artifact codec round-trip divergence at case {case}")

        artifact_id_stream.update(artifact.artifact_id)
        artifact_wire_stream.update(hashlib.sha256(artifact.to_bytes()).digest())

        # Descriptor mutation must change ArtifactId.
        descriptor_variant = ArtifactDescriptorV1(
            descriptor.logical_name + ".v2",
            descriptor.media_type,
        )
        changed_descriptor = create_artifact_v1(
            profile,
            descriptor=descriptor_variant,
            tree_root=tree if profile is not ArtifactProfileV1.TRAJECTORY else None,
            trajectory_digest=digest if profile is not ArtifactProfileV1.TREE else None,
            manifest_id=manifest_id,
            parent_artifact_ids=parents,
        )
        if changed_descriptor.artifact_id == artifact.artifact_id:
            raise AssertionError("descriptor mutation did not change ArtifactId")
        mutation_stream.update(changed_descriptor.artifact_id)
        mutation_count += 1

        # Parent-set mutation must change ArtifactId.
        extra_parent = hashlib.sha256(f"extra-parent-{case}".encode()).digest()
        changed_parents = create_artifact_v1(
            profile,
            descriptor=descriptor,
            tree_root=tree if profile is not ArtifactProfileV1.TRAJECTORY else None,
            trajectory_digest=digest if profile is not ArtifactProfileV1.TREE else None,
            manifest_id=manifest_id,
            parent_artifact_ids=(*parents, extra_parent),
        )
        if changed_parents.artifact_id == artifact.artifact_id:
            raise AssertionError("parent mutation did not change ArtifactId")
        mutation_stream.update(changed_parents.artifact_id)
        mutation_count += 1

        # Manifest identity mutation must change ArtifactId.
        changed_manifest_id = hashlib.sha256(f"changed-manifest-{case}".encode()).digest()
        changed_manifest = create_artifact_v1(
            profile,
            descriptor=descriptor,
            tree_root=tree if profile is not ArtifactProfileV1.TRAJECTORY else None,
            trajectory_digest=digest if profile is not ArtifactProfileV1.TREE else None,
            manifest_id=changed_manifest_id,
            parent_artifact_ids=parents,
        )
        if changed_manifest.artifact_id == artifact.artifact_id:
            raise AssertionError("manifest mutation did not change ArtifactId")
        mutation_stream.update(changed_manifest.artifact_id)
        mutation_count += 1

        # Stored ArtifactId corruption must reject at parse time.
        raw = bytearray(artifact.to_bytes())
        raw[20] ^= 1
        try:
            SigmaArtifactV1.from_bytes(bytes(raw))
        except (TypeError, ValueError):
            parser_rejections += 1
        else:
            raise AssertionError("artifact parser accepted corrupted stored ArtifactId")

        if (
            profile is not ArtifactProfileV1.TREE
            and audit_stability_count < audit_stability_cases
        ):
            compact = audit_from_evaluation_v3(
                evaluation, mode=TrajectoryAuditModeV3.COMPACT
            )
            full = audit_from_evaluation_v3(
                evaluation, mode=TrajectoryAuditModeV3.FULL
            )
            base = create_artifact_v1(
                profile,
                descriptor=descriptor,
                tree_root=(
                    tree if profile is ArtifactProfileV1.DUAL else None
                ),
                trajectory_digest=digest,
                manifest_id=manifest_id,
                parent_artifact_ids=parents,
            )
            compact_artifact = create_artifact_v1(
                profile,
                descriptor=descriptor,
                tree_root=(
                    tree if profile is ArtifactProfileV1.DUAL else None
                ),
                trajectory_digest=digest,
                trajectory_audit=compact,
                manifest_id=manifest_id,
                parent_artifact_ids=parents,
            )
            full_artifact = create_artifact_v1(
                profile,
                descriptor=descriptor,
                tree_root=(
                    tree if profile is ArtifactProfileV1.DUAL else None
                ),
                trajectory_digest=digest,
                trajectory_audit=full,
                manifest_id=manifest_id,
                parent_artifact_ids=parents,
            )
            if not (
                base.artifact_id
                == compact_artifact.artifact_id
                == full_artifact.artifact_id
            ):
                raise AssertionError("auxiliary trajectory audit changed ArtifactId")
            if len(
                {
                    base.to_bytes(),
                    compact_artifact.to_bytes(),
                    full_artifact.to_bytes(),
                }
            ) != 3:
                raise AssertionError("audit envelope variants did not change artifact wire")
            audit_stability_count += 1

    if mutation_count < identity_mutations:
        raise AssertionError(
            f"SA0 identity mutation campaign too small: {mutation_count}"
        )
    if audit_stability_count < audit_stability_cases:
        raise AssertionError(
            f"SA0 audit stability campaign too small: {audit_stability_count}"
        )

    return {
        "schema": "sigma-sa0-canonical-artifact-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "differential_cases": differential_cases,
        "profile_counts": profile_counts,
        "identity_mutations": mutation_count,
        "stored_id_parser_rejections": parser_rejections,
        "audit_stability_cases": audit_stability_count,
        "artifact_id_stream_sha256": artifact_id_stream.hexdigest(),
        "artifact_wire_stream_sha256": artifact_wire_stream.hexdigest(),
        "identity_mutation_stream_sha256": mutation_stream.hexdigest(),
        "frozen_vector_corpus_sha256": hashlib.sha256(frozen).hexdigest(),
        "artifact_id_includes_auxiliary_audit": False,
        "external_signature_in_artifact_identity": False,
        "security_width_claim": False,
        "empirical_performance_claims": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--differential-cases", type=int, default=MIN_DIFFERENTIAL_CASES
    )
    parser.add_argument(
        "--identity-mutations", type=int, default=MIN_IDENTITY_MUTATIONS
    )
    parser.add_argument(
        "--audit-stability-cases",
        type=int,
        default=MIN_AUDIT_STABILITY_CASES,
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        differential_cases=args.differential_cases,
        identity_mutations=args.identity_mutations,
        audit_stability_cases=args.audit_stability_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
