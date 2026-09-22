from __future__ import annotations

import pytest

from sigma.artifact import (
    ArtifactDescriptorV1,
    ArtifactIdentityV1,
    ArtifactProfileV1,
    SigmaArtifactV1,
    create_artifact_v1,
    manifest_identity_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    TrajectoryAuditModeV3,
    audit_from_evaluation_v3,
)
from sigma.tree import ManifestEntryKind, ManifestEntryV1, ManifestV1, build_tree
from sigma.v3 import evaluate_v3


def _evaluation(message: bytes = b"sa0-artifact"):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"sa0",
        challenge=b"artifact",
        application_context=b"tests/sa0",
    )
    return evaluate_v3(context, BytesSource(message))


def _parts(message: bytes = b"sa0-artifact"):
    evaluation = _evaluation(message)
    return build_tree(message), digest_from_evaluation_v3(evaluation), evaluation


def test_tree_trajectory_dual_profiles_require_exact_primary_evidence():
    tree, digest, _ = _parts()

    assert ArtifactIdentityV1(
        ArtifactProfileV1.TREE,
        ArtifactDescriptorV1(),
        tree_root=tree,
    ).profile is ArtifactProfileV1.TREE
    assert ArtifactIdentityV1(
        ArtifactProfileV1.TRAJECTORY,
        ArtifactDescriptorV1(),
        trajectory_digest=digest,
    ).profile is ArtifactProfileV1.TRAJECTORY
    assert ArtifactIdentityV1(
        ArtifactProfileV1.DUAL,
        ArtifactDescriptorV1(),
        tree_root=tree,
        trajectory_digest=digest,
    ).profile is ArtifactProfileV1.DUAL

    with pytest.raises(ValueError, match="exactly declared"):
        ArtifactIdentityV1(ArtifactProfileV1.TREE, ArtifactDescriptorV1())
    with pytest.raises(ValueError, match="exactly declared"):
        ArtifactIdentityV1(
            ArtifactProfileV1.TREE,
            ArtifactDescriptorV1(),
            tree_root=tree,
            trajectory_digest=digest,
        )
    with pytest.raises(ValueError, match="exactly declared"):
        ArtifactIdentityV1(
            ArtifactProfileV1.TRAJECTORY,
            ArtifactDescriptorV1(),
            tree_root=tree,
            trajectory_digest=digest,
        )
    with pytest.raises(ValueError, match="exactly declared"):
        ArtifactIdentityV1(
            ArtifactProfileV1.DUAL,
            ArtifactDescriptorV1(),
            tree_root=tree,
        )


def test_dual_rejects_primary_evidence_with_different_committed_lengths():
    tree = build_tree(b"short")
    digest = digest_from_evaluation_v3(_evaluation(b"different-length"))
    with pytest.raises(ValueError, match="different byte lengths"):
        ArtifactIdentityV1(
            ArtifactProfileV1.DUAL,
            ArtifactDescriptorV1(),
            tree_root=tree,
            trajectory_digest=digest,
        )


def test_descriptor_is_canonical_nfc_and_media_type():
    descriptor = ArtifactDescriptorV1("résumé.bin", "application/octet-stream")
    assert ArtifactDescriptorV1.from_bytes(descriptor.to_bytes()) == descriptor

    with pytest.raises(ValueError, match="NFC"):
        ArtifactDescriptorV1("résumé.bin")
    with pytest.raises(ValueError, match="NUL"):
        ArtifactDescriptorV1("bad\x00name")
    with pytest.raises(ValueError, match="canonical lowercase"):
        ArtifactDescriptorV1("x", "Application/JSON")
    with pytest.raises(ValueError, match="canonical lowercase"):
        ArtifactDescriptorV1("x", "application/json; charset=utf-8")


def test_artifact_id_is_non_circular_and_stored_id_is_checked():
    tree, digest, _ = _parts()
    artifact = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        descriptor=ArtifactDescriptorV1("sample.bin", "application/octet-stream"),
        tree_root=tree,
        trajectory_digest=digest,
    )
    encoded = artifact.to_bytes()
    decoded = SigmaArtifactV1.from_bytes(encoded)
    assert decoded.artifact_id == artifact.artifact_id

    mutated = bytearray(encoded)
    # record header (14) + first TLV header (6) => ArtifactId starts at byte 20
    mutated[20] ^= 1
    with pytest.raises(ValueError):
        SigmaArtifactV1.from_bytes(bytes(mutated))


def test_parent_ids_are_bound_and_canonical():
    tree, _, _ = _parts()
    parent_a = bytes.fromhex("11" * 32)
    parent_b = bytes.fromhex("22" * 32)

    one = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=tree,
        parent_artifact_ids=(parent_b, parent_a),
    )
    assert one.parent_artifact_ids == (parent_a, parent_b)

    changed = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=tree,
        parent_artifact_ids=(parent_a, bytes.fromhex("33" * 32)),
    )
    assert changed.artifact_id != one.artifact_id

    with pytest.raises(ValueError, match="sorted and unique"):
        ArtifactIdentityV1(
            ArtifactProfileV1.TREE,
            ArtifactDescriptorV1(),
            tree_root=tree,
            parent_artifact_ids=(parent_b, parent_a),
        )
    with pytest.raises(ValueError, match="sorted and unique"):
        ArtifactIdentityV1(
            ArtifactProfileV1.TREE,
            ArtifactDescriptorV1(),
            tree_root=tree,
            parent_artifact_ids=(parent_a, parent_a),
        )


def test_manifest_identity_is_bound_to_artifact_identity():
    root = build_tree(b"manifest-file")
    manifest_a = ManifestV1()
    manifest_b = ManifestV1(
        (
            ManifestEntryV1(
                "file.bin",
                ManifestEntryKind.FILE,
                len(b"manifest-file"),
                root,
            ),
        )
    )
    assert manifest_identity_v1(manifest_a) != manifest_identity_v1(manifest_b)

    artifact_a = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=root,
        manifest=manifest_a,
    )
    artifact_b = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=root,
        manifest=manifest_b,
    )
    assert artifact_a.manifest_id == manifest_identity_v1(manifest_a)
    assert artifact_b.manifest_id == manifest_identity_v1(manifest_b)
    assert artifact_a.artifact_id != artifact_b.artifact_id


def test_trajectory_audit_is_bound_to_digest_but_not_artifact_identity():
    message = b"audit-stability"
    tree, digest, evaluation = _parts(message)
    compact = audit_from_evaluation_v3(
        evaluation, mode=TrajectoryAuditModeV3.COMPACT
    )
    full = audit_from_evaluation_v3(
        evaluation, mode=TrajectoryAuditModeV3.FULL
    )

    base = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=tree,
        trajectory_digest=digest,
    )
    with_compact = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=tree,
        trajectory_digest=digest,
        trajectory_audit=compact,
    )
    with_full = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=tree,
        trajectory_digest=digest,
        trajectory_audit=full,
    )

    assert base.artifact_id == with_compact.artifact_id == with_full.artifact_id
    assert base.to_bytes() != with_compact.to_bytes()
    assert with_compact.to_bytes() != with_full.to_bytes()

    other_evaluation = _evaluation(b"other-audit-source")
    other_audit = audit_from_evaluation_v3(other_evaluation)
    with pytest.raises(ValueError, match="different SigmaDigestV3"):
        SigmaArtifactV1(base.identity, other_audit)


def test_tree_profile_must_not_carry_trajectory_audit():
    tree, _, evaluation = _parts()
    audit = audit_from_evaluation_v3(evaluation)
    identity = ArtifactIdentityV1(
        ArtifactProfileV1.TREE,
        ArtifactDescriptorV1(),
        tree_root=tree,
    )
    with pytest.raises(ValueError, match="must not carry trajectory audit"):
        SigmaArtifactV1(identity, audit)


def test_create_rejects_manifest_and_manifest_id_together():
    tree, _, _ = _parts()
    with pytest.raises(ValueError, match="manifest or manifest_id"):
        create_artifact_v1(
            ArtifactProfileV1.TREE,
            tree_root=tree,
            manifest=ManifestV1(),
            manifest_id=bytes(32),
        )


def _record_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    assert body_length == len(encoded) - 14
    offset = 14
    fields = []
    while offset < len(encoded):
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        fields.append((tag, encoded[offset : offset + length]))
        offset += length
    return fields


def _rebuild_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def test_artifact_codec_rejects_missing_duplicate_reordered_unknown_fields():
    tree, digest, _ = _parts()
    artifact = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=tree,
        trajectory_digest=digest,
    )
    encoded = artifact.to_bytes()
    fields = _record_fields(encoded)
    mutations = []
    for index, field in enumerate(fields):
        mutations.append(_rebuild_record(encoded, [*fields[:index], *fields[index + 1 :]]))
        mutations.append(
            _rebuild_record(
                encoded,
                [*fields[: index + 1], field, *fields[index + 1 :]],
            )
        )
    reordered = list(fields)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    mutations.append(_rebuild_record(encoded, reordered))
    mutations.append(_rebuild_record(encoded, [*fields, (0xFFFF, b"")]))

    for mutated in mutations:
        with pytest.raises(ValueError):
            SigmaArtifactV1.from_bytes(mutated)


def test_identity_parent_wire_reorder_rejects():
    tree, _, _ = _parts()
    parent_a = bytes.fromhex("11" * 32)
    parent_b = bytes.fromhex("22" * 32)
    identity = ArtifactIdentityV1(
        ArtifactProfileV1.TREE,
        ArtifactDescriptorV1(),
        tree_root=tree,
        parent_artifact_ids=(parent_a, parent_b),
    )
    encoded = identity.to_bytes()
    fields = _record_fields(encoded)
    parent_index = next(i for i, (tag, _) in enumerate(fields) if tag == 6)
    parent_wire = fields[parent_index][1]
    assert int.from_bytes(parent_wire[:2], "big") == 2
    reversed_parents = parent_wire[:2] + parent_b + parent_a
    mutated_fields = list(fields)
    mutated_fields[parent_index] = (6, reversed_parents)
    mutated = _rebuild_record(encoded, mutated_fields)
    with pytest.raises(ValueError):
        ArtifactIdentityV1.from_bytes(mutated)
