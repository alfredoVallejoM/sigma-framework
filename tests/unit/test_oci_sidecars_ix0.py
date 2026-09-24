from __future__ import annotations

import hashlib
import json

import pytest

from sigma.artifact import manifest_identity_v1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_MANIFEST_ID_ANNOTATION,
    SIGMA_MANIFEST_REFERRER_TYPE,
    SIGMA_RECEIPT_ID_ANNOTATION,
    SIGMA_SIDECAR_KIND_ANNOTATION,
    SIGMA_TREE_ROOT_WIRE_SHA256_ANNOTATION,
    SIGMA_WIRE_SHA256_ANNOTATION,
    OciDescriptorV1,
    OciManifestError,
    OciSigmaSidecarKindV1,
    build_sigma_inclusion_proof_referrer_v1,
    build_sigma_manifest_referrer_v1,
    build_sigma_range_proof_referrer_v1,
    build_sigma_receipt_referrer_v1,
    verify_sigma_inclusion_proof_referrer_v1,
    verify_sigma_manifest_referrer_v1,
    verify_sigma_range_proof_referrer_v1,
    verify_sigma_receipt_referrer_v1,
    verify_sigma_sidecar_referrer_v1,
)
from sigma.trajectory import (
    VerificationDecisionCodeV1,
    VerificationDecisionKindV1,
    VerificationReceiptV1,
)
from sigma.tree import ManifestV1, TreeProofIndex, build_tree


def _subject() -> OciDescriptorV1:
    return OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "ab" * 32,
        size=1234,
    )


def _receipt() -> VerificationReceiptV1:
    return VerificationReceiptV1(
        artifact_identity=b"artifact:ix0-sidecar",
        policy_id=bytes.fromhex("11" * 32),
        verifier_package="sigma-framework",
        verifier_version="3.0.0a1",
        verifier_build=b"ix0-test",
        evidence_kind=None,
        evidence_id=None,
        decision_kind=VerificationDecisionKindV1.ACCEPTED,
        decision_code=VerificationDecisionCodeV1.OK,
        decision_reason="verified",
        structure_valid=True,
        message_binding_verified=True,
        evidence_hashes=(),
        claimed_unix_time=1_800_000_000,
    )


def _proofs():
    data = bytes(range(251)) * 400
    index = TreeProofIndex(data)
    return (
        index.prove_leaf(1),
        index.prove_range(17, 70_000),
    )


def _mutate_manifest(wire: bytes, mutate) -> bytes:
    value = json.loads(wire.decode("utf-8"))
    mutate(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_ix0_manifest_referrer_reuses_existing_manifest_identity():
    manifest = ManifestV1()
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=_subject(),
        annotations={"example.note": "manifest"},
    )

    expected_id = manifest_identity_v1(manifest)
    assert binding.semantic_id == expected_id
    assert binding.manifest_descriptor.artifact_type == (
        SIGMA_MANIFEST_REFERRER_TYPE
    )
    assert dict(binding.payload_descriptor.annotations)[
        SIGMA_MANIFEST_ID_ANNOTATION
    ] == expected_id.hex()
    assert dict(binding.manifest_descriptor.annotations)[
        SIGMA_MANIFEST_ID_ANNOTATION
    ] == expected_id.hex()
    assert dict(binding.manifest_descriptor.annotations)[
        "example.note"
    ] == "manifest"

    verified = verify_sigma_manifest_referrer_v1(
        binding.manifest_wire,
        binding.payload_wire,
        expected_subject=_subject(),
        expected_manifest_id=expected_id,
    )
    assert verified.binding == binding
    assert verified.payload == manifest


def test_ix0_receipt_referrer_reuses_existing_receipt_id():
    receipt = _receipt()
    binding = build_sigma_receipt_referrer_v1(
        receipt,
        subject=_subject(),
    )

    assert binding.semantic_id == receipt.receipt_id
    assert dict(binding.payload_descriptor.annotations)[
        SIGMA_RECEIPT_ID_ANNOTATION
    ] == receipt.receipt_id.hex()

    verified = verify_sigma_receipt_referrer_v1(
        binding.manifest_wire,
        binding.payload_wire,
        expected_receipt_id=receipt.receipt_id,
    )
    assert verified.payload == receipt
    assert verified.binding.semantic_id == receipt.receipt_id


def test_ix0_tree_proofs_use_wire_and_root_binding_without_invented_proof_id():
    inclusion, range_proof = _proofs()

    for proof, builder, verifier, expected_kind in (
        (
            inclusion,
            build_sigma_inclusion_proof_referrer_v1,
            verify_sigma_inclusion_proof_referrer_v1,
            OciSigmaSidecarKindV1.INCLUSION_PROOF,
        ),
        (
            range_proof,
            build_sigma_range_proof_referrer_v1,
            verify_sigma_range_proof_referrer_v1,
            OciSigmaSidecarKindV1.RANGE_PROOF,
        ),
    ):
        binding = builder(
            proof,
            subject=_subject(),
        )
        assert binding.semantic_id is None
        annotations = dict(binding.payload_descriptor.annotations)
        assert annotations[SIGMA_SIDECAR_KIND_ANNOTATION] == (
            expected_kind.value
        )
        assert annotations[SIGMA_WIRE_SHA256_ANNOTATION] == (
            hashlib.sha256(proof.to_bytes()).hexdigest()
        )
        assert annotations[
            SIGMA_TREE_ROOT_WIRE_SHA256_ANNOTATION
        ] == hashlib.sha256(proof.root.to_bytes()).hexdigest()
        assert SIGMA_MANIFEST_ID_ANNOTATION not in annotations
        assert SIGMA_RECEIPT_ID_ANNOTATION not in annotations

        verified = verifier(
            binding.manifest_wire,
            binding.payload_wire,
            expected_root=proof.root,
        )
        assert verified.payload == proof


def test_ix0_sidecar_user_cannot_override_reserved_sigma_annotations():
    with pytest.raises(
        OciManifestError,
        match="reserved",
    ):
        build_sigma_manifest_referrer_v1(
            ManifestV1(),
            subject=_subject(),
            annotations={
                SIGMA_MANIFEST_ID_ANNOTATION: "00" * 32,
            },
        )

    with pytest.raises(
        OciManifestError,
        match="reserved",
    ):
        build_sigma_receipt_referrer_v1(
            _receipt(),
            subject=_subject(),
            annotations={
                "dev.sigma.future": "not-user-owned",
            },
        )


def test_ix0_sidecar_payload_digest_tampering_is_rejected():
    binding = build_sigma_manifest_referrer_v1(
        ManifestV1(),
        subject=_subject(),
    )
    tampered = _mutate_manifest(
        binding.manifest_wire,
        lambda value: value["layers"][0].__setitem__(
            "digest",
            "sha256:" + "00" * 32,
        ),
    )

    with pytest.raises(
        OciManifestError,
        match="does not match bytes",
    ):
        verify_sigma_manifest_referrer_v1(
            tampered,
            binding.payload_wire,
        )


def test_ix0_sidecar_wrong_expected_kind_fails_closed():
    binding = build_sigma_manifest_referrer_v1(
        ManifestV1(),
        subject=_subject(),
    )

    with pytest.raises(
        OciManifestError,
        match="kind differs",
    ):
        verify_sigma_sidecar_referrer_v1(
            binding.manifest_wire,
            binding.payload_wire,
            expected_kind=OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
        )


def test_ix0_sidecar_unknown_reserved_system_annotation_is_rejected():
    binding = build_sigma_manifest_referrer_v1(
        ManifestV1(),
        subject=_subject(),
    )
    tampered = _mutate_manifest(
        binding.manifest_wire,
        lambda value: value["annotations"].__setitem__(
            "dev.sigma.unregistered",
            "x",
        ),
    )

    with pytest.raises(
        OciManifestError,
        match="unknown reserved",
    ):
        verify_sigma_manifest_referrer_v1(
            tampered,
            binding.payload_wire,
        )


def test_ix0_sidecar_semantic_identity_tampering_is_rejected():
    manifest = ManifestV1()
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=_subject(),
    )
    tampered = _mutate_manifest(
        binding.manifest_wire,
        lambda value: (
            value["annotations"].__setitem__(
                SIGMA_MANIFEST_ID_ANNOTATION,
                "22" * 32,
            ),
            value["layers"][0]["annotations"].__setitem__(
                SIGMA_MANIFEST_ID_ANNOTATION,
                "22" * 32,
            ),
        ),
    )

    with pytest.raises(
        OciManifestError,
        match="system annotation mismatch|not canonical",
    ):
        verify_sigma_manifest_referrer_v1(
            tampered,
            binding.payload_wire,
        )


def test_ix0_sidecar_payload_wire_mutation_is_rejected_before_semantic_use():
    receipt = _receipt()
    binding = build_sigma_receipt_referrer_v1(
        receipt,
        subject=_subject(),
    )
    corrupted = bytearray(binding.payload_wire)
    corrupted[-1] ^= 1

    with pytest.raises(
        OciManifestError,
        match="descriptor does not match bytes",
    ):
        verify_sigma_receipt_referrer_v1(
            binding.manifest_wire,
            bytes(corrupted),
        )


def test_ix0_proof_expected_root_mismatch_is_rejected():
    inclusion, _ = _proofs()
    binding = build_sigma_inclusion_proof_referrer_v1(
        inclusion,
        subject=_subject(),
    )
    other_root = build_tree(b"other-root")

    with pytest.raises(
        OciManifestError,
        match="root differs",
    ):
        verify_sigma_inclusion_proof_referrer_v1(
            binding.manifest_wire,
            binding.payload_wire,
            expected_root=other_root,
        )
