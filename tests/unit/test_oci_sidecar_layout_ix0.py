from __future__ import annotations

import json

import pytest

from sigma.artifact import manifest_identity_v1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OCI_LAYOUT_INDEX_FILE,
    OciDescriptorV1,
    OciLayoutIntegrityError,
    OciSigmaSidecarKindV1,
    build_sigma_inclusion_proof_referrer_v1,
    build_sigma_manifest_referrer_v1,
    build_sigma_range_proof_referrer_v1,
    build_sigma_receipt_referrer_v1,
    oci_sha256_digest_v1,
    verify_sigma_sidecar_layout_v1,
    write_sigma_sidecar_layout_v1,
)
from sigma.trajectory import (
    VerificationDecisionCodeV1,
    VerificationDecisionKindV1,
    VerificationReceiptV1,
)
from sigma.tree import ManifestV1, TreeProofIndex


def _subject_wire(label: str) -> bytes:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": (
                    "sha256:"
                    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                ),
                "size": 2,
            },
            "layers": [],
            "annotations": {"example.label": label},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _subject(wire: bytes) -> OciDescriptorV1:
    return OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest=oci_sha256_digest_v1(wire),
        size=len(wire),
    )


def _receipt() -> VerificationReceiptV1:
    return VerificationReceiptV1(
        artifact_identity=b"artifact:ix0-sidecar-layout",
        policy_id=bytes.fromhex("31" * 32),
        verifier_package="sigma-framework",
        verifier_version="3.0.0a1",
        verifier_build=b"ix0-layout",
        evidence_kind=None,
        evidence_id=None,
        decision_kind=VerificationDecisionKindV1.ACCEPTED,
        decision_code=VerificationDecisionCodeV1.OK,
        decision_reason="verified",
        structure_valid=True,
        message_binding_verified=True,
        evidence_hashes=(),
        claimed_unix_time=1_800_000_200,
    )


def _proofs():
    data = b"ix0-sidecar-layout-proof" * 6000
    index = TreeProofIndex(data)
    return (
        index.prove_leaf(0),
        index.prove_range(23, 90_000),
    )


@pytest.mark.parametrize("kind_name", ["manifest", "receipt"])
def test_ix0_sidecar_layout_semantic_round_trip(tmp_path, kind_name):
    subject_wire = _subject_wire(kind_name)
    subject = _subject(subject_wire)
    if kind_name == "manifest":
        payload = ManifestV1()
        binding = build_sigma_manifest_referrer_v1(
            payload,
            subject=subject,
        )
        kind = OciSigmaSidecarKindV1.MANIFEST
        semantic_id = manifest_identity_v1(payload)
    else:
        payload = _receipt()
        binding = build_sigma_receipt_referrer_v1(
            payload,
            subject=subject,
        )
        kind = OciSigmaSidecarKindV1.VERIFICATION_RECEIPT
        semantic_id = payload.receipt_id

    root = tmp_path / kind_name
    result = write_sigma_sidecar_layout_v1(
        root,
        binding,
        subject_wire=subject_wire,
        subject_ref_name="subject",
        referrer_ref_name="sigma-sidecar",
    )

    assert result.binding == binding
    verified = verify_sigma_sidecar_layout_v1(
        root,
        kind=kind,
        expected_semantic_id=semantic_id,
        referrer_ref_name="sigma-sidecar",
    )
    assert verified.payload == payload
    assert verified.binding == binding


@pytest.mark.parametrize(
    ("builder", "kind", "select_ref"),
    [
        (
            build_sigma_inclusion_proof_referrer_v1,
            OciSigmaSidecarKindV1.INCLUSION_PROOF,
            "inclusion",
        ),
        (
            build_sigma_range_proof_referrer_v1,
            OciSigmaSidecarKindV1.RANGE_PROOF,
            "range",
        ),
    ],
)
def test_ix0_proof_sidecar_layout_round_trip_without_proof_id(
    tmp_path,
    builder,
    kind,
    select_ref,
):
    inclusion, range_proof = _proofs()
    proof = (
        inclusion
        if kind is OciSigmaSidecarKindV1.INCLUSION_PROOF
        else range_proof
    )
    subject_wire = _subject_wire(select_ref)
    binding = builder(
        proof,
        subject=_subject(subject_wire),
    )
    root = tmp_path / select_ref

    write_sigma_sidecar_layout_v1(
        root,
        binding,
        subject_wire=subject_wire,
        referrer_ref_name=select_ref,
    )
    verified = verify_sigma_sidecar_layout_v1(
        root,
        kind=kind,
        referrer_ref_name=select_ref,
    )
    assert verified.payload == proof
    assert verified.binding.semantic_id is None

    with pytest.raises(
        ValueError,
        match="no semantic ProofId",
    ):
        verify_sigma_sidecar_layout_v1(
            root,
            kind=kind,
            expected_semantic_id=bytes(32),
        )


def test_ix0_sidecar_layout_rejects_subject_bytes_not_bound_by_referrer(tmp_path):
    good_wire = _subject_wire("good")
    binding = build_sigma_manifest_referrer_v1(
        ManifestV1(),
        subject=_subject(good_wire),
    )

    with pytest.raises(
        OciLayoutIntegrityError,
        match="subject bytes differ",
    ):
        write_sigma_sidecar_layout_v1(
            tmp_path / "layout",
            binding,
            subject_wire=_subject_wire("different"),
        )

    assert not (tmp_path / "layout").exists()


def test_ix0_sidecar_layout_payload_corruption_rejects(tmp_path):
    subject_wire = _subject_wire("corruption")
    receipt = _receipt()
    binding = build_sigma_receipt_referrer_v1(
        receipt,
        subject=_subject(subject_wire),
    )
    root = tmp_path / "layout"
    write_sigma_sidecar_layout_v1(
        root,
        binding,
        subject_wire=subject_wire,
    )
    digest = binding.payload_descriptor.digest.split(":", 1)[1]
    path = root / "blobs" / "sha256" / digest
    corrupted = bytearray(path.read_bytes())
    corrupted[-1] ^= 1
    path.write_bytes(bytes(corrupted))

    with pytest.raises(
        OciLayoutIntegrityError,
        match="digest differs",
    ):
        verify_sigma_sidecar_layout_v1(
            root,
            kind=OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
            expected_semantic_id=receipt.receipt_id,
        )


def test_ix0_sidecar_layout_index_annotation_divergence_rejects(tmp_path):
    subject_wire = _subject_wire("index-divergence")
    manifest = ManifestV1()
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=_subject(subject_wire),
        annotations={"example.bound": "original"},
    )
    root = tmp_path / "layout"
    write_sigma_sidecar_layout_v1(
        root,
        binding,
        subject_wire=subject_wire,
    )

    index_path = root / OCI_LAYOUT_INDEX_FILE
    index = json.loads(index_path.read_text(encoding="utf-8"))
    referrer = next(
        item
        for item in index["manifests"]
        if item["digest"] == binding.manifest_descriptor.digest
    )
    referrer["annotations"]["example.bound"] = "mutated"
    index_path.write_text(
        json.dumps(
            index,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        OciLayoutIntegrityError,
        match="annotations differ",
    ):
        verify_sigma_sidecar_layout_v1(
            root,
            kind=OciSigmaSidecarKindV1.MANIFEST,
            expected_semantic_id=manifest_identity_v1(manifest),
        )


def test_ix0_sidecar_layout_wrong_kind_does_not_cross_select(tmp_path):
    subject_wire = _subject_wire("wrong-kind")
    manifest = ManifestV1()
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=_subject(subject_wire),
    )
    root = tmp_path / "layout"
    write_sigma_sidecar_layout_v1(
        root,
        binding,
        subject_wire=subject_wire,
    )

    with pytest.raises(
        OciLayoutIntegrityError,
        match="no matching Sigma sidecar",
    ):
        verify_sigma_sidecar_layout_v1(
            root,
            kind=OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
        )
