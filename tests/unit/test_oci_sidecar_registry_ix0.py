from __future__ import annotations

import json

import pytest

from scripts.product_closure.ix0_fixtures import (
    GateOciRegistryTransport,
    make_subject_descriptor,
)
from sigma.artifact import manifest_identity_v1
from sigma.interop import (
    SIGMA_INCLUSION_PROOF_REFERRER_TYPE,
    SIGMA_MANIFEST_REFERRER_TYPE,
    SIGMA_RANGE_PROOF_REFERRER_TYPE,
    SIGMA_RECEIPT_REFERRER_TYPE,
    OciRegistryClientV1,
    OciRegistryConflictError,
    OciSigmaSidecarKindV1,
    build_sigma_inclusion_proof_referrer_v1,
    build_sigma_manifest_referrer_v1,
    build_sigma_range_proof_referrer_v1,
    build_sigma_receipt_referrer_v1,
)
from sigma.trajectory import (
    VerificationDecisionCodeV1,
    VerificationDecisionKindV1,
    VerificationReceiptV1,
)
from sigma.tree import ManifestV1, TreeProofIndex


def _client(
    transport: GateOciRegistryTransport,
) -> OciRegistryClientV1:
    return OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
    )


def _receipt() -> VerificationReceiptV1:
    return VerificationReceiptV1(
        artifact_identity=b"artifact:ix0-registry-sidecar",
        policy_id=bytes.fromhex("21" * 32),
        verifier_package="sigma-framework",
        verifier_version="3.0.0a1",
        verifier_build=b"ix0-sidecar-registry",
        evidence_kind=None,
        evidence_id=None,
        decision_kind=VerificationDecisionKindV1.ACCEPTED,
        decision_code=VerificationDecisionCodeV1.OK,
        decision_reason="verified",
        structure_valid=True,
        message_binding_verified=True,
        evidence_hashes=(),
        claimed_unix_time=1_800_000_100,
    )


def _proofs():
    data = b"sidecar-registry-proof" * 5000
    index = TreeProofIndex(data)
    return (
        index.prove_leaf(0),
        index.prove_range(7, 80_000),
    )


@pytest.mark.parametrize("native_referrers", [True, False])
def test_ix0_registry_manifest_sidecar_round_trip(native_referrers):
    transport = GateOciRegistryTransport(
        native_referrers=native_referrers
    )
    client = _client(transport)
    subject = make_subject_descriptor(b"manifest-sidecar-subject")
    manifest = ManifestV1()
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=subject,
        annotations={"example.registry": "manifest"},
    )

    attached = client.attach_sidecar(binding)

    assert attached.discovered_after_push is True
    refs = client.list_referrers(
        subject.digest,
        artifact_type=SIGMA_MANIFEST_REFERRER_TYPE,
    )
    assert [item.digest for item in refs.descriptors] == [
        binding.manifest_descriptor.digest
    ]
    assert refs.artifact_type == SIGMA_MANIFEST_REFERRER_TYPE

    pulled = client.pull_sidecar(
        subject.digest,
        kind=OciSigmaSidecarKindV1.MANIFEST,
        semantic_id=manifest_identity_v1(manifest),
    )
    assert pulled.payload == manifest
    assert pulled.binding == binding


@pytest.mark.parametrize("native_referrers", [True, False])
def test_ix0_registry_receipt_sidecar_round_trip(native_referrers):
    transport = GateOciRegistryTransport(
        native_referrers=native_referrers
    )
    client = _client(transport)
    subject = make_subject_descriptor(b"receipt-sidecar-subject")
    receipt = _receipt()
    binding = build_sigma_receipt_referrer_v1(
        receipt,
        subject=subject,
    )

    attached = client.attach_sidecar(binding)

    assert attached.discovered_after_push is True
    refs = client.list_referrers(
        subject.digest,
        artifact_type=SIGMA_RECEIPT_REFERRER_TYPE,
    )
    assert len(refs.descriptors) == 1
    pulled = client.pull_sidecar(
        subject.digest,
        kind=OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
        semantic_id=receipt.receipt_id,
    )
    assert pulled.payload == receipt
    assert pulled.binding.semantic_id == receipt.receipt_id


@pytest.mark.parametrize(
    ("builder", "kind", "artifact_type"),
    [
        (
            build_sigma_inclusion_proof_referrer_v1,
            OciSigmaSidecarKindV1.INCLUSION_PROOF,
            SIGMA_INCLUSION_PROOF_REFERRER_TYPE,
        ),
        (
            build_sigma_range_proof_referrer_v1,
            OciSigmaSidecarKindV1.RANGE_PROOF,
            SIGMA_RANGE_PROOF_REFERRER_TYPE,
        ),
    ],
)
def test_ix0_registry_proof_sidecars_pull_by_referrer_digest(
    builder,
    kind,
    artifact_type,
):
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(
        f"{kind.value}-subject".encode()
    )
    inclusion, range_proof = _proofs()
    proof = (
        inclusion
        if kind is OciSigmaSidecarKindV1.INCLUSION_PROOF
        else range_proof
    )
    binding = builder(
        proof,
        subject=subject,
    )

    client.attach_sidecar(binding)

    refs = client.list_referrers(
        subject.digest,
        artifact_type=artifact_type,
    )
    assert len(refs.descriptors) == 1
    pulled = client.pull_sidecar_by_digest(
        binding.manifest_descriptor.digest,
        expected_kind=kind,
        expected_subject_digest=subject.digest,
        expected_referrer=refs.descriptors[0],
    )
    assert pulled.payload == proof

    with pytest.raises(
        ValueError,
        match="no semantic ProofId",
    ):
        client.pull_sidecar(
            subject.digest,
            kind=kind,
            semantic_id=bytes(32),
        )


def test_ix0_registry_artifact_type_discovery_isolated_between_sidecars():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"mixed-sidecar-subject")
    manifest_binding = build_sigma_manifest_referrer_v1(
        ManifestV1(),
        subject=subject,
    )
    receipt_binding = build_sigma_receipt_referrer_v1(
        _receipt(),
        subject=subject,
    )

    client.attach_sidecar(manifest_binding)
    client.attach_sidecar(receipt_binding)

    manifest_refs = client.list_referrers(
        subject.digest,
        artifact_type=SIGMA_MANIFEST_REFERRER_TYPE,
    )
    receipt_refs = client.list_referrers(
        subject.digest,
        artifact_type=SIGMA_RECEIPT_REFERRER_TYPE,
    )

    assert [item.digest for item in manifest_refs.descriptors] == [
        manifest_binding.manifest_descriptor.digest
    ]
    assert [item.digest for item in receipt_refs.descriptors] == [
        receipt_binding.manifest_descriptor.digest
    ]


def test_ix0_registry_sidecar_descriptor_divergence_fails_closed():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"sidecar-divergence-subject")
    manifest = ManifestV1()
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=subject,
    )
    client.attach_sidecar(binding)

    digest = binding.manifest_descriptor.digest
    descriptor = dict(transport.referrers[subject.digest][digest])
    annotations = dict(descriptor["annotations"])
    annotations["example.injected"] = "server-mutation"
    descriptor["annotations"] = annotations
    transport.referrers[subject.digest][digest] = descriptor

    with pytest.raises(
        OciRegistryConflictError,
        match="descriptor differs",
    ):
        client.pull_sidecar(
            subject.digest,
            kind=OciSigmaSidecarKindV1.MANIFEST,
            semantic_id=manifest_identity_v1(manifest),
        )


def test_ix0_registry_sidecar_payload_corruption_rejects():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"sidecar-corrupt-subject")
    binding = build_sigma_receipt_referrer_v1(
        _receipt(),
        subject=subject,
    )
    client.attach_sidecar(binding)

    payload_digest = binding.payload_descriptor.digest
    payload = bytearray(transport.blobs[payload_digest])
    payload[-1] ^= 1
    transport.blobs[payload_digest] = bytes(payload)

    with pytest.raises(
        Exception,
        match="digest|descriptor",
    ):
        client.pull_sidecar_by_digest(
            binding.manifest_descriptor.digest,
            expected_kind=OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
        )


def test_ix0_fallback_index_contains_multiple_sidecar_artifact_types():
    transport = GateOciRegistryTransport(native_referrers=False)
    client = _client(transport)
    subject = make_subject_descriptor(b"fallback-mixed-sidecars")
    manifest_binding = build_sigma_manifest_referrer_v1(
        ManifestV1(),
        subject=subject,
    )
    receipt_binding = build_sigma_receipt_referrer_v1(
        _receipt(),
        subject=subject,
    )

    client.attach_sidecar(manifest_binding)
    client.attach_sidecar(receipt_binding)

    tag = next(iter(transport.tags))
    stored = json.loads(
        transport.manifests[transport.tags[tag]].decode("utf-8")
    )
    artifact_types = {
        item["artifactType"]
        for item in stored["manifests"]
    }
    assert SIGMA_MANIFEST_REFERRER_TYPE in artifact_types
    assert SIGMA_RECEIPT_REFERRER_TYPE in artifact_types
