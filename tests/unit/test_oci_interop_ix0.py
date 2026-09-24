from __future__ import annotations

import hashlib
import json

import pytest

from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import audit_from_evaluation_v3
from sigma.interop import (
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_ARTIFACT_ID_ANNOTATION,
    SIGMA_ARTIFACT_REFERRER_TYPE,
    OciArtifactBindingError,
    OciDescriptorV1,
    OciManifestError,
    OciPlatformV1,
    build_sigma_artifact_referrer_v1,
    oci_sha256_digest_v1,
    parse_sigma_referrers_index_v1,
    sigma_artifact_payload_descriptor_v1,
    verify_sigma_artifact_referrer_v1,
)
from sigma.tree import build_tree
from sigma.v3 import evaluate_v3


def _artifact(payload: bytes = b"ix0-oci-artifact"):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(payload),
    )


def _subject(payload: bytes = b'{"schemaVersion":2}'):
    return OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest=oci_sha256_digest_v1(payload),
        size=len(payload),
    )


def _json_mutation(wire: bytes, mutate):
    decoded = json.loads(wire.decode("utf-8"))
    mutate(decoded)
    return json.dumps(
        decoded,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_ix0_referrer_round_trip_verifies_fully_offline():
    artifact = _artifact()
    subject = _subject()

    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=subject,
    )
    verified = verify_sigma_artifact_referrer_v1(
        binding.manifest_wire,
        binding.artifact_wire,
        expected_subject=subject,
        expected_artifact_id=artifact.artifact_id,
    )

    assert verified.artifact_id == artifact.artifact_id
    assert verified.artifact_wire == artifact.to_bytes()
    assert verified.subject == subject
    assert verified.payload_descriptor.digest == (
        "sha256:" + hashlib.sha256(artifact.to_bytes()).hexdigest()
    )
    assert verified.manifest_descriptor.digest == oci_sha256_digest_v1(
        binding.manifest_wire
    )


def test_ix0_oci_digest_and_sigma_artifact_id_are_distinct_namespaces():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(),
    )

    assert binding.payload_descriptor.digest.startswith("sha256:")
    assert binding.manifest_descriptor.digest.startswith("sha256:")
    assert len(artifact.artifact_id) == 32
    assert binding.payload_descriptor.digest != artifact.artifact_id.hex()
    assert binding.manifest_descriptor.digest != artifact.artifact_id.hex()
    assert dict(binding.payload_descriptor.annotations)[
        SIGMA_ARTIFACT_ID_ANNOTATION
    ] == artifact.artifact_id.hex()


def test_ix0_registry_metadata_mutation_does_not_change_artifact_id():
    artifact = _artifact()
    one = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(b"subject-one"),
        annotations={"org.opencontainers.image.title": "one"},
    )
    two = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(b"subject-two"),
        annotations={"org.opencontainers.image.title": "two"},
    )

    assert one.artifact_id == two.artifact_id == artifact.artifact_id
    assert one.artifact_wire == two.artifact_wire == artifact.to_bytes()
    assert one.manifest_descriptor.digest != two.manifest_descriptor.digest
    assert dict(one.manifest_descriptor.annotations)[
        "org.opencontainers.image.title"
    ] == "one"
    assert dict(two.manifest_descriptor.annotations)[
        "org.opencontainers.image.title"
    ] == "two"


def test_ix0_manifest_json_reencoding_changes_only_oci_identity():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(),
    )
    decoded = json.loads(binding.manifest_wire.decode("utf-8"))
    pretty = json.dumps(decoded, indent=2, sort_keys=False).encode("utf-8")

    verified = verify_sigma_artifact_referrer_v1(
        pretty,
        artifact.to_bytes(),
        expected_artifact_id=artifact.artifact_id,
    )

    assert verified.artifact_id == artifact.artifact_id
    assert verified.manifest_descriptor.digest != binding.manifest_descriptor.digest


def test_ix0_rejects_payload_digest_tampering():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(),
    )
    tampered = _json_mutation(
        binding.manifest_wire,
        lambda value: value["layers"][0].__setitem__(
            "digest",
            "sha256:" + "00" * 32,
        ),
    )

    with pytest.raises(
        OciArtifactBindingError,
        match="payload descriptor",
    ):
        verify_sigma_artifact_referrer_v1(
            tampered,
            artifact.to_bytes(),
        )


def test_ix0_rejects_artifact_id_annotation_tampering():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(),
    )
    tampered = _json_mutation(
        binding.manifest_wire,
        lambda value: value["annotations"].__setitem__(
            SIGMA_ARTIFACT_ID_ANNOTATION,
            "00" * 32,
        ),
    )

    with pytest.raises(
        OciArtifactBindingError,
        match="manifest annotation",
    ):
        verify_sigma_artifact_referrer_v1(
            tampered,
            artifact.to_bytes(),
        )


def test_ix0_expected_subject_is_fail_closed():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(b"subject-a"),
    )

    with pytest.raises(
        OciArtifactBindingError,
        match="expected subject",
    ):
        verify_sigma_artifact_referrer_v1(
            binding.manifest_wire,
            artifact.to_bytes(),
            expected_subject=_subject(b"subject-b"),
        )


def test_ix0_referrers_index_filters_sigma_artifact_type():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(),
    )
    other = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "22" * 32,
        size=100,
        artifact_type="application/vnd.example.other.v1",
    )
    index = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
        "manifests": [
            other.to_dict(),
            binding.manifest_descriptor.to_dict(),
        ],
    }
    wire = json.dumps(
        index,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert parse_sigma_referrers_index_v1(wire) == (
        binding.manifest_descriptor,
    )


def test_ix0_rejects_unknown_descriptor_fields_and_duplicate_json_keys():
    with pytest.raises(
        OciManifestError,
        match="unsupported OCI descriptor field",
    ):
        OciDescriptorV1.from_dict(
            {
                "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "digest": "sha256:" + "11" * 32,
                "size": 1,
                "urls": ["https://example.invalid/blob"],
            }
        )

    duplicate = (
        b'{"schemaVersion":2,"schemaVersion":2,'
        + b'"mediaType":"application/vnd.oci.image.index.v1+json",'
        + b'"manifests":[]}'
    )
    with pytest.raises(
        OciManifestError,
        match="duplicate JSON object key",
    ):
        parse_sigma_referrers_index_v1(duplicate)


def test_ix0_rejects_reserved_artifact_id_annotation_from_caller():
    with pytest.raises(
        OciManifestError,
        match="reserved",
    ):
        build_sigma_artifact_referrer_v1(
            _artifact(),
            subject=_subject(),
            annotations={SIGMA_ARTIFACT_ID_ANNOTATION: "00" * 32},
        )


def test_ix0_sigma_referrer_artifact_type_is_explicit():
    artifact = _artifact()
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(),
    )
    assert binding.manifest_descriptor.artifact_type == (
        SIGMA_ARTIFACT_REFERRER_TYPE
    )


def test_ix0_rejects_trajectory_audit_inside_artifact_payload():
    message = b"ix0-no-audit-boundary"
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"ix0",
        challenge=b"no-audit",
        application_context=b"tests/ix0",
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    digest = digest_from_evaluation_v3(evaluation)
    audit = audit_from_evaluation_v3(evaluation)
    audited = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=build_tree(message),
        trajectory_digest=digest,
        trajectory_audit=audit,
    )

    with pytest.raises(
        OciArtifactBindingError,
        match="no-audit",
    ):
        sigma_artifact_payload_descriptor_v1(audited)

    base = create_artifact_v1(
        ArtifactProfileV1.DUAL,
        tree_root=build_tree(message),
        trajectory_digest=digest,
    )
    binding = build_sigma_artifact_referrer_v1(
        base,
        subject=_subject(),
    )
    audited_wire = audited.to_bytes()
    tampered = _json_mutation(
        binding.manifest_wire,
        lambda value: (
            value["layers"][0].__setitem__(
                "digest",
                oci_sha256_digest_v1(audited_wire),
            ),
            value["layers"][0].__setitem__(
                "size",
                len(audited_wire),
            ),
            value["layers"][0]["annotations"].__setitem__(
                "dev.sigma.wire.sha256",
                hashlib.sha256(audited_wire).hexdigest(),
            ),
        ),
    )
    with pytest.raises(
        OciArtifactBindingError,
        match="no-audit",
    ):
        verify_sigma_artifact_referrer_v1(
            tampered,
            audited_wire,
        )


def test_ix0_descriptor_preserves_standard_optional_oci_fields():
    descriptor = OciDescriptorV1.from_dict(
        {
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "digest": "sha256:" + "ab" * 32,
            "size": 321,
            "artifactType": SIGMA_ARTIFACT_REFERRER_TYPE,
            "annotations": {"example.keep": "yes"},
            "urls": [
                "https://mirror-a.example/object",
                "https://mirror-b.example/object",
            ],
            "data": "e30=",
            "platform": {
                "architecture": "amd64",
                "os": "linux",
                "os.version": "6.8",
                "os.features": ["feature-a"],
                "variant": "v3",
                "features": ["reserved-future"],
            },
        }
    )

    assert descriptor.urls == (
        "https://mirror-a.example/object",
        "https://mirror-b.example/object",
    )
    assert descriptor.data == "e30="
    assert descriptor.platform == OciPlatformV1(
        architecture="amd64",
        os="linux",
        os_version="6.8",
        os_features=("feature-a",),
        variant="v3",
        features=("reserved-future",),
    )
    assert OciDescriptorV1.from_dict(descriptor.to_dict()) == descriptor


def test_ix0_referrers_parser_accepts_configured_page_above_manifest_default():
    descriptors = [
        {
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "digest": "sha256:" + f"{index:064x}",
            "size": 100 + index,
            "artifactType": SIGMA_ARTIFACT_REFERRER_TYPE,
            "annotations": {
                "example.padding": "x" * 256,
            },
        }
        for index in range(3500)
    ]
    wire = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": descriptors,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(wire) > 1024 * 1024
    assert len(wire) < 4 * 1024 * 1024

    with pytest.raises(
        OciManifestError,
        match="size limit",
    ):
        parse_sigma_referrers_index_v1(wire)

    parsed = parse_sigma_referrers_index_v1(
        wire,
        max_bytes=4 * 1024 * 1024,
    )
    assert len(parsed) == len(descriptors)


def test_ix0_platform_rejects_unknown_extension_fields():
    with pytest.raises(
        OciManifestError,
        match="unsupported OCI platform field",
    ):
        OciPlatformV1.from_dict(
            {
                "architecture": "amd64",
                "os": "linux",
                "vendor.private": "unexpected",
            }
        )


def test_ix0_offline_verify_reconstructs_all_referrer_annotations():
    artifact = _artifact(b"annotation-roundtrip")
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=_subject(b"annotation-subject"),
        annotations={
            "example.alpha": "a",
            "example.beta": "b",
        },
    )
    verified = verify_sigma_artifact_referrer_v1(
        binding.manifest_wire,
        binding.artifact_wire,
    )

    assert verified.manifest_descriptor.annotations == (
        ("dev.sigma.artifact.id", artifact.artifact_id.hex()),
        ("example.alpha", "a"),
        ("example.beta", "b"),
    )
