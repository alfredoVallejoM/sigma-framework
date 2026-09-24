from __future__ import annotations

import json

import pytest

from scripts.product_closure.ix0_fixtures import (
    GateOciRegistryTransport,
    make_subject_descriptor,
)
from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.interop import (
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_ARTIFACT_REFERRER_TYPE,
    OciDescriptorV1,
    OciPlatformV1,
    OciRegistryClientV1,
    OciRegistryConflictError,
    OciRegistryLimitsV1,
    OciRegistryProtocolError,
    OciRegistryResourceLimitError,
    OciReferrersSourceV1,
    oci_referrers_tag_v1,
)
from sigma.tree import build_tree


def _artifact(payload: bytes):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(payload),
    )


def _client(
    transport: GateOciRegistryTransport,
    *,
    limits: OciRegistryLimitsV1 | None = None,
    headers: dict[str, str] | None = None,
):
    return OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
        headers=headers,
        limits=limits
        or OciRegistryLimitsV1(
            retry_backoff_seconds=0,
        ),
    )


def test_ix0_native_referrers_attach_discover_pull_roundtrip():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"native-subject")
    artifact = _artifact(b"native-artifact")

    result = client.attach_artifact(
        artifact,
        subject=subject,
        annotations={"org.opencontainers.image.title": "sigma-evidence"},
    )

    assert result.subject_acknowledged is True
    assert result.fallback_tag_updated is False
    assert result.discovered_after_push is True

    refs = client.list_referrers(subject.digest)
    assert refs.source is OciReferrersSourceV1.API
    assert [item.digest for item in refs.descriptors] == [
        result.binding.manifest_descriptor.digest
    ]

    pulled = client.pull_referrer_by_digest(
        result.binding.manifest_descriptor.digest,
        expected_subject=subject,
        expected_artifact_id=artifact.artifact_id,
    )
    assert pulled.artifact_wire == artifact.to_bytes()
    assert pulled.artifact_id == artifact.artifact_id

    selected = client.pull_artifact(subject.digest, artifact.artifact_id)
    assert selected.artifact_wire == artifact.to_bytes()


def test_ix0_old_registry_uses_referrers_tag_fallback():
    transport = GateOciRegistryTransport(native_referrers=False)
    client = _client(transport)
    subject = make_subject_descriptor(b"fallback-subject")
    artifact = _artifact(b"fallback-artifact")

    result = client.attach_artifact(
        artifact,
        subject=subject,
    )

    assert result.subject_acknowledged is False
    assert result.fallback_tag_updated is True
    tag = oci_referrers_tag_v1(subject.digest)
    assert tag in transport.tags

    refs = client.list_referrers(subject.digest)
    assert refs.source is OciReferrersSourceV1.TAG_FALLBACK
    assert len(refs.descriptors) == 1
    assert refs.descriptors[0].digest == result.binding.manifest_descriptor.digest

    pulled = client.pull_artifact(
        subject.digest,
        artifact.artifact_id,
    )
    assert pulled.artifact_wire == artifact.to_bytes()


def test_ix0_repeated_attach_is_idempotent():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"idempotent-subject")
    artifact = _artifact(b"idempotent-artifact")

    first = client.attach_artifact(artifact, subject=subject)
    second = client.attach_artifact(artifact, subject=subject)

    assert first.config_reused is False
    assert first.payload_reused is False
    assert second.config_reused is True
    assert second.payload_reused is True

    refs = client.list_referrers(subject.digest)
    assert len(refs.descriptors) == 1
    assert refs.descriptors[0].digest == first.binding.manifest_descriptor.digest


def test_ix0_fallback_preserves_unrelated_referrers():
    transport = GateOciRegistryTransport(native_referrers=False)
    client = _client(transport)
    subject = make_subject_descriptor(b"preserve-subject")
    other = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "11" * 32,
        size=123,
        artifact_type="application/vnd.example.other.v1",
        annotations=(("example.keep", "yes"),),
    )
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [other.to_dict()],
            "annotations": {"example.index-owner": "external-client"},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    tag = oci_referrers_tag_v1(subject.digest)
    client.put_manifest(
        index,
        media_type=OCI_IMAGE_INDEX_MEDIA_TYPE,
        reference=tag,
    )

    result = client.attach_artifact(
        _artifact(b"preserve-artifact"),
        subject=subject,
    )

    stored_digest = transport.tags[tag]
    stored = json.loads(transport.manifests[stored_digest].decode("utf-8"))
    descriptors = stored["manifests"]
    assert stored["annotations"] == {
        "example.index-owner": "external-client"
    }
    assert any(item.get("digest") == other.digest for item in descriptors)
    assert any(
        item.get("digest") == result.binding.manifest_descriptor.digest
        for item in descriptors
    )


def test_ix0_referrers_pagination_is_bounded_and_complete():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        page_size=1,
    )
    client = _client(transport)
    subject = make_subject_descriptor(b"paged-subject")

    expected = []
    for index in range(4):
        result = client.attach_artifact(
            _artifact(f"paged-{index}".encode()),
            subject=subject,
        )
        expected.append(result.binding.manifest_descriptor.digest)

    refs = client.list_referrers(subject.digest)
    assert refs.pages == 4
    assert [item.digest for item in refs.descriptors] == sorted(expected)

    limited = _client(
        transport,
        limits=OciRegistryLimitsV1(
            max_pages=2,
            retry_backoff_seconds=0,
        ),
    )
    with pytest.raises(
        OciRegistryResourceLimitError,
        match="page limit",
    ):
        limited.list_referrers(subject.digest)


def test_ix0_retryable_registry_failure_is_retried_idempotently():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        retry_once={("POST", "/blobs/uploads/"): 1},
    )
    client = _client(transport)
    subject = make_subject_descriptor(b"retry-subject")
    artifact = _artifact(b"retry-artifact")

    result = client.attach_artifact(artifact, subject=subject)

    assert result.discovered_after_push
    post_requests = [
        item
        for item in transport.requests
        if item[0] == "POST" and "/blobs/uploads/" in item[1]
    ]
    assert len(post_requests) >= 3


def test_ix0_cross_origin_upload_location_does_not_receive_authorization():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        cross_origin_upload=True,
    )
    client = _client(
        transport,
        headers={"AUTHORIZATION": "Bearer top-secret"},
    )
    client.attach_artifact(
        _artifact(b"cross-origin"),
        subject=make_subject_descriptor(b"cross-origin-subject"),
    )

    upload_puts = [
        request
        for request in transport.requests
        if request[0] == "PUT"
        and request[1].startswith("https://uploads.example/")
    ]
    assert upload_puts
    assert all(
        all(key.lower() != "authorization" for key in request[2])
        for request in upload_puts
    )


def test_ix0_corrupted_pulled_blob_fails_before_sigma_acceptance():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    artifact = _artifact(b"corrupt-me")
    result = client.attach_artifact(
        artifact,
        subject=make_subject_descriptor(b"corrupt-subject"),
    )
    digest = result.binding.payload_descriptor.digest
    payload = bytearray(transport.blobs[digest])
    payload[-1] ^= 1
    transport.blobs[digest] = bytes(payload)

    with pytest.raises(
        OciRegistryProtocolError,
        match="descriptor digest",
    ):
        client.pull_referrer_by_digest(
            result.binding.manifest_descriptor.digest,
        )


def test_ix0_corrupted_manifest_digest_is_rejected():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    result = client.attach_artifact(
        _artifact(b"manifest-corrupt"),
        subject=make_subject_descriptor(b"manifest-subject"),
    )
    digest = result.binding.manifest_descriptor.digest
    wire = bytearray(transport.manifests[digest])
    wire[-1] ^= 1
    transport.manifests[digest] = bytes(wire)

    with pytest.raises(
        OciRegistryProtocolError,
        match="requested digest",
    ):
        client.pull_referrer_by_digest(digest)


def test_ix0_ambiguous_multiple_referrers_for_same_artifact_id_fail_closed():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"ambiguous-subject")
    artifact = _artifact(b"ambiguous-artifact")

    one = client.attach_artifact(
        artifact,
        subject=subject,
        annotations={"example.variant": "one"},
    )
    two = client.attach_artifact(
        artifact,
        subject=subject,
        annotations={"example.variant": "two"},
    )
    assert one.binding.manifest_descriptor.digest != two.binding.manifest_descriptor.digest

    with pytest.raises(
        OciRegistryConflictError,
        match="multiple Sigma referrers",
    ):
        client.pull_artifact(subject.digest, artifact.artifact_id)


def test_ix0_blob_limit_rejects_before_upload_session():
    transport = GateOciRegistryTransport(native_referrers=True)
    limits = OciRegistryLimitsV1(
        max_blob_bytes=16,
        retry_backoff_seconds=0,
    )
    client = _client(transport, limits=limits)

    with pytest.raises(
        OciRegistryResourceLimitError,
        match="blob exceeds",
    ):
        client.put_blob(b"x" * 17)

    assert not any(
        request[0] == "POST" and "/blobs/uploads/" in request[1]
        for request in transport.requests
    )


def test_ix0_referrers_count_limit_fails_closed():
    transport = GateOciRegistryTransport(native_referrers=True)
    generous = _client(transport)
    subject = make_subject_descriptor(b"count-subject")
    for index in range(3):
        generous.attach_artifact(
            _artifact(f"count-{index}".encode()),
            subject=subject,
        )

    limited = _client(
        transport,
        limits=OciRegistryLimitsV1(
            max_referrers=2,
            retry_backoff_seconds=0,
        ),
    )
    with pytest.raises(
        OciRegistryResourceLimitError,
        match="referrer count",
    ):
        limited.list_referrers(subject.digest)


def test_ix0_referrers_tag_matches_distribution_spec_shape():
    assert oci_referrers_tag_v1(
        "sha256:" + "a" * 64
    ) == "sha256-" + "a" * 64
    weird = oci_referrers_tag_v1(
        "test+algorithm+using+algorithm+separators+and+long:"
        "alsoSome=Encoded_Value-With-Lots-Of-Characters" + "x" * 80
    )
    assert len(weird) <= 32 + 1 + 64
    assert "+" not in weird
    assert "=" not in weird


def test_ix0_ping_and_explicit_artifact_type():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    assert client.ping() is True

    result = client.attach_artifact(
        _artifact(b"artifact-type"),
        subject=make_subject_descriptor(b"artifact-type-subject"),
    )
    assert result.binding.manifest_descriptor.artifact_type == (
        SIGMA_ARTIFACT_REFERRER_TYPE
    )


def test_ix0_blob_completion_response_loss_reconciles_by_digest():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        lose_blob_completion_once=True,
    )
    client = _client(transport)
    artifact = _artifact(b"accepted-response-loss")
    subject = make_subject_descriptor(b"accepted-response-loss-subject")

    result = client.attach_artifact(
        artifact,
        subject=subject,
    )

    assert result.discovered_after_push is True
    pulled = client.pull_artifact(
        subject.digest,
        artifact.artifact_id,
    )
    assert pulled.artifact_wire == artifact.to_bytes()


def test_ix0_fallback_conditional_response_loss_reconciles_exact_index():
    transport = GateOciRegistryTransport(
        native_referrers=False,
        lose_conditional_manifest_once=True,
    )
    client = _client(transport)
    subject = make_subject_descriptor(b"conditional-loss-subject")
    tag = oci_referrers_tag_v1(subject.digest)
    existing = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "44" * 32,
        size=44,
        artifact_type="application/vnd.example.other.v1",
    )
    initial = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [existing.to_dict()],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    client.put_manifest(
        initial,
        media_type=OCI_IMAGE_INDEX_MEDIA_TYPE,
        reference=tag,
    )

    artifact = _artifact(b"conditional-loss-artifact")
    result = client.attach_artifact(
        artifact,
        subject=subject,
    )

    assert result.discovered_after_push is True
    refs = client.list_referrers(subject.digest)
    assert any(
        item.digest == result.binding.manifest_descriptor.digest
        for item in refs.descriptors
    )


def _subject_manifest_wire() -> bytes:
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
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_ix0_resolves_subject_tag_and_can_preflight_attach():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject_wire = _subject_manifest_wire()
    client.put_manifest(
        subject_wire,
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        reference="latest",
    )

    subject = client.resolve_manifest_descriptor("latest")
    assert subject.digest.startswith("sha256:")
    assert subject.size == len(subject_wire)
    assert subject.media_type == OCI_IMAGE_MANIFEST_MEDIA_TYPE
    assert client.verify_subject_descriptor(subject) == subject

    artifact = _artifact(b"preflight-subject")
    result = client.attach_artifact(
        artifact,
        subject=subject,
        verify_subject=True,
    )
    assert result.discovered_after_push is True


def test_ix0_subject_preflight_rejects_wrong_size_or_media_type():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject_wire = _subject_manifest_wire()
    stored = client.put_manifest(
        subject_wire,
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        reference="subject",
    )
    valid = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest=stored.digest,
        size=len(subject_wire),
    )

    with pytest.raises(
        OciRegistryConflictError,
        match="differs from registry content",
    ):
        client.verify_subject_descriptor(
            OciDescriptorV1(
                media_type=valid.media_type,
                digest=valid.digest,
                size=valid.size + 1,
            )
        )

    with pytest.raises(
        OciRegistryConflictError,
        match="differs from registry content",
    ):
        client.verify_subject_descriptor(
            OciDescriptorV1(
                media_type=OCI_IMAGE_INDEX_MEDIA_TYPE,
                digest=valid.digest,
                size=valid.size,
            )
        )


def test_ix0_manifest_content_type_mismatch_rejects_resolution():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject_wire = _subject_manifest_wire()
    client.put_manifest(
        subject_wire,
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        reference="latest",
    )
    transport.manifest_content_type_override = "application/json"

    with pytest.raises(
        OciRegistryProtocolError,
        match="unexpected Content-Type",
    ):
        client.resolve_manifest_descriptor("latest")


def test_ix0_referrers_requires_oci_index_content_type():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"content-type-subject")
    client.attach_artifact(
        _artifact(b"content-type-artifact"),
        subject=subject,
    )
    transport.referrers_content_type_override = "application/json"

    with pytest.raises(
        OciRegistryProtocolError,
        match="unexpected Content-Type",
    ):
        client.list_referrers(subject.digest)


def test_ix0_referrers_missing_content_type_fails_closed():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"missing-content-type-subject")
    client.attach_artifact(
        _artifact(b"missing-content-type-artifact"),
        subject=subject,
    )
    transport.referrers_content_type_override = ""

    with pytest.raises(
        OciRegistryProtocolError,
        match="required Content-Type",
    ):
        client.list_referrers(subject.digest)


def test_ix0_referrers_pagination_loop_is_rejected_immediately():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"loop-subject")
    for index in range(2):
        client.attach_artifact(
            _artifact(f"loop-{index}".encode()),
            subject=subject,
        )

    transport.page_size = 1
    transport.pagination_loop = True
    with pytest.raises(
        OciRegistryProtocolError,
        match="pagination loop",
    ):
        client.list_referrers(subject.digest)


def test_ix0_fallback_preserves_rich_standard_descriptor_fields():
    transport = GateOciRegistryTransport(native_referrers=False)
    client = _client(transport)
    subject = make_subject_descriptor(b"rich-fallback-subject")
    rich = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "77" * 32,
        size=777,
        artifact_type="application/vnd.example.rich.v1",
        annotations=(("example.rich", "yes"),),
        urls=("https://mirror.example/referrer",),
        data="e30=",
        platform=OciPlatformV1(
            architecture="amd64",
            os="linux",
            os_version="6.8",
            os_features=("feature-a",),
            variant="v3",
        ),
    )
    tag = oci_referrers_tag_v1(subject.digest)
    initial = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [rich.to_dict()],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    client.put_manifest(
        initial,
        media_type=OCI_IMAGE_INDEX_MEDIA_TYPE,
        reference=tag,
    )

    client.attach_artifact(
        _artifact(b"rich-fallback-artifact"),
        subject=subject,
    )

    stored_digest = transport.tags[tag]
    stored = json.loads(transport.manifests[stored_digest].decode("utf-8"))
    stored_rich = next(
        item
        for item in stored["manifests"]
        if item["digest"] == rich.digest
    )
    assert OciDescriptorV1.from_dict(stored_rich) == rich


def test_ix0_pull_can_check_subject_digest_without_full_descriptor():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"digest-only-subject")
    result = client.attach_artifact(
        _artifact(b"digest-only-artifact"),
        subject=subject,
    )

    pulled = client.pull_referrer_by_digest(
        result.binding.manifest_descriptor.digest,
        expected_subject_digest=subject.digest,
    )
    assert pulled.subject.digest == subject.digest

    with pytest.raises(
        OciRegistryConflictError,
        match="subject digest differs",
    ):
        client.pull_referrer_by_digest(
            result.binding.manifest_descriptor.digest,
            expected_subject_digest="sha256:" + "99" * 32,
        )


def test_ix0_native_referrers_filters_locally_when_registry_ignores_filter():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        apply_artifact_type_filter=False,
    )
    client = _client(transport)
    subject = make_subject_descriptor(b"ignored-filter-subject")
    sigma = client.attach_artifact(
        _artifact(b"ignored-filter-artifact"),
        subject=subject,
    )

    other_wire = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "artifactType": "application/vnd.example.other.v1",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": (
                    "sha256:"
                    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                ),
                "size": 2,
            },
            "layers": [],
            "subject": subject.to_dict(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    other_digest = client.put_manifest(
        other_wire,
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        expected_subject_digest=subject.digest,
    ).digest
    assert other_digest in transport.referrers[subject.digest]

    refs = client.list_referrers(subject.digest)
    assert refs.filter_applied is False
    assert [item.digest for item in refs.descriptors] == [
        sigma.binding.manifest_descriptor.digest
    ]


def test_ix0_invalid_fallback_tag_is_reported_as_empty_invalid_query():
    transport = GateOciRegistryTransport(native_referrers=False)
    client = _client(transport)
    subject = make_subject_descriptor(b"invalid-fallback-subject")
    tag = oci_referrers_tag_v1(subject.digest)
    wrong_wire = json.dumps(
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
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    client.put_manifest(
        wrong_wire,
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        reference=tag,
    )

    refs = client.list_referrers(subject.digest)
    assert refs.source is OciReferrersSourceV1.TAG_FALLBACK
    assert refs.descriptors == ()
    assert refs.fallback_valid is False


def test_ix0_attach_refuses_to_overwrite_invalid_fallback_tag():
    transport = GateOciRegistryTransport(native_referrers=False)
    client = _client(transport)
    subject = make_subject_descriptor(b"invalid-fallback-push-subject")
    tag = oci_referrers_tag_v1(subject.digest)
    wrong_wire = json.dumps(
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
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    original = client.put_manifest(
        wrong_wire,
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        reference=tag,
    ).digest

    with pytest.raises(
        OciRegistryProtocolError,
        match="unexpected Content-Type|not an image index",
    ):
        client.attach_artifact(
            _artifact(b"must-not-overwrite"),
            subject=subject,
        )

    assert transport.tags[tag] == original


def test_ix0_pull_rejects_referrers_descriptor_size_divergence():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"descriptor-size-subject")
    artifact = _artifact(b"descriptor-size-artifact")
    result = client.attach_artifact(
        artifact,
        subject=subject,
    )
    digest = result.binding.manifest_descriptor.digest
    descriptor = dict(transport.referrers[subject.digest][digest])
    descriptor["size"] = int(descriptor["size"]) + 1
    transport.referrers[subject.digest][digest] = descriptor

    with pytest.raises(
        OciRegistryConflictError,
        match="discovered OCI referrer descriptor differs",
    ):
        client.pull_artifact(
            subject.digest,
            artifact.artifact_id,
        )


def test_ix0_pull_rejects_referrers_annotation_divergence():
    transport = GateOciRegistryTransport(native_referrers=True)
    client = _client(transport)
    subject = make_subject_descriptor(b"descriptor-annotation-subject")
    artifact = _artifact(b"descriptor-annotation-artifact")
    result = client.attach_artifact(
        artifact,
        subject=subject,
        annotations={"example.bound": "original"},
    )
    digest = result.binding.manifest_descriptor.digest
    descriptor = dict(transport.referrers[subject.digest][digest])
    annotations = dict(descriptor["annotations"])
    annotations["example.bound"] = "mutated"
    descriptor["annotations"] = annotations
    transport.referrers[subject.digest][digest] = descriptor

    with pytest.raises(
        OciRegistryConflictError,
        match="discovered OCI referrer descriptor differs",
    ):
        client.pull_artifact(
            subject.digest,
            artifact.artifact_id,
        )
