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
        headers={"Authorization": "Bearer top-secret"},
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
        "Authorization" not in request[2]
        and "authorization" not in request[2]
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
