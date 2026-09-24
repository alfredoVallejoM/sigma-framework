from __future__ import annotations

import json
import os

import pytest

from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OCI_LAYOUT_FILE,
    OCI_LAYOUT_INDEX_FILE,
    OCI_REF_NAME_ANNOTATION,
    OciLayoutError,
    OciLayoutIntegrityError,
    OciLayoutLimitsV1,
    OciLayoutResourceLimitError,
    oci_sha256_digest_v1,
    verify_sigma_artifact_layout_v1,
    write_sigma_artifact_layout_v1,
)
from sigma.tree import build_tree


def _artifact(payload: bytes = b"ix0-layout-artifact"):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(payload),
    )


def _subject_wire(payload: bytes = b"layout-subject") -> bytes:
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
            "annotations": {
                "example.subject": payload.hex(),
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _blob_path(root, digest):
    algorithm, encoded = digest.split(":", 1)
    return root / "blobs" / algorithm / encoded


def test_ix0_layout_round_trip_is_self_contained(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact()
    subject_wire = _subject_wire()

    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=subject_wire,
        subject_ref_name="subject-latest",
        referrer_ref_name="sigma-integrity",
        annotations={"example.layout": "yes"},
    )

    assert root.is_dir()
    assert (root / OCI_LAYOUT_FILE).is_file()
    assert (root / OCI_LAYOUT_INDEX_FILE).is_file()
    assert _blob_path(
        root,
        written.subject_descriptor.digest,
    ).read_bytes() == subject_wire
    assert _blob_path(
        root,
        written.binding.payload_descriptor.digest,
    ).read_bytes() == artifact.to_bytes()
    assert _blob_path(
        root,
        written.binding.manifest_descriptor.digest,
    ).read_bytes() == written.binding.manifest_wire

    verified = verify_sigma_artifact_layout_v1(
        root,
        expected_artifact_id=artifact.artifact_id,
    )
    assert verified.artifact_id == artifact.artifact_id
    assert verified.artifact_wire == artifact.to_bytes()
    assert verified.subject.digest == oci_sha256_digest_v1(subject_wire)


def test_ix0_layout_index_reference_annotations_are_non_identity_metadata(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"ref-name")
    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"ref-name"),
        subject_ref_name="release",
        referrer_ref_name="sigma",
    )
    index = json.loads(
        (root / OCI_LAYOUT_INDEX_FILE).read_text(encoding="utf-8")
    )
    by_digest = {
        item["digest"]: item
        for item in index["manifests"]
    }
    assert by_digest[written.subject_descriptor.digest]["annotations"][
        OCI_REF_NAME_ANNOTATION
    ] == "release"
    assert by_digest[written.binding.manifest_descriptor.digest]["annotations"][
        OCI_REF_NAME_ANNOTATION
    ] == "sigma"

    verified = verify_sigma_artifact_layout_v1(
        root,
        expected_artifact_id=artifact.artifact_id,
    )
    assert verified.artifact_id == artifact.artifact_id


def test_ix0_layout_corrupted_payload_is_rejected(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"corrupt-layout")
    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"corrupt-layout"),
    )
    payload = _blob_path(
        root,
        written.binding.payload_descriptor.digest,
    )
    data = bytearray(payload.read_bytes())
    data[-1] ^= 1
    payload.write_bytes(bytes(data))

    with pytest.raises(
        OciLayoutIntegrityError,
        match="digest differs",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            expected_artifact_id=artifact.artifact_id,
        )


def test_ix0_layout_missing_subject_blob_is_rejected(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"missing-subject")
    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"missing-subject"),
    )
    _blob_path(
        root,
        written.subject_descriptor.digest,
    ).unlink()

    with pytest.raises(
        OciLayoutIntegrityError,
        match="OCI subject is missing",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            expected_artifact_id=artifact.artifact_id,
        )


def test_ix0_layout_refuses_existing_destination(tmp_path):
    root = tmp_path / "layout"
    root.mkdir()

    with pytest.raises(
        OciLayoutError,
        match="must not already exist",
    ):
        write_sigma_artifact_layout_v1(
            root,
            _artifact(b"existing-target"),
            subject_wire=_subject_wire(b"existing-target"),
        )


def test_ix0_layout_blob_limit_fails_before_destination_publication(tmp_path):
    root = tmp_path / "layout"
    subject = _subject_wire(b"limit")
    limits = OciLayoutLimitsV1(
        max_blob_bytes=len(subject) - 1,
    )

    with pytest.raises(
        OciLayoutResourceLimitError,
        match="subject blob",
    ):
        write_sigma_artifact_layout_v1(
            root,
            _artifact(b"limit"),
            subject_wire=subject,
            limits=limits,
        )

    assert not root.exists()


def test_ix0_layout_index_descriptor_tampering_is_rejected(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"index-tamper")
    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"index-tamper"),
    )
    index_path = root / OCI_LAYOUT_INDEX_FILE
    index = json.loads(index_path.read_text(encoding="utf-8"))
    target = next(
        item
        for item in index["manifests"]
        if item["digest"] == written.binding.manifest_descriptor.digest
    )
    target["size"] += 1
    index_path.write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(
        OciLayoutIntegrityError,
        match="size differs|descriptor differs",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            expected_artifact_id=artifact.artifact_id,
        )


def test_ix0_layout_ambiguous_same_artifact_referrers_fail_closed(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"ambiguous-layout")
    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"ambiguous-layout"),
    )
    index_path = root / OCI_LAYOUT_INDEX_FILE
    index = json.loads(index_path.read_text(encoding="utf-8"))
    referrer = next(
        item
        for item in index["manifests"]
        if item["digest"] == written.binding.manifest_descriptor.digest
    )
    duplicate = json.loads(json.dumps(referrer))
    duplicate.setdefault("annotations", {})[
        OCI_REF_NAME_ANNOTATION
    ] = "duplicate-ref"
    index["manifests"].append(duplicate)
    index_path.write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(
        OciLayoutIntegrityError,
        match="ambiguous",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            expected_artifact_id=artifact.artifact_id,
        )


@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="platform does not expose symlink support",
)
def test_ix0_layout_rejects_symlinked_blob_directory(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"symlink-layout")
    write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"symlink-layout"),
    )

    real = root / "blobs" / "sha256-real"
    (root / "blobs" / "sha256").rename(real)
    try:
        os.symlink(real, root / "blobs" / "sha256")
    except OSError:
        pytest.skip("symlink creation not permitted on this platform")

    with pytest.raises(
        OciLayoutIntegrityError,
        match="must not be symlink",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            expected_artifact_id=artifact.artifact_id,
        )


def test_ix0_layout_tolerates_unrelated_extra_files(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"extra-files")
    write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"extra-files"),
    )
    (root / "vendor-note.txt").write_text(
        "ignored by OCI layout verifier",
        encoding="utf-8",
    )

    verified = verify_sigma_artifact_layout_v1(
        root,
        expected_artifact_id=artifact.artifact_id,
    )
    assert verified.artifact_id == artifact.artifact_id


def test_ix0_layout_can_select_referrer_by_ref_name(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"ref-name-selection")
    write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"ref-name-selection"),
        referrer_ref_name="sigma-proof",
    )

    verified = verify_sigma_artifact_layout_v1(
        root,
        referrer_ref_name="sigma-proof",
    )
    assert verified.artifact_id == artifact.artifact_id

    with pytest.raises(
        OciLayoutIntegrityError,
        match="no matching Sigma referrer",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            referrer_ref_name="missing-ref",
        )


def test_ix0_layout_rejects_subject_media_type_mismatch_before_publish(tmp_path):
    root = tmp_path / "layout"
    subject = _subject_wire(b"media-type-mismatch")

    with pytest.raises(
        OciLayoutIntegrityError,
        match="mediaType differs",
    ):
        write_sigma_artifact_layout_v1(
            root,
            _artifact(b"media-type-mismatch"),
            subject_wire=subject,
            subject_media_type="application/vnd.oci.image.index.v1+json",
        )

    assert not root.exists()


def test_ix0_layout_verify_rejects_subject_body_media_type_tampering(tmp_path):
    root = tmp_path / "layout"
    artifact = _artifact(b"subject-body-tamper")
    written = write_sigma_artifact_layout_v1(
        root,
        artifact,
        subject_wire=_subject_wire(b"subject-body-tamper"),
    )
    subject_path = _blob_path(
        root,
        written.subject_descriptor.digest,
    )
    subject = json.loads(subject_path.read_text(encoding="utf-8"))
    subject["mediaType"] = "application/vnd.oci.image.index.v1+json"
    tampered = json.dumps(
        subject,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    subject_path.write_bytes(tampered)

    with pytest.raises(
        OciLayoutIntegrityError,
        match="size differs|digest differs",
    ):
        verify_sigma_artifact_layout_v1(
            root,
            expected_artifact_id=artifact.artifact_id,
        )
