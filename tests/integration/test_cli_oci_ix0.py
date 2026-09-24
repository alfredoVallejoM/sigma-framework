from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OciDescriptorV1,
    OciReferrersSourceV1,
    build_sigma_artifact_referrer_v1,
)
from sigma.interop.cli_oci import _write_bytes_atomic
from sigma.product_cli import build_parser, main
from sigma.tree import build_tree


def test_ix0_cli_commands_are_registered():
    parser = build_parser()
    args = parser.parse_args(
        [
            "oci",
            "refs",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--subject-digest",
            "sha256:" + "11" * 32,
        ]
    )
    assert args.command == "oci"
    assert args.oci_command == "refs"
    assert callable(args.handler)


def test_ix0_cli_offline_verify(tmp_path, monkeypatch, capsys):
    artifact = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(b"cli-offline-verify"),
    )
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "22" * 32,
        size=123,
    )
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=subject,
    )
    manifest_path = tmp_path / "referrer.json"
    artifact_path = tmp_path / "artifact.sigart"
    manifest_path.write_bytes(binding.manifest_wire)
    artifact_path.write_bytes(binding.artifact_wire)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "verify",
            str(manifest_path),
            str(artifact_path),
            "--artifact-id",
            artifact.artifact_id.hex(),
            "--subject-digest",
            subject.digest,
            "--subject-size",
            str(subject.size),
            "--subject-media-type",
            subject.media_type,
        ],
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["offline_verified"] is True
    assert result["artifact_id"] == artifact.artifact_id.hex()
    assert result["subject_digest"] == subject.digest
    assert result["referrer_digest"] == binding.manifest_descriptor.digest


def test_ix0_cli_atomic_write_creates_parent_and_replaces(tmp_path):
    target = tmp_path / "nested" / "artifact.sigart"
    _write_bytes_atomic(target, b"new-bytes")
    assert target.read_bytes() == b"new-bytes"
    assert list(target.parent.glob(".*.tmp")) == []


def test_ix0_cli_atomic_write_preserves_existing_file_on_replace_failure(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "artifact.sigart"
    target.write_bytes(b"old-bytes")

    def fail_replace(source, destination):
        del source, destination
        raise OSError("replace failed")

    monkeypatch.setattr(
        "sigma.interop.cli_oci.os.replace",
        fail_replace,
    )
    with pytest.raises(OSError, match="replace failed"):
        _write_bytes_atomic(target, b"new-bytes")

    assert target.read_bytes() == b"old-bytes"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_ix0_cli_refs_resolves_subject_reference(
    monkeypatch,
    capsys,
):
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "33" * 32,
        size=333,
    )

    class FakeClient:
        def resolve_manifest_descriptor(self, reference):
            assert reference == "latest"
            return subject

        def list_referrers(self, digest):
            assert digest == subject.digest
            return SimpleNamespace(
                subject_digest=digest,
                source=OciReferrersSourceV1.API,
                pages=1,
                filter_applied=True,
                fallback_valid=True,
                descriptors=(),
            )

    fake = FakeClient()
    monkeypatch.setattr(
        "sigma.interop.cli_oci.OciRegistryClientV1",
        lambda *args, **kwargs: fake,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "refs",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--subject-reference",
            "latest",
        ],
    )

    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["subject_digest"] == subject.digest
    assert result["filter_applied"] is True
    assert result["fallback_valid"] is True


def test_ix0_cli_pull_accepts_digest_only_expected_subject(
    tmp_path,
    monkeypatch,
    capsys,
):
    artifact = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(b"cli-digest-only-subject"),
    )
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "44" * 32,
        size=444,
    )
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=subject,
    )
    captured = {}

    class FakeClient:
        def pull_referrer_by_digest(self, digest, **kwargs):
            captured["digest"] = digest
            captured.update(kwargs)
            return binding

    fake = FakeClient()
    monkeypatch.setattr(
        "sigma.interop.cli_oci.OciRegistryClientV1",
        lambda *args, **kwargs: fake,
    )
    output = tmp_path / "nested" / "artifact.sigart"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "pull",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--referrer-digest",
            binding.manifest_descriptor.digest,
            "--subject-digest",
            subject.digest,
            "--output-artifact",
            str(output),
        ],
    )

    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert output.read_bytes() == artifact.to_bytes()
    assert result["offline_verified"] is True
    assert captured["expected_subject"] is None
    assert captured["expected_subject_digest"] == subject.digest
