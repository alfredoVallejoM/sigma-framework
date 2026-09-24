from __future__ import annotations

import json
import sys

import pytest

from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OciDescriptorV1,
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
