from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from sigma.artifact import ArtifactProfileV1, create_artifact_v1, manifest_identity_v1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OciDescriptorV1,
    OciReferrersSourceV1,
    OciVerifiedSigmaSidecarV1,
    build_sigma_artifact_referrer_v1,
    build_sigma_manifest_referrer_v1,
    verify_sigma_manifest_referrer_v1,
)
from sigma.interop.cli_oci import _write_bytes_atomic
from sigma.product_cli import build_parser, main
from sigma.tree import ManifestV1, build_tree


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


def test_ix0_cli_builds_private_registry_auth_from_environment(
    monkeypatch,
    capsys,
):
    subject_digest = "sha256:" + "55" * 32
    captured = {}

    class FakeClient:
        def list_referrers(self, digest):
            assert digest == subject_digest
            return SimpleNamespace(
                subject_digest=digest,
                source=OciReferrersSourceV1.API,
                pages=1,
                filter_applied=True,
                fallback_valid=True,
                descriptors=(),
            )

    def client_factory(*args, **kwargs):
        del args
        captured.update(kwargs)
        return FakeClient()

    monkeypatch.setenv(
        "SIGMA_IX0_TEST_PASSWORD",
        "never-print-this-password",
    )
    monkeypatch.setattr(
        "sigma.interop.cli_oci.OciRegistryClientV1",
        client_factory,
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
            "--registry-user",
            "alice",
            "--registry-password-env",
            "SIGMA_IX0_TEST_PASSWORD",
            "--subject-digest",
            subject_digest,
        ],
    )

    assert main() == 0
    output = capsys.readouterr().out
    assert "never-print-this-password" not in output
    auth = captured["bearer_auth"]
    assert auth.username == "alice"
    assert auth.password == "never-print-this-password"
    assert "never-print-this-password" not in repr(auth)


def test_ix0_cli_rejects_missing_registry_password_environment(
    monkeypatch,
    capsys,
):
    monkeypatch.delenv(
        "SIGMA_IX0_MISSING_PASSWORD",
        raising=False,
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
            "--registry-user",
            "alice",
            "--registry-password-env",
            "SIGMA_IX0_MISSING_PASSWORD",
            "--subject-digest",
            "sha256:" + "66" * 32,
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "SIGMA_IX0_MISSING_PASSWORD" in captured.err


def test_ix0_cli_rejects_conflicting_bearer_auth_modes(
    monkeypatch,
):
    monkeypatch.setenv(
        "SIGMA_IX0_TEST_PASSWORD",
        "secret",
    )
    parser = build_parser()
    args = parser.parse_args(
        [
            "oci",
            "refs",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--registry-user",
            "alice",
            "--registry-password-env",
            "SIGMA_IX0_TEST_PASSWORD",
            "--registry-anonymous-bearer",
            "--subject-digest",
            "sha256:" + "77" * 32,
        ]
    )

    from sigma.interop.cli_oci import _registry_client

    with pytest.raises(
        ValueError,
        match="conflicts",
    ):
        _registry_client(args)


def test_ix0_cli_layout_export_and_verify_round_trip(
    tmp_path,
    monkeypatch,
    capsys,
):
    artifact = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(b"cli-layout"),
    )
    artifact_path = tmp_path / "artifact.sigart"
    artifact_path.write_bytes(artifact.to_bytes())
    subject_path = tmp_path / "subject.json"
    subject_path.write_text(
        json.dumps(
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
        ),
        encoding="utf-8",
    )
    layout = tmp_path / "layout"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "layout-export",
            str(artifact_path),
            "--subject",
            str(subject_path),
            "--subject-ref-name",
            "latest",
            "--referrer-ref-name",
            "sigma",
            "--output",
            str(layout),
        ],
    )
    assert main() == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["artifact_id"] == artifact.artifact_id.hex()
    assert layout.is_dir()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "layout-verify",
            str(layout),
            "--artifact-id",
            artifact.artifact_id.hex(),
        ],
    )
    assert main() == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["artifact_id"] == artifact.artifact_id.hex()
    assert verified["offline_verified"] is True


def test_ix0_cli_sidecar_verify_manifest_round_trip(
    tmp_path,
    monkeypatch,
    capsys,
):
    manifest = ManifestV1()
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "88" * 32,
        size=888,
    )
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=subject,
    )
    manifest_path = tmp_path / "oci-referrer.json"
    payload_path = tmp_path / "sigma-manifest.bin"
    manifest_path.write_bytes(binding.manifest_wire)
    payload_path.write_bytes(binding.payload_wire)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "sidecar-verify",
            "--kind",
            "manifest",
            str(manifest_path),
            str(payload_path),
            "--semantic-id",
            manifest_identity_v1(manifest).hex(),
        ],
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["kind"] == "manifest-v1"
    assert result["semantic_id"] == manifest_identity_v1(manifest).hex()
    assert result["offline_verified"] is True


def test_ix0_cli_sidecar_attach_builds_canonical_binding(
    tmp_path,
    monkeypatch,
    capsys,
):
    manifest = ManifestV1()
    payload_path = tmp_path / "manifest.bin"
    payload_path.write_bytes(manifest.to_bytes())
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "89" * 32,
        size=889,
    )
    captured = {}

    class FakeClient:
        def attach_sidecar(self, binding, *, verify_subject=False):
            captured["binding"] = binding
            captured["verify_subject"] = verify_subject
            return SimpleNamespace(
                subject_acknowledged=True,
                fallback_tag_updated=False,
                payload_reused=False,
                discovered_after_push=True,
            )

    monkeypatch.setattr(
        "sigma.interop.cli_oci.OciRegistryClientV1",
        lambda *args, **kwargs: FakeClient(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "sidecar-attach",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--kind",
            "manifest",
            "--subject-digest",
            subject.digest,
            "--subject-size",
            str(subject.size),
            "--subject-media-type",
            subject.media_type,
            "--annotation",
            "example.cli=yes",
            str(payload_path),
        ],
    )

    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    binding = captured["binding"]
    assert binding.semantic_id == manifest_identity_v1(manifest)
    assert dict(binding.manifest_descriptor.annotations)[
        "example.cli"
    ] == "yes"
    assert result["semantic_id"] == manifest_identity_v1(manifest).hex()


def test_ix0_cli_sidecar_pull_semantic_identity_writes_atomically(
    tmp_path,
    monkeypatch,
    capsys,
):
    manifest = ManifestV1()
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "90" * 32,
        size=890,
    )
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=subject,
    )
    verified = verify_sigma_manifest_referrer_v1(
        binding.manifest_wire,
        binding.payload_wire,
    )
    semantic_id = manifest_identity_v1(manifest)
    captured = {}

    class FakeClient:
        def pull_sidecar(self, subject_digest, *, kind, semantic_id):
            captured["subject_digest"] = subject_digest
            captured["kind"] = kind
            captured["semantic_id"] = semantic_id
            return verified

    monkeypatch.setattr(
        "sigma.interop.cli_oci.OciRegistryClientV1",
        lambda *args, **kwargs: FakeClient(),
    )
    payload_out = tmp_path / "nested" / "manifest.bin"
    referrer_out = tmp_path / "nested" / "referrer.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "sidecar-pull",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--kind",
            "manifest",
            "--semantic-id",
            semantic_id.hex(),
            "--subject-digest",
            subject.digest,
            "--output-payload",
            str(payload_out),
            "--output-manifest",
            str(referrer_out),
        ],
    )

    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert payload_out.read_bytes() == manifest.to_bytes()
    assert referrer_out.read_bytes() == binding.manifest_wire
    assert result["offline_verified"] is True
    assert captured["semantic_id"] == semantic_id


def test_ix0_cli_sidecar_digest_pull_can_also_check_semantic_identity(
    tmp_path,
    monkeypatch,
    capsys,
):
    manifest = ManifestV1()
    subject = OciDescriptorV1(
        media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest="sha256:" + "91" * 32,
        size=891,
    )
    binding = build_sigma_manifest_referrer_v1(
        manifest,
        subject=subject,
    )
    verified = OciVerifiedSigmaSidecarV1(
        binding=binding,
        payload=manifest,
    )
    semantic_id = manifest_identity_v1(manifest)
    captured = {}

    class FakeClient:
        def pull_sidecar_by_digest(self, digest, **kwargs):
            captured["digest"] = digest
            captured.update(kwargs)
            return verified

    monkeypatch.setattr(
        "sigma.interop.cli_oci.OciRegistryClientV1",
        lambda *args, **kwargs: FakeClient(),
    )
    payload_out = tmp_path / "manifest.bin"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "sidecar-pull",
            "--registry",
            "https://registry.example",
            "--repository",
            "team/sigma",
            "--kind",
            "manifest",
            "--referrer-digest",
            binding.manifest_descriptor.digest,
            "--semantic-id",
            semantic_id.hex(),
            "--subject-digest",
            subject.digest,
            "--output-payload",
            str(payload_out),
        ],
    )

    assert main() == 0
    json.loads(capsys.readouterr().out)
    assert captured["expected_semantic_id"] == semantic_id
    assert captured["expected_subject_digest"] == subject.digest


def test_ix0_cli_sidecar_layout_export_and_verify_round_trip(
    tmp_path,
    monkeypatch,
    capsys,
):
    manifest = ManifestV1()
    payload_path = tmp_path / "manifest.bin"
    payload_path.write_bytes(manifest.to_bytes())
    subject_path = tmp_path / "subject.json"
    subject_path.write_text(
        json.dumps(
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
        ),
        encoding="utf-8",
    )
    layout = tmp_path / "sidecar-layout"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "sidecar-layout-export",
            "--kind",
            "manifest",
            str(payload_path),
            "--subject",
            str(subject_path),
            "--referrer-ref-name",
            "manifest-sidecar",
            "--output",
            str(layout),
        ],
    )
    assert main() == 0
    exported = json.loads(capsys.readouterr().out)
    expected_id = manifest_identity_v1(manifest).hex()
    assert exported["semantic_id"] == expected_id
    assert layout.is_dir()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sigma",
            "oci",
            "sidecar-layout-verify",
            "--kind",
            "manifest",
            str(layout),
            "--semantic-id",
            expected_id,
            "--referrer-ref-name",
            "manifest-sidecar",
        ],
    )
    assert main() == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["semantic_id"] == expected_id
    assert verified["offline_verified"] is True
