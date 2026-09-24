"""Command-line surface for Sigma IX0 OCI/ORAS interoperability."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from sigma.artifact import SigmaArtifactV1

from .oci import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OciDescriptorV1,
    verify_sigma_artifact_referrer_v1,
)
from .oci_auth import OciBearerAuthV1
from .oci_layout import (
    verify_sigma_artifact_layout_v1,
    write_sigma_artifact_layout_v1,
)
from .oci_registry import OciRegistryClientV1


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    if not isinstance(path, Path):
        raise TypeError("path must be Path")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _key_values(values: list[str] | None, *, what: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values or []:
        if "=" not in raw:
            raise ValueError(f"{what} must use KEY=VALUE syntax")
        key, value = raw.split("=", 1)
        if not key or key in result:
            raise ValueError(f"{what} keys must be non-empty and unique")
        result[key] = value
    return result


def _artifact_id(value: str | None) -> bytes | None:
    if value is None:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("ArtifactId must be 64 hexadecimal characters") from exc
    if len(raw) != 32:
        raise ValueError("ArtifactId must be 64 hexadecimal characters")
    return raw


def _subject_from_args(
    args: argparse.Namespace,
    *,
    required: bool,
) -> OciDescriptorV1 | None:
    digest = getattr(args, "subject_digest", None)
    size = getattr(args, "subject_size", None)
    media_type = getattr(args, "subject_media_type", None)
    if digest is None and size is None and media_type is None:
        if required:
            raise ValueError(
                "subject requires --subject-reference or "
                "--subject-digest/--subject-size"
            )
        return None
    if digest is None or size is None:
        raise ValueError(
            "explicit subject requires --subject-digest and --subject-size"
        )
    return OciDescriptorV1(
        media_type=media_type or OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        digest=digest,
        size=size,
    )


def _registry_client(args: argparse.Namespace) -> OciRegistryClientV1:
    headers = _key_values(args.header, what="header")
    username = getattr(args, "registry_user", None)
    password_env = getattr(args, "registry_password_env", None)
    anonymous_bearer = bool(
        getattr(args, "registry_anonymous_bearer", False)
    )
    allow_insecure_realm = bool(
        getattr(args, "allow_insecure_auth_realm", False)
    )

    if anonymous_bearer and (username is not None or password_env is not None):
        raise ValueError(
            "--registry-anonymous-bearer conflicts with username/password auth"
        )
    if (username is None) != (password_env is None):
        raise ValueError(
            "--registry-user and --registry-password-env must be used together"
        )

    bearer_auth = None
    if anonymous_bearer:
        bearer_auth = OciBearerAuthV1(
            allow_insecure_realm=allow_insecure_realm,
        )
    elif username is not None and password_env is not None:
        if password_env not in os.environ:
            raise ValueError(
                f"registry password environment variable is unset: {password_env}"
            )
        bearer_auth = OciBearerAuthV1(
            username=username,
            password=os.environ[password_env],
            allow_insecure_realm=allow_insecure_realm,
        )

    return OciRegistryClientV1(
        args.registry,
        args.repository,
        headers=headers,
        timeout=args.timeout,
        bearer_auth=bearer_auth,
    )


def _registry_subject(
    args: argparse.Namespace,
    client: OciRegistryClientV1,
    *,
    required: bool,
) -> OciDescriptorV1 | None:
    reference = getattr(args, "subject_reference", None)
    explicit = _subject_from_args(args, required=False)
    if reference is not None and explicit is not None:
        raise ValueError(
            "use --subject-reference or explicit subject fields, not both"
        )
    if reference is not None:
        return client.resolve_manifest_descriptor(reference)
    if explicit is not None:
        if getattr(args, "verify_subject", False):
            client.verify_subject_descriptor(explicit)
        return explicit
    if required:
        raise ValueError(
            "subject requires --subject-reference or --subject-digest"
        )
    return None


def _registry_subject_digest(
    args: argparse.Namespace,
    client: OciRegistryClientV1,
    *,
    required: bool,
) -> str | None:
    reference = getattr(args, "subject_reference", None)
    digest = getattr(args, "subject_digest", None)
    if reference is not None and digest is not None:
        raise ValueError(
            "use --subject-reference or --subject-digest, not both"
        )
    if reference is not None:
        return client.resolve_manifest_descriptor(reference).digest
    if digest is not None:
        return digest
    if required:
        raise ValueError(
            "subject requires --subject-reference or --subject-digest"
        )
    return None


def _attach(args: argparse.Namespace) -> int:
    artifact = SigmaArtifactV1.from_bytes(args.artifact.read_bytes())
    client = _registry_client(args)
    subject = _registry_subject(
        args,
        client,
        required=True,
    )
    if subject is None:
        raise ValueError("OCI subject is required")
    annotations = _key_values(args.annotation, what="annotation")
    result = client.attach_artifact(
        artifact,
        subject=subject,
        annotations=annotations,
    )
    print(
        json.dumps(
            {
                "artifact_id": result.binding.artifact_id.hex(),
                "payload_digest": result.binding.payload_descriptor.digest,
                "referrer_digest": result.binding.manifest_descriptor.digest,
                "subject_digest": subject.digest,
                "subject_acknowledged": result.subject_acknowledged,
                "fallback_tag_updated": result.fallback_tag_updated,
                "config_reused": result.config_reused,
                "payload_reused": result.payload_reused,
                "discovered_after_push": result.discovered_after_push,
            },
            sort_keys=True,
        )
    )
    return 0


def _refs(args: argparse.Namespace) -> int:
    client = _registry_client(args)
    subject_digest = _registry_subject_digest(
        args,
        client,
        required=True,
    )
    if subject_digest is None:
        raise ValueError("OCI subject digest is required")
    result = client.list_referrers(subject_digest)
    print(
        json.dumps(
            {
                "subject_digest": result.subject_digest,
                "source": result.source.value,
                "pages": result.pages,
                "filter_applied": result.filter_applied,
                "fallback_valid": result.fallback_valid,
                "referrers": [item.to_dict() for item in result.descriptors],
            },
            sort_keys=True,
        )
    )
    return 0


def _pull(args: argparse.Namespace) -> int:
    client = _registry_client(args)
    expected_id = _artifact_id(args.artifact_id)
    if args.referrer_digest is not None:
        has_full_subject = (
            args.subject_reference is not None
            or args.subject_size is not None
            or args.subject_media_type is not None
        )
        expected_subject = (
            _registry_subject(
                args,
                client,
                required=False,
            )
            if has_full_subject
            else None
        )
        expected_subject_digest = (
            None
            if expected_subject is not None
            else _registry_subject_digest(
                args,
                client,
                required=False,
            )
        )
        binding = client.pull_referrer_by_digest(
            args.referrer_digest,
            expected_subject=expected_subject,
            expected_subject_digest=expected_subject_digest,
            expected_artifact_id=expected_id,
        )
    else:
        if expected_id is None:
            raise ValueError(
                "pull requires --referrer-digest or --artifact-id"
            )
        subject_digest = _registry_subject_digest(
            args,
            client,
            required=True,
        )
        if subject_digest is None:
            raise ValueError(
                "ArtifactId discovery requires an OCI subject"
            )
        binding = client.pull_artifact(
            subject_digest,
            expected_id,
        )

    _write_bytes_atomic(
        args.output_artifact,
        binding.artifact_wire,
    )
    if args.output_manifest is not None:
        _write_bytes_atomic(
            args.output_manifest,
            binding.manifest_wire,
        )

    print(
        json.dumps(
            {
                "artifact_id": binding.artifact_id.hex(),
                "artifact_output": str(args.output_artifact),
                "manifest_output": (
                    None
                    if args.output_manifest is None
                    else str(args.output_manifest)
                ),
                "payload_digest": binding.payload_descriptor.digest,
                "referrer_digest": binding.manifest_descriptor.digest,
                "subject_digest": binding.subject.digest,
                "offline_verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


def _layout_export(args: argparse.Namespace) -> int:
    artifact = SigmaArtifactV1.from_bytes(args.artifact.read_bytes())
    annotations = _key_values(args.annotation, what="annotation")
    result = write_sigma_artifact_layout_v1(
        args.output,
        artifact,
        subject_wire=args.subject.read_bytes(),
        subject_media_type=args.subject_media_type,
        subject_ref_name=args.subject_ref_name,
        referrer_ref_name=args.referrer_ref_name,
        annotations=annotations,
    )
    print(
        json.dumps(
            {
                "artifact_id": result.binding.artifact_id.hex(),
                "layout": str(result.root),
                "payload_digest": result.binding.payload_descriptor.digest,
                "referrer_digest": result.binding.manifest_descriptor.digest,
                "subject_digest": result.subject_descriptor.digest,
                "index_descriptor_count": result.index_descriptor_count,
            },
            sort_keys=True,
        )
    )
    return 0


def _layout_verify(args: argparse.Namespace) -> int:
    expected_id = _artifact_id(args.artifact_id)
    binding = verify_sigma_artifact_layout_v1(
        args.layout,
        expected_artifact_id=expected_id,
        referrer_digest=args.referrer_digest,
    )
    print(
        json.dumps(
            {
                "artifact_id": binding.artifact_id.hex(),
                "layout": str(args.layout),
                "payload_digest": binding.payload_descriptor.digest,
                "referrer_digest": binding.manifest_descriptor.digest,
                "subject_digest": binding.subject.digest,
                "offline_verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


def _verify(args: argparse.Namespace) -> int:
    expected_subject = _subject_from_args(args, required=False)
    expected_id = _artifact_id(args.artifact_id)
    binding = verify_sigma_artifact_referrer_v1(
        args.manifest.read_bytes(),
        args.artifact.read_bytes(),
        expected_subject=expected_subject,
        expected_artifact_id=expected_id,
    )
    print(
        json.dumps(
            {
                "artifact_id": binding.artifact_id.hex(),
                "payload_digest": binding.payload_descriptor.digest,
                "referrer_digest": binding.manifest_descriptor.digest,
                "subject_digest": binding.subject.digest,
                "offline_verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


def _registry_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--registry", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="registry HTTP header; values are never emitted in command output",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--registry-user",
        help="username for optional Bearer token-service authentication",
    )
    parser.add_argument(
        "--registry-password-env",
        metavar="ENV_VAR",
        help="environment variable containing the registry password",
    )
    parser.add_argument(
        "--registry-anonymous-bearer",
        action="store_true",
        help="follow Bearer challenges without Basic credentials",
    )
    parser.add_argument(
        "--allow-insecure-auth-realm",
        action="store_true",
        help="allow Bearer token exchange over HTTP; intended for local registries",
    )


def _registry_subject_args(
    parser: argparse.ArgumentParser,
    *,
    allow_digest_only: bool,
) -> None:
    parser.add_argument(
        "--subject-reference",
        help="registry tag or digest resolved to a verified subject descriptor",
    )
    parser.add_argument("--subject-digest")
    if not allow_digest_only:
        parser.add_argument("--subject-size", type=int)
        parser.add_argument("--subject-media-type")
        parser.add_argument(
            "--verify-subject",
            action="store_true",
            help="preflight an explicit subject descriptor against registry bytes",
        )


def _offline_subject_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--subject-digest")
    parser.add_argument("--subject-size", type=int)
    parser.add_argument("--subject-media-type")


def add_oci_commands(commands) -> None:
    oci = commands.add_parser(
        "oci",
        help="OCI/ORAS interoperability for Sigma Artifact V1",
    )
    actions = oci.add_subparsers(
        dest="oci_command",
        required=True,
    )

    attach = actions.add_parser(
        "attach",
        help="attach canonical Sigma artifact bytes as an OCI referrer",
    )
    _registry_args(attach)
    _registry_subject_args(
        attach,
        allow_digest_only=False,
    )
    attach.add_argument("artifact", type=Path)
    attach.add_argument(
        "--annotation",
        action="append",
        default=[],
        metavar="KEY=VALUE",
    )
    attach.set_defaults(handler=_attach)

    refs = actions.add_parser(
        "refs",
        help="list Sigma referrers for an OCI subject",
    )
    _registry_args(refs)
    _registry_subject_args(
        refs,
        allow_digest_only=True,
    )
    refs.set_defaults(handler=_refs)

    pull = actions.add_parser(
        "pull",
        help="pull and offline-verify a Sigma OCI referrer",
    )
    _registry_args(pull)
    selector = pull.add_mutually_exclusive_group(required=True)
    selector.add_argument("--referrer-digest")
    selector.add_argument("--artifact-id")
    pull.add_argument("--subject-reference")
    pull.add_argument("--subject-digest")
    pull.add_argument("--subject-size", type=int)
    pull.add_argument("--subject-media-type")
    pull.add_argument(
        "--verify-subject",
        action="store_true",
    )
    pull.add_argument("--output-artifact", type=Path, required=True)
    pull.add_argument("--output-manifest", type=Path)
    pull.set_defaults(handler=_pull)

    layout_export = actions.add_parser(
        "layout-export",
        help="write a self-contained OCI Image Layout with a Sigma referrer",
    )
    layout_export.add_argument("artifact", type=Path)
    layout_export.add_argument("--subject", type=Path, required=True)
    layout_export.add_argument(
        "--subject-media-type",
        default=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    )
    layout_export.add_argument("--subject-ref-name")
    layout_export.add_argument("--referrer-ref-name")
    layout_export.add_argument(
        "--annotation",
        action="append",
        default=[],
        metavar="KEY=VALUE",
    )
    layout_export.add_argument("--output", type=Path, required=True)
    layout_export.set_defaults(handler=_layout_export)

    layout_verify = actions.add_parser(
        "layout-verify",
        help="verify a Sigma referrer from an OCI Image Layout",
    )
    layout_verify.add_argument("layout", type=Path)
    layout_verify.add_argument("--artifact-id")
    layout_verify.add_argument("--referrer-digest")
    layout_verify.set_defaults(handler=_layout_verify)

    verify = actions.add_parser(
        "verify",
        help="verify previously extracted OCI manifest + Sigma artifact offline",
    )
    verify.add_argument("manifest", type=Path)
    verify.add_argument("artifact", type=Path)
    verify.add_argument("--artifact-id")
    _offline_subject_args(verify)
    verify.set_defaults(handler=_verify)


__all__ = ["add_oci_commands"]
