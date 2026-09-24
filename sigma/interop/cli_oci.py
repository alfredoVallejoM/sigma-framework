"""Command-line surface for Sigma IX0 OCI/ORAS interoperability."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sigma.artifact import SigmaArtifactV1

from .oci import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OciDescriptorV1,
    verify_sigma_artifact_referrer_v1,
)
from .oci_registry import OciRegistryClientV1


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
    supplied = (digest is not None, size is not None, media_type is not None)
    if not any(supplied):
        if required:
            raise ValueError(
                "subject requires --subject-digest, --subject-size and "
                "--subject-media-type"
            )
        return None
    if not all(supplied):
        raise ValueError(
            "subject requires --subject-digest, --subject-size and "
            "--subject-media-type together"
        )
    return OciDescriptorV1(
        media_type=media_type,
        digest=digest,
        size=size,
    )


def _registry_client(args: argparse.Namespace) -> OciRegistryClientV1:
    headers = _key_values(args.header, what="header")
    return OciRegistryClientV1(
        args.registry,
        args.repository,
        headers=headers,
        timeout=args.timeout,
    )


def _attach(args: argparse.Namespace) -> int:
    artifact = SigmaArtifactV1.from_bytes(args.artifact.read_bytes())
    subject = _subject_from_args(args, required=True)
    assert subject is not None
    annotations = _key_values(args.annotation, what="annotation")
    result = _registry_client(args).attach_artifact(
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
    result = _registry_client(args).list_referrers(args.subject_digest)
    print(
        json.dumps(
            {
                "subject_digest": result.subject_digest,
                "source": result.source.value,
                "pages": result.pages,
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
        expected_subject = _subject_from_args(args, required=False)
        binding = client.pull_referrer_by_digest(
            args.referrer_digest,
            expected_subject=expected_subject,
            expected_artifact_id=expected_id,
        )
    else:
        if expected_id is None:
            raise ValueError(
                "pull requires --referrer-digest or --artifact-id"
            )
        if args.subject_digest is None:
            raise ValueError(
                "ArtifactId discovery requires --subject-digest"
            )
        binding = client.pull_artifact(
            args.subject_digest,
            expected_id,
        )

    args.output_artifact.write_bytes(binding.artifact_wire)
    if args.output_manifest is not None:
        args.output_manifest.write_bytes(binding.manifest_wire)

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


def _subject_args(
    parser: argparse.ArgumentParser,
    *,
    required: bool,
) -> None:
    parser.add_argument(
        "--subject-digest",
        required=required,
    )
    parser.add_argument(
        "--subject-size",
        type=int,
        required=required,
    )
    parser.add_argument(
        "--subject-media-type",
        default=(
            OCI_IMAGE_MANIFEST_MEDIA_TYPE
            if required
            else None
        ),
        required=False,
    )


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
    _subject_args(attach, required=True)
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
        help="list Sigma referrers for an OCI subject digest",
    )
    _registry_args(refs)
    refs.add_argument("--subject-digest", required=True)
    refs.set_defaults(handler=_refs)

    pull = actions.add_parser(
        "pull",
        help="pull and offline-verify a Sigma OCI referrer",
    )
    _registry_args(pull)
    selector = pull.add_mutually_exclusive_group(required=True)
    selector.add_argument("--referrer-digest")
    selector.add_argument("--artifact-id")
    pull.add_argument("--subject-digest")
    pull.add_argument("--subject-size", type=int)
    pull.add_argument("--subject-media-type")
    pull.add_argument("--output-artifact", type=Path, required=True)
    pull.add_argument("--output-manifest", type=Path)
    pull.set_defaults(handler=_pull)

    verify = actions.add_parser(
        "verify",
        help="verify previously extracted OCI manifest + Sigma artifact offline",
    )
    verify.add_argument("manifest", type=Path)
    verify.add_argument("artifact", type=Path)
    verify.add_argument("--artifact-id")
    _subject_args(verify, required=False)
    verify.set_defaults(handler=_verify)


__all__ = ["add_oci_commands"]
