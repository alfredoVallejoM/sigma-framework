"""Live OCI registry differential for typed Sigma IX0-D sidecars and ORAS."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from sigma.interop import (
    OciDescriptorV1,
    OciRegistryClientV1,
    OciSigmaSidecarKindV1,
    build_sigma_inclusion_proof_referrer_v1,
    build_sigma_manifest_referrer_v1,
    build_sigma_range_proof_referrer_v1,
    build_sigma_receipt_referrer_v1,
    sidecar_artifact_type_v1,
)
from sigma.trajectory import VerificationReceiptV1
from sigma.tree import InclusionProofV1, ManifestV1, RangeProofV1

_KIND_BY_CLI = {
    "manifest": OciSigmaSidecarKindV1.MANIFEST,
    "receipt": OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
    "inclusion-proof": OciSigmaSidecarKindV1.INCLUSION_PROOF,
    "range-proof": OciSigmaSidecarKindV1.RANGE_PROOF,
}


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _key_values(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise ValueError("headers must use KEY=VALUE syntax")
        key, value = raw.split("=", 1)
        if not key or key in result:
            raise ValueError(
                "header keys must be non-empty and unique"
            )
        result[key] = value
    return result


def _binding(
    kind: OciSigmaSidecarKindV1,
    payload_path: Path,
    *,
    subject: OciDescriptorV1,
):
    wire = payload_path.read_bytes()
    if kind is OciSigmaSidecarKindV1.MANIFEST:
        return build_sigma_manifest_referrer_v1(
            ManifestV1.from_bytes(wire),
            subject=subject,
        )
    if kind is OciSigmaSidecarKindV1.VERIFICATION_RECEIPT:
        return build_sigma_receipt_referrer_v1(
            VerificationReceiptV1.from_bytes(wire),
            subject=subject,
        )
    if kind is OciSigmaSidecarKindV1.INCLUSION_PROOF:
        return build_sigma_inclusion_proof_referrer_v1(
            InclusionProofV1.from_bytes(wire),
            subject=subject,
        )
    if kind is OciSigmaSidecarKindV1.RANGE_PROOF:
        return build_sigma_range_proof_referrer_v1(
            RangeProofV1.from_bytes(wire),
            subject=subject,
        )
    raise AssertionError("unknown sidecar kind")


def run_diff(args: argparse.Namespace) -> dict[str, object]:
    oras = shutil.which(args.oras)
    if oras is None:
        raise RuntimeError(
            f"ORAS executable not found: {args.oras}"
        )
    kind = _KIND_BY_CLI[args.kind]
    subject = OciDescriptorV1(
        media_type=args.subject_media_type,
        digest=args.subject_digest,
        size=args.subject_size,
    )
    binding = _binding(
        kind,
        args.payload,
        subject=subject,
    )
    client = OciRegistryClientV1(
        args.registry_url,
        args.repository,
        headers=_key_values(args.header),
        timeout=args.timeout,
    )
    attached = client.attach_sidecar(binding)

    artifact_type = sidecar_artifact_type_v1(kind)
    subject_target = f"{args.oras_target}@{subject.digest}"
    discover_command = [
        oras,
        "discover",
        "--artifact-type",
        artifact_type,
        "--format",
        "json",
        "--depth",
        "1",
        *args.oras_arg,
        subject_target,
    ]
    discovered_raw = _run(discover_command).stdout
    try:
        discovered = json.loads(discovered_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "ORAS discover did not return JSON"
        ) from exc
    manifests = discovered.get("manifests")
    if not isinstance(manifests, list):
        raise RuntimeError(
            "ORAS discover JSON lacks manifests list"
        )
    referrer_digest = attached.binding.manifest_descriptor.digest
    oras_digests = {
        item.get("digest")
        for item in manifests
        if isinstance(item, dict)
        and item.get("artifactType") == artifact_type
    }
    if referrer_digest not in oras_digests:
        raise AssertionError(
            "ORAS did not discover the Sigma typed sidecar"
        )

    with tempfile.TemporaryDirectory(
        prefix="sigma-ix0-oras-sidecar-"
    ) as temp:
        root = Path(temp)
        manifest_path = root / "referrer.json"
        payload_path = root / "payload.bin"

        _run(
            [
                oras,
                "manifest",
                "fetch",
                "--output",
                str(manifest_path),
                *args.oras_arg,
                f"{args.oras_target}@{referrer_digest}",
            ]
        )
        if manifest_path.read_bytes() != binding.manifest_wire:
            raise AssertionError(
                "ORAS manifest fetch changed sidecar referrer bytes"
            )

        _run(
            [
                oras,
                "blob",
                "fetch",
                "--output",
                str(payload_path),
                *args.oras_arg,
                (
                    f"{args.oras_target}@"
                    f"{binding.payload_descriptor.digest}"
                ),
            ]
        )
        if payload_path.read_bytes() != binding.payload_wire:
            raise AssertionError(
                "ORAS blob fetch changed sidecar payload bytes"
            )

    pulled = client.pull_sidecar_by_digest(
        referrer_digest,
        expected_kind=kind,
        expected_subject=subject,
        expected_semantic_id=binding.semantic_id,
    )
    if pulled.binding.payload_wire != binding.payload_wire:
        raise AssertionError(
            "Sigma registry sidecar pull diverged after ORAS readback"
        )

    return {
        "status": "PASS",
        "oras": oras,
        "kind": kind.value,
        "semantic_id": (
            None
            if binding.semantic_id is None
            else binding.semantic_id.hex()
        ),
        "subject_digest": subject.digest,
        "artifact_type": artifact_type,
        "referrer_digest": referrer_digest,
        "payload_digest": binding.payload_descriptor.digest,
        "oras_discovered": True,
        "oras_manifest_byte_exact": True,
        "oras_blob_byte_exact": True,
        "sigma_offline_verify_after_pull": True,
        "subject_acknowledged": attached.subject_acknowledged,
        "fallback_tag_updated": attached.fallback_tag_updated,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry-url", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--oras-target",
        required=True,
        help="ORAS repository target without scheme",
    )
    parser.add_argument(
        "--kind",
        choices=tuple(_KIND_BY_CLI),
        required=True,
    )
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--subject-digest", required=True)
    parser.add_argument("--subject-size", type=int, required=True)
    parser.add_argument(
        "--subject-media-type",
        default="application/vnd.oci.image.manifest.v1+json",
    )
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument(
        "--oras-arg",
        action="append",
        default=[],
    )
    parser.add_argument("--oras", default="oras")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = run_diff(args)
    encoded = json.dumps(
        report,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        args.output.write_text(
            encoded,
            encoding="utf-8",
        )
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
