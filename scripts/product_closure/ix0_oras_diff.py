"""Live OCI registry differential between Sigma IX0 and ORAS CLI.

This script is intentionally manual/local.  It never runs through GitHub Actions.
The target subject must already exist in the selected registry repository.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from sigma.artifact import SigmaArtifactV1
from sigma.interop import (
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_ARTIFACT_REFERRER_TYPE,
    OciDescriptorV1,
    OciRegistryClientV1,
)


def _key_values(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise ValueError("headers must use KEY=VALUE syntax")
        key, value = raw.split("=", 1)
        if not key or key in result:
            raise ValueError("header keys must be non-empty and unique")
        result[key] = value
    return result


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_diff(args: argparse.Namespace) -> dict[str, object]:
    oras = shutil.which(args.oras)
    if oras is None:
        raise RuntimeError(f"ORAS executable not found: {args.oras}")

    artifact = SigmaArtifactV1.from_bytes(args.artifact.read_bytes())
    subject = OciDescriptorV1(
        media_type=args.subject_media_type,
        digest=args.subject_digest,
        size=args.subject_size,
    )
    client = OciRegistryClientV1(
        args.registry_url,
        args.repository,
        headers=_key_values(args.header),
        timeout=args.timeout,
    )
    attached = client.attach_artifact(
        artifact,
        subject=subject,
    )

    subject_target = f"{args.oras_target}@{subject.digest}"
    discover_command = [
        oras,
        "discover",
        "--artifact-type",
        SIGMA_ARTIFACT_REFERRER_TYPE,
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
        raise RuntimeError("ORAS discover did not return JSON") from exc
    manifests = discovered.get("manifests")
    if not isinstance(manifests, list):
        raise RuntimeError("ORAS discover JSON lacks manifests list")
    oras_digests = {
        item.get("digest")
        for item in manifests
        if isinstance(item, dict)
        and item.get("artifactType") == SIGMA_ARTIFACT_REFERRER_TYPE
    }
    referrer_digest = attached.binding.manifest_descriptor.digest
    if referrer_digest not in oras_digests:
        raise AssertionError("ORAS did not discover the Sigma IX0 referrer")

    with tempfile.TemporaryDirectory(prefix="sigma-ix0-oras-") as temp:
        root = Path(temp)
        manifest_path = root / "referrer.json"
        payload_path = root / "artifact.sigart"

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
        if manifest_path.read_bytes() != attached.binding.manifest_wire:
            raise AssertionError(
                "ORAS manifest fetch changed IX0 referrer bytes"
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
                    f"{attached.binding.payload_descriptor.digest}"
                ),
            ]
        )
        if payload_path.read_bytes() != artifact.to_bytes():
            raise AssertionError(
                "ORAS blob fetch changed canonical Sigma artifact bytes"
            )

    pulled = client.pull_referrer_by_digest(
        referrer_digest,
        expected_subject=subject,
        expected_artifact_id=artifact.artifact_id,
    )
    if pulled.artifact_wire != artifact.to_bytes():
        raise AssertionError("Sigma registry pull diverged after ORAS readback")

    return {
        "status": "PASS",
        "oras": oras,
        "artifact_id": artifact.artifact_id.hex(),
        "subject_digest": subject.digest,
        "referrer_digest": referrer_digest,
        "payload_digest": attached.binding.payload_descriptor.digest,
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
        help="ORAS repository target without scheme, e.g. localhost:5000/repo",
    )
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--subject-digest", required=True)
    parser.add_argument("--subject-size", type=int, required=True)
    parser.add_argument(
        "--subject-media-type",
        default=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    )
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument(
        "--oras-arg",
        action="append",
        default=[],
        help="extra ORAS flag, e.g. --oras-arg=--plain-http",
    )
    parser.add_argument("--oras", default="oras")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = run_diff(args)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
