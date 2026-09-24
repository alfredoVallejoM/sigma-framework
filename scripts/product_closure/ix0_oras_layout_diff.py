"""ORAS 1.3 differential for a Sigma IX0-C OCI Image Layout."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from sigma.interop import verify_sigma_artifact_layout_v1


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _artifact_id(value: str | None) -> bytes | None:
    if value is None:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            "ArtifactId must be 64 hexadecimal characters"
        ) from exc
    if len(raw) != 32:
        raise ValueError(
            "ArtifactId must be 64 hexadecimal characters"
        )
    return raw


def run_diff(args: argparse.Namespace) -> dict[str, object]:
    oras = shutil.which(args.oras)
    if oras is None:
        raise RuntimeError(
            f"ORAS executable not found: {args.oras}"
        )

    binding = verify_sigma_artifact_layout_v1(
        args.layout,
        expected_artifact_id=_artifact_id(args.artifact_id),
        referrer_digest=args.referrer_digest,
    )
    referrer_digest = binding.manifest_descriptor.digest
    payload_digest = binding.payload_descriptor.digest
    subject_digest = binding.subject.digest

    with tempfile.TemporaryDirectory(
        prefix="sigma-ix0-oras-layout-"
    ) as temp:
        root = Path(temp)
        oras_manifest = root / "referrer.json"
        oras_payload = root / "artifact.sigart"
        oras_subject = root / "subject.json"

        _run(
            [
                oras,
                "manifest",
                "fetch",
                "--oci-layout",
                "--output",
                str(oras_manifest),
                f"{args.layout}@{referrer_digest}",
            ]
        )
        if oras_manifest.read_bytes() != binding.manifest_wire:
            raise AssertionError(
                "ORAS layout manifest bytes differ from Sigma referrer"
            )

        _run(
            [
                oras,
                "blob",
                "fetch",
                "--oci-layout",
                "--output",
                str(oras_payload),
                f"{args.layout}@{payload_digest}",
            ]
        )
        if oras_payload.read_bytes() != binding.artifact_wire:
            raise AssertionError(
                "ORAS layout payload bytes differ from Sigma artifact"
            )

        _run(
            [
                oras,
                "manifest",
                "fetch",
                "--oci-layout",
                "--output",
                str(oras_subject),
                f"{args.layout}@{subject_digest}",
            ]
        )
        subject_blob = (
            args.layout
            / "blobs"
            / "sha256"
            / subject_digest.split(":", 1)[1]
        ).read_bytes()
        if oras_subject.read_bytes() != subject_blob:
            raise AssertionError(
                "ORAS layout subject bytes differ from OCI layout blob"
            )

    return {
        "status": "PASS",
        "oras": oras,
        "artifact_id": binding.artifact_id.hex(),
        "referrer_digest": referrer_digest,
        "payload_digest": payload_digest,
        "subject_digest": subject_digest,
        "oras_manifest_byte_exact": True,
        "oras_payload_byte_exact": True,
        "oras_subject_byte_exact": True,
        "sigma_layout_verify": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--artifact-id")
    parser.add_argument("--referrer-digest")
    parser.add_argument("--oras", default="oras")
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
