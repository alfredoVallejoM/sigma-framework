"""ORAS 1.3 byte differential for Sigma IX0 OCI Image Layout objects."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from sigma.interop import (
    OciSigmaSidecarKindV1,
    verify_sigma_artifact_layout_v1,
    verify_sigma_sidecar_layout_v1,
)

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


def _id32(
    value: str | None,
    *,
    name: str,
) -> bytes | None:
    if value is None:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be 64 hexadecimal characters"
        ) from exc
    if len(raw) != 32:
        raise ValueError(
            f"{name} must be 64 hexadecimal characters"
        )
    return raw


def run_diff(args: argparse.Namespace) -> dict[str, object]:
    oras = shutil.which(args.oras)
    if oras is None:
        raise RuntimeError(
            f"ORAS executable not found: {args.oras}"
        )

    artifact_id_hex: str | None = None
    semantic_id_hex: str | None = None
    if args.kind == "artifact":
        artifact_id = _id32(
            args.artifact_id,
            name="ArtifactId",
        )
        binding = verify_sigma_artifact_layout_v1(
            args.layout,
            expected_artifact_id=artifact_id,
            referrer_digest=args.referrer_digest,
            referrer_ref_name=args.referrer_ref_name,
        )
        payload_wire = binding.artifact_wire
        kind_name = "artifact"
        identity_hex = binding.artifact_id.hex()
        artifact_id_hex = identity_hex
    else:
        kind = _KIND_BY_CLI[args.kind]
        semantic_id = _id32(
            args.semantic_id,
            name="sidecar semantic id",
        )
        verified = verify_sigma_sidecar_layout_v1(
            args.layout,
            kind=kind,
            expected_semantic_id=semantic_id,
            referrer_digest=args.referrer_digest,
            referrer_ref_name=args.referrer_ref_name,
        )
        binding = verified.binding
        payload_wire = binding.payload_wire
        kind_name = binding.kind.value
        identity_hex = (
            None
            if binding.semantic_id is None
            else binding.semantic_id.hex()
        )
        semantic_id_hex = identity_hex

    referrer_digest = binding.manifest_descriptor.digest
    payload_digest = binding.payload_descriptor.digest
    subject_digest = binding.subject.digest

    with tempfile.TemporaryDirectory(
        prefix="sigma-ix0-oras-layout-"
    ) as temp:
        root = Path(temp)
        oras_manifest = root / "referrer.json"
        oras_payload = root / "payload.bin"
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
        if oras_payload.read_bytes() != payload_wire:
            raise AssertionError(
                "ORAS layout payload bytes differ from Sigma payload"
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
        "kind": kind_name,
        "identity": identity_hex,
        "artifact_id": artifact_id_hex,
        "semantic_id": semantic_id_hex,
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
    parser.add_argument(
        "--kind",
        choices=(
            "artifact",
            "manifest",
            "receipt",
            "inclusion-proof",
            "range-proof",
        ),
        default="artifact",
    )
    parser.add_argument("--artifact-id")
    parser.add_argument("--semantic-id")
    parser.add_argument("--referrer-digest")
    parser.add_argument("--referrer-ref-name")
    parser.add_argument("--oras", default="oras")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.kind == "artifact" and args.semantic_id is not None:
        parser.error("--semantic-id is only valid for sidecar kinds")
    if args.kind != "artifact" and args.artifact_id is not None:
        parser.error("--artifact-id is only valid for artifact layouts")

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
