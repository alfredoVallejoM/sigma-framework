"""Reproducible IX0 source-level closure gate.

This gate is dependency-free and uses the deterministic OCI Distribution model
from ix0_fixtures.  A separate live-registry/ORAS probe is required before IX0
can be promoted to COMPLETE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from reference.artifact_v1 import (
    PROFILE_TREE,
    artifact_wire as reference_artifact_wire,
    descriptor_wire as reference_descriptor_wire,
    identity_wire as reference_identity_wire,
)
from scripts.product_closure.ix0_fixtures import (
    GateOciRegistryTransport,
    make_subject_descriptor,
)
from sigma.artifact import ArtifactDescriptorV1, ArtifactProfileV1, create_artifact_v1
from sigma.interop import (
    OciRegistryClientV1,
    OciRegistryConflictError,
    OciRegistryLimitsV1,
    OciRegistryProtocolError,
)
from sigma.tree import build_tree

MIN_NATIVE_CASES = 200
MIN_FALLBACK_CASES = 120
MIN_METADATA_CASES = 120
MIN_CORRUPTION_CASES = 120
MIN_RETRY_CASES = 60
MIN_AMBIGUITY_CASES = 40


def _artifact(rng: random.Random, case: int):
    source = rng.randbytes(rng.randrange(0, 4097))
    descriptor = ArtifactDescriptorV1(
        logical_name=f"ix0-{case}.bin",
        media_type="application/octet-stream",
    )
    artifact = create_artifact_v1(
        ArtifactProfileV1.TREE,
        descriptor=descriptor,
        tree_root=build_tree(source),
    )
    reference_descriptor = reference_descriptor_wire(
        logical_name=descriptor.logical_name,
        media_type=descriptor.media_type,
    )
    reference_identity = reference_identity_wire(
        profile=PROFILE_TREE,
        descriptor=reference_descriptor,
        tree_root=artifact.tree_root.to_bytes(),
    )
    expected_wire = reference_artifact_wire(identity=reference_identity)
    if artifact.to_bytes() != expected_wire:
        raise AssertionError("IX0 artifact diverges from independent SA0 oracle")
    return artifact, expected_wire


def _client(
    transport: GateOciRegistryTransport,
    *,
    max_pages: int = 32,
):
    return OciRegistryClientV1(
        "https://registry.example/",
        "sigma/gate",
        transport=transport,
        limits=OciRegistryLimitsV1(
            max_pages=max_pages,
            retry_backoff_seconds=0,
        ),
    )


def run_gate(
    *,
    native_cases: int,
    fallback_cases: int,
    metadata_cases: int,
    corruption_cases: int,
    retry_cases: int,
    ambiguity_cases: int,
) -> dict[str, object]:
    for name, value, minimum in (
        ("native", native_cases, MIN_NATIVE_CASES),
        ("fallback", fallback_cases, MIN_FALLBACK_CASES),
        ("metadata", metadata_cases, MIN_METADATA_CASES),
        ("corruption", corruption_cases, MIN_CORRUPTION_CASES),
        ("retry", retry_cases, MIN_RETRY_CASES),
        ("ambiguity", ambiguity_cases, MIN_AMBIGUITY_CASES),
    ):
        if value < minimum:
            raise ValueError(f"IX0 {name} campaign too small")

    rng = random.Random(0x49583047415445)
    stream = hashlib.sha256()

    native_verified = 0
    fallback_verified = 0
    metadata_invariant = 0
    corruption_rejected = 0
    retry_recovered = 0
    ambiguity_rejected = 0

    for case in range(native_cases):
        artifact, expected_wire = _artifact(rng, case)
        transport = GateOciRegistryTransport(native_referrers=True)
        client = _client(transport)
        subject = make_subject_descriptor(
            b"IX0-NATIVE-SUBJECT" + case.to_bytes(8, "big")
        )
        result = client.attach_artifact(
            artifact,
            subject=subject,
        )
        if not result.subject_acknowledged or result.fallback_tag_updated:
            raise AssertionError("IX0 native referrers acknowledgement diverged")
        pulled = client.pull_artifact(
            subject.digest,
            artifact.artifact_id,
        )
        if pulled.artifact_wire != expected_wire:
            raise AssertionError("IX0 native round-trip changed Sigma bytes")
        native_verified += 1
        stream.update(
            b"N"
            + artifact.artifact_id
            + bytes.fromhex(result.binding.payload_descriptor.digest.split(":", 1)[1])
        )

    for case in range(fallback_cases):
        artifact, expected_wire = _artifact(rng, 10_000 + case)
        transport = GateOciRegistryTransport(native_referrers=False)
        client = _client(transport)
        subject = make_subject_descriptor(
            b"IX0-FALLBACK-SUBJECT" + case.to_bytes(8, "big")
        )
        result = client.attach_artifact(
            artifact,
            subject=subject,
        )
        if result.subject_acknowledged or not result.fallback_tag_updated:
            raise AssertionError("IX0 fallback path was not activated")
        pulled = client.pull_artifact(
            subject.digest,
            artifact.artifact_id,
        )
        if pulled.artifact_wire != expected_wire:
            raise AssertionError("IX0 fallback round-trip changed Sigma bytes")
        fallback_verified += 1
        stream.update(
            b"F"
            + artifact.artifact_id
            + bytes.fromhex(result.binding.manifest_descriptor.digest.split(":", 1)[1])
        )

    for case in range(metadata_cases):
        artifact, expected_wire = _artifact(rng, 20_000 + case)
        transport = GateOciRegistryTransport(native_referrers=True)
        client = _client(transport)
        first = client.attach_artifact(
            artifact,
            subject=make_subject_descriptor(
                b"IX0-META-A" + case.to_bytes(8, "big")
            ),
            annotations={"example.registry-metadata": "a"},
        )
        second = client.attach_artifact(
            artifact,
            subject=make_subject_descriptor(
                b"IX0-META-B" + case.to_bytes(8, "big")
            ),
            annotations={"example.registry-metadata": "b"},
        )
        if first.binding.artifact_id != artifact.artifact_id:
            raise AssertionError("OCI metadata changed ArtifactId")
        if second.binding.artifact_id != artifact.artifact_id:
            raise AssertionError("OCI metadata changed ArtifactId")
        if first.binding.artifact_wire != expected_wire:
            raise AssertionError("OCI metadata changed Sigma wire")
        if second.binding.artifact_wire != expected_wire:
            raise AssertionError("OCI metadata changed Sigma wire")
        if (
            first.binding.manifest_descriptor.digest
            == second.binding.manifest_descriptor.digest
        ):
            raise AssertionError("metadata variant did not affect OCI identity")
        metadata_invariant += 1
        stream.update(b"M" + artifact.artifact_id)

    for case in range(corruption_cases):
        artifact, _ = _artifact(rng, 30_000 + case)
        transport = GateOciRegistryTransport(native_referrers=True)
        client = _client(transport)
        subject = make_subject_descriptor(
            b"IX0-CORRUPT" + case.to_bytes(8, "big")
        )
        result = client.attach_artifact(
            artifact,
            subject=subject,
        )
        digest = result.binding.payload_descriptor.digest
        corrupt = bytearray(transport.blobs[digest])
        corrupt[case % len(corrupt)] ^= 1 << (case % 8)
        transport.blobs[digest] = bytes(corrupt)
        try:
            client.pull_referrer_by_digest(
                result.binding.manifest_descriptor.digest,
            )
        except OciRegistryProtocolError:
            corruption_rejected += 1
        else:
            raise AssertionError("IX0 accepted corrupted OCI payload")
        stream.update(
            b"C"
            + artifact.artifact_id
            + hashlib.sha256(bytes(corrupt)).digest()
        )

    for case in range(retry_cases):
        artifact, expected_wire = _artifact(rng, 40_000 + case)
        transport = GateOciRegistryTransport(
            native_referrers=True,
            retry_once={
                ("POST", "/blobs/uploads/"): 1,
                ("GET", "/referrers/"): 1,
            },
        )
        client = _client(transport)
        subject = make_subject_descriptor(
            b"IX0-RETRY" + case.to_bytes(8, "big")
        )
        result = client.attach_artifact(
            artifact,
            subject=subject,
        )
        pulled = client.pull_referrer_by_digest(
            result.binding.manifest_descriptor.digest,
        )
        if pulled.artifact_wire != expected_wire:
            raise AssertionError("IX0 retry changed accepted bytes")
        retry_recovered += 1
        stream.update(b"R" + artifact.artifact_id)

    for case in range(ambiguity_cases):
        artifact, _ = _artifact(rng, 50_000 + case)
        transport = GateOciRegistryTransport(native_referrers=True)
        client = _client(transport)
        subject = make_subject_descriptor(
            b"IX0-AMBIG" + case.to_bytes(8, "big")
        )
        client.attach_artifact(
            artifact,
            subject=subject,
            annotations={"example.variant": "a"},
        )
        client.attach_artifact(
            artifact,
            subject=subject,
            annotations={"example.variant": "b"},
        )
        try:
            client.pull_artifact(
                subject.digest,
                artifact.artifact_id,
            )
        except OciRegistryConflictError:
            ambiguity_rejected += 1
        else:
            raise AssertionError("IX0 accepted ambiguous ArtifactId discovery")
        stream.update(b"A" + artifact.artifact_id)

    # One deterministic pagination/resource check is structural rather than
    # statistical.
    paged_transport = GateOciRegistryTransport(
        native_referrers=True,
        page_size=1,
    )
    paged_client = _client(paged_transport)
    paged_subject = make_subject_descriptor(b"IX0-PAGED")
    for index in range(5):
        artifact, _ = _artifact(rng, 60_000 + index)
        paged_client.attach_artifact(
            artifact,
            subject=paged_subject,
        )
    paged = paged_client.list_referrers(paged_subject.digest)
    if paged.pages != 5 or len(paged.descriptors) != 5:
        raise AssertionError("IX0 bounded pagination diverged")

    try:
        _client(paged_transport, max_pages=2).list_referrers(
            paged_subject.digest
        )
    except Exception as exc:
        if exc.__class__.__name__ != "OciRegistryResourceLimitError":
            raise
    else:
        raise AssertionError("IX0 page limit did not fail closed")

    return {
        "status": "PASS",
        "native_roundtrips": native_verified,
        "fallback_roundtrips": fallback_verified,
        "metadata_identity_cases": metadata_invariant,
        "corruption_rejections": corruption_rejected,
        "retry_recoveries": retry_recovered,
        "ambiguity_rejections": ambiguity_rejected,
        "pagination_pages": paged.pages,
        "campaign_sha256": stream.hexdigest(),
        "live_registry_oras_required_for_complete": True,
        "identity_rule": (
            "ArtifactId is independent of OCI subject/tag/annotation/manifest digest"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-cases", type=int, default=MIN_NATIVE_CASES)
    parser.add_argument("--fallback-cases", type=int, default=MIN_FALLBACK_CASES)
    parser.add_argument("--metadata-cases", type=int, default=MIN_METADATA_CASES)
    parser.add_argument("--corruption-cases", type=int, default=MIN_CORRUPTION_CASES)
    parser.add_argument("--retry-cases", type=int, default=MIN_RETRY_CASES)
    parser.add_argument("--ambiguity-cases", type=int, default=MIN_AMBIGUITY_CASES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = run_gate(
        native_cases=args.native_cases,
        fallback_cases=args.fallback_cases,
        metadata_cases=args.metadata_cases,
        corruption_cases=args.corruption_cases,
        retry_cases=args.retry_cases,
        ambiguity_cases=args.ambiguity_cases,
    )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
