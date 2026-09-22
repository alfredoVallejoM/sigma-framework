"""Generate/check frozen Sigma Tree V1 ST2 proof-vector hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from sigma.tree import TreeProofIndex

CHUNK = 65_536
DEFAULT_OUTPUT = Path("specification/test-vectors/sigma-tree-v1-st2.json")


def _payload(name: str) -> bytes:
    if name == "abc":
        return b"abc"
    if name == "chunk_plus_one":
        return bytes(i % 251 for i in range(CHUNK + 1))
    if name == "nine_chunks":
        return bytes((i * 17 + 5) % 251 for i in range(9 * CHUNK))
    if name == "two_chunks_tail":
        return bytes((i * 29 + 7) % 251 for i in range(2 * CHUNK + 17))
    if name == "five_chunks_tail":
        return bytes((i * 31 + 11) % 251 for i in range(5 * CHUNK + 19))
    if name == "three_chunks_tail":
        return bytes((i * 13 + 3) % 251 for i in range(3 * CHUNK + 5))
    raise ValueError(f"unknown ST2 vector source: {name}")


def render() -> bytes:
    cases: list[dict[str, object]] = []

    for source, leaf_index in (
        ("abc", 0),
        ("chunk_plus_one", 1),
        ("nine_chunks", 4),
    ):
        data = _payload(source)
        index = TreeProofIndex(data)
        proof = index.prove_leaf(leaf_index)
        start = leaf_index * CHUNK
        leaf = data[start : min(start + CHUNK, len(data))]
        wire = proof.to_bytes()
        if not verify_inclusion_wire(leaf, wire):
            raise AssertionError("independent ST2 inclusion vector verification failed")
        cases.append(
            {
                "kind": "inclusion",
                "name": f"{source}-leaf-{leaf_index}",
                "source": source,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "root_wire_sha256": hashlib.sha256(proof.root.to_bytes()).hexdigest(),
                "leaf_index": leaf_index,
                "leaf_length": len(leaf),
                "steps": len(proof.steps),
                "proof_wire_bytes": len(wire),
                "proof_wire_sha256": hashlib.sha256(wire).hexdigest(),
            }
        )

    for source, start, length, label in (
        ("abc", 0, 1, "first-byte"),
        ("two_chunks_tail", CHUNK - 1, 3, "cross-chunk"),
        ("five_chunks_tail", CHUNK + 7, 2 * CHUNK + 11, "multi-chunk"),
        ("three_chunks_tail", 0, 3 * CHUNK + 5, "full-object"),
    ):
        data = _payload(source)
        index = TreeProofIndex(data)
        proof = index.prove_range(start, length)
        selected = data[start : start + length]
        wire = proof.to_bytes()
        if not verify_range_wire(selected, wire):
            raise AssertionError("independent ST2 range vector verification failed")
        cases.append(
            {
                "kind": "range",
                "name": f"{source}-{label}",
                "source": source,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "root_wire_sha256": hashlib.sha256(proof.root.to_bytes()).hexdigest(),
                "start": start,
                "length": length,
                "prefix_bytes": len(proof.prefix),
                "suffix_bytes": len(proof.suffix),
                "witnesses": len(proof.witnesses),
                "proof_wire_bytes": len(wire),
                "proof_wire_sha256": hashlib.sha256(wire).hexdigest(),
            }
        )

    return (
        json.dumps({"schema": "sigma-tree-v1-st2-kat", "cases": cases}, indent=2)
        + "\n"
    ).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = render()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != payload:
            parser.error("Sigma Tree ST2 KAT corpus is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(hashlib.sha256(payload).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
