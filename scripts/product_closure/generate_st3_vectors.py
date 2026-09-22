"""Generate/check frozen Sigma Tree V1 ST3 checkpoint vector hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference.tree_checkpoint_v1 import checkpoint_wire as reference_checkpoint_wire
from reference.tree_checkpoint_v1 import resume_checkpoint_wire
from sigma.tree import checkpoint_bytes, resume_tree

CHUNK = 65_536
DEFAULT_OUTPUT = Path("specification/test-vectors/sigma-tree-v1-st3.json")


def _case(name: str) -> tuple[bytes, bytes]:
    if name == "empty-to-abc":
        return b"", b"abc"
    if name == "one-byte":
        return b"A", b"BC"
    if name == "chunk-boundary":
        return bytes(i % 251 for i in range(CHUNK)), b"tail"
    if name == "chunk-plus-tail":
        return bytes((i * 17 + 5) % 251 for i in range(CHUNK + 19)), b"suffix"
    if name == "three-chunks-tail":
        return bytes((i * 29 + 7) % 251 for i in range(3 * CHUNK + 123)), b"END"
    raise ValueError(f"unknown ST3 vector case: {name}")


def render() -> bytes:
    cases = []
    for name in (
        "empty-to-abc",
        "one-byte",
        "chunk-boundary",
        "chunk-plus-tail",
        "three-chunks-tail",
    ):
        prefix, suffix = _case(name)
        checkpoint = checkpoint_bytes(prefix)
        wire = checkpoint.to_bytes()
        if wire != reference_checkpoint_wire(prefix):
            raise AssertionError("independent ST3 checkpoint wire divergence")
        product_root = resume_tree(checkpoint, suffix).to_bytes()
        reference_root = resume_checkpoint_wire(wire, suffix)
        if product_root != reference_root:
            raise AssertionError("independent ST3 resume divergence")

        cases.append(
            {
                "name": name,
                "prefix_length": len(prefix),
                "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                "suffix_length": len(suffix),
                "suffix_sha256": hashlib.sha256(suffix).hexdigest(),
                "completed_leaf_count": checkpoint.completed_leaf_count,
                "frontier_nodes": len(checkpoint.frontier.nodes),
                "tail_length": len(checkpoint.tail),
                "checkpoint_wire_bytes": len(wire),
                "checkpoint_wire_sha256": hashlib.sha256(wire).hexdigest(),
                "resumed_root_wire_sha256": hashlib.sha256(product_root).hexdigest(),
            }
        )
    return (
        json.dumps({"schema": "sigma-tree-v1-st3-kat", "cases": cases}, indent=2)
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
            parser.error("Sigma Tree ST3 KAT corpus is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(hashlib.sha256(payload).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
