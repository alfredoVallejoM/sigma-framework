"""Generate/check the frozen Sigma Tree V1 ST0 KAT corpus from the independent oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference.tree_v1 import build, root_wire

DEFAULT_OUTPUT = Path("specification/test-vectors/sigma-tree-v1-st0.json")


def _input(name: str) -> bytes:
    if name == "empty":
        return b""
    if name == "abc":
        return b"abc"
    if name == "chunk_zeros":
        return b"\0" * 65_536
    if name == "chunk_plus_one":
        return bytes(i % 251 for i in range(65_537))
    if name == "three_chunks_tail":
        return b"A" * (3 * 65_536) + b"END"
    raise ValueError(f"unknown KAT case: {name}")


def render() -> bytes:
    cases = []
    for name in ("empty", "abc", "chunk_zeros", "chunk_plus_one", "three_chunks_tail"):
        data = _input(name)
        length, leaf_count, digests = build(data)
        wire = root_wire(data)
        cases.append(
            {
                "name": name,
                "length": length,
                "leaf_count": leaf_count,
                "sha256_input": hashlib.sha256(data).hexdigest(),
                "digests": [digest.hex() for digest in digests],
                "root_wire_sha256": hashlib.sha256(wire).hexdigest(),
            }
        )
    return (
        json.dumps({"schema": "sigma-tree-v1-st0-kat", "cases": cases}, indent=2) + "\n"
    ).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = render()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != payload:
            parser.error("Sigma Tree ST0 KAT corpus is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(hashlib.sha256(payload).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
