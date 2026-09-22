"""Generate/check frozen Sigma Tree V1 ST4 semantic vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference.tree_delta_v1 import (
    affected_leaves,
    ancestor_closure,
    append_root_wire,
    apply_same_length,
    normalize_edits,
)
from sigma.tree import TreeDeltaIndex, TreeEditV1

CHUNK = 65_536
DEFAULT_OUTPUT = Path("specification/test-vectors/sigma-tree-v1-st4.json")


def _source(name: str) -> bytes:
    if name == "three_chunks_tail":
        return bytes((i * 17 + 5) % 251 for i in range(3 * CHUNK + 19))
    if name == "five_chunks":
        return bytes((i * 29 + 7) % 251 for i in range(5 * CHUNK))
    if name == "seven_chunks_tail":
        return bytes((i * 31 + 11) % 251 for i in range(7 * CHUNK + 23))
    raise ValueError(f"unknown ST4 source: {name}")


def _delta_case(name: str, source_name: str, edits: list[TreeEditV1]) -> dict[str, object]:
    source = _source(source_name)
    tuples = [(edit.start, edit.delete_length, edit.data) for edit in edits]
    normalized = normalize_edits(tuples, len(source))
    expected = apply_same_length(source, tuples)
    product = TreeDeltaIndex(source)
    result = product.apply_delta(edits)
    if result.root.to_bytes() != append_root_wire(expected, b""):
        raise AssertionError(f"ST4 delta product/reference divergence: {name}")
    affected = affected_leaves(tuples, len(source))
    closure = ancestor_closure(result.root.leaf_count, affected)
    if result.telemetry.invalidated_nodes != closure:
        raise AssertionError(f"ST4 delta closure divergence: {name}")
    row: dict[str, object] = {
        "name": name,
        "operation": "delta",
        "source": source_name,
        "source_length": len(source),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "edit_count": len(edits),
        "normalized_count": len(normalized),
        "normalized_intervals": [[start, length] for start, length, _ in normalized],
        "affected_leaves": list(affected),
        "ancestor_nodes": len(closure),
        "result_sha256": hashlib.sha256(expected).hexdigest(),
        "root_wire_sha256": hashlib.sha256(result.root.to_bytes()).hexdigest(),
    }
    if name == "delta-full-file":
        row["replacement_sha256"] = hashlib.sha256(edits[0].data).hexdigest()
    return row


def _append_case(name: str, source_name: str, suffix: bytes) -> dict[str, object]:
    source = _source(source_name)
    expected = source + suffix
    product = TreeDeltaIndex(source)
    result = product.append(suffix)
    if result.root.to_bytes() != append_root_wire(source, suffix):
        raise AssertionError(f"ST4 append product/reference divergence: {name}")
    return {
        "name": name,
        "operation": "append",
        "source": source_name,
        "source_length": len(source),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "suffix_length": len(suffix),
        "suffix_sha256": hashlib.sha256(suffix).hexdigest(),
        "result_sha256": hashlib.sha256(expected).hexdigest(),
        "root_wire_sha256": hashlib.sha256(result.root.to_bytes()).hexdigest(),
    }


def render() -> bytes:
    five_chunks = _source("five_chunks")
    full_replacement = bytes((i * 7 + 19) % 251 for i in range(len(five_chunks)))
    cases = [
        _delta_case(
            "delta-one-byte",
            "three_chunks_tail",
            [TreeEditV1(CHUNK + 7, 1, b"Z")],
        ),
        _delta_case(
            "delta-cross-chunk",
            "three_chunks_tail",
            [TreeEditV1(CHUNK - 2, 4, b"WXYZ")],
        ),
        _delta_case(
            "delta-overlap",
            "three_chunks_tail",
            [
                TreeEditV1(4, 4, b"EFGH"),
                TreeEditV1(0, 4, b"ABCD"),
                TreeEditV1(2, 4, b"CDEF"),
                TreeEditV1(8, 2, b"IJ"),
            ],
        ),
        _delta_case(
            "delta-full-file",
            "five_chunks",
            [TreeEditV1(0, len(five_chunks), full_replacement)],
        ),
        _append_case("append-tail", "seven_chunks_tail", b"suffix"),
        _append_case(
            "append-chunk-tail",
            "five_chunks",
            bytes((i * 13 + 3) % 251 for i in range(CHUNK + 17)),
        ),
    ]
    return (
        json.dumps({"schema": "sigma-tree-v1-st4-kat", "cases": cases}, indent=2)
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
            parser.error("Sigma Tree ST4 KAT corpus is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(hashlib.sha256(payload).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
