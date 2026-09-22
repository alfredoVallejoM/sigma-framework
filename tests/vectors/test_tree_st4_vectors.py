from __future__ import annotations

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


def _source(name: str) -> bytes:
    if name == "three_chunks_tail":
        return bytes((i * 17 + 5) % 251 for i in range(3 * CHUNK + 19))
    if name == "five_chunks":
        return bytes((i * 29 + 7) % 251 for i in range(5 * CHUNK))
    if name == "seven_chunks_tail":
        return bytes((i * 31 + 11) % 251 for i in range(7 * CHUNK + 23))
    raise AssertionError(name)


def _edits(name: str, source: bytes) -> list[TreeEditV1]:
    if name == "delta-one-byte":
        return [TreeEditV1(CHUNK + 7, 1, b"Z")]
    if name == "delta-cross-chunk":
        return [TreeEditV1(CHUNK - 2, 4, b"WXYZ")]
    if name == "delta-overlap":
        return [
            TreeEditV1(4, 4, b"EFGH"),
            TreeEditV1(0, 4, b"ABCD"),
            TreeEditV1(2, 4, b"CDEF"),
            TreeEditV1(8, 2, b"IJ"),
        ]
    if name == "delta-full-file":
        replacement = bytes((i * 7 + 19) % 251 for i in range(len(source)))
        return [TreeEditV1(0, len(source), replacement)]
    raise AssertionError(name)


def _suffix(name: str) -> bytes:
    if name == "append-tail":
        return b"suffix"
    if name == "append-chunk-tail":
        return bytes((i * 13 + 3) % 251 for i in range(CHUNK + 17))
    raise AssertionError(name)


def test_sigma_tree_st4_kats():
    path = Path("specification/test-vectors/sigma-tree-v1-st4.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema"] == "sigma-tree-v1-st4-kat"

    for case in payload["cases"]:
        source = _source(case["source"])
        assert len(source) == case["source_length"]
        assert hashlib.sha256(source).hexdigest() == case["source_sha256"]

        index = TreeDeltaIndex(source)
        if case["operation"] == "delta":
            edits = _edits(case["name"], source)
            tuples = [(edit.start, edit.delete_length, edit.data) for edit in edits]
            normalized = normalize_edits(tuples, len(source))
            expected = apply_same_length(source, tuples)
            result = index.apply_delta(edits)

            assert len(edits) == case["edit_count"]
            assert len(normalized) == case["normalized_count"]
            assert [[start, length] for start, length, _ in normalized] == case[
                "normalized_intervals"
            ]
            affected = affected_leaves(tuples, len(source))
            assert list(affected) == case["affected_leaves"]
            assert len(ancestor_closure(result.root.leaf_count, affected)) == case[
                "ancestor_nodes"
            ]
            if "replacement_sha256" in case:
                assert hashlib.sha256(edits[0].data).hexdigest() == case[
                    "replacement_sha256"
                ]
        else:
            suffix = _suffix(case["name"])
            expected = source + suffix
            result = index.append(suffix)
            assert len(suffix) == case["suffix_length"]
            assert hashlib.sha256(suffix).hexdigest() == case["suffix_sha256"]
            assert result.root.to_bytes() == append_root_wire(source, suffix)

        assert index.materialize() == expected
        assert hashlib.sha256(expected).hexdigest() == case["result_sha256"]
        assert hashlib.sha256(result.root.to_bytes()).hexdigest() == case[
            "root_wire_sha256"
        ]
