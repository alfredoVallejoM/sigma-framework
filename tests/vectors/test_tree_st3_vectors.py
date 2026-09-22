from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reference.tree_checkpoint_v1 import checkpoint_wire as reference_checkpoint_wire
from reference.tree_checkpoint_v1 import resume_checkpoint_wire
from sigma.tree import checkpoint_bytes, resume_tree

CHUNK = 65_536


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
    raise AssertionError(name)


def test_sigma_tree_st3_kats():
    path = Path("specification/test-vectors/sigma-tree-v1-st3.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema"] == "sigma-tree-v1-st3-kat"

    for case in payload["cases"]:
        prefix, suffix = _case(case["name"])
        checkpoint = checkpoint_bytes(prefix)
        wire = checkpoint.to_bytes()

        assert len(prefix) == case["prefix_length"]
        assert hashlib.sha256(prefix).hexdigest() == case["prefix_sha256"]
        assert len(suffix) == case["suffix_length"]
        assert hashlib.sha256(suffix).hexdigest() == case["suffix_sha256"]
        assert checkpoint.completed_leaf_count == case["completed_leaf_count"]
        assert len(checkpoint.frontier.nodes) == case["frontier_nodes"]
        assert len(checkpoint.tail) == case["tail_length"]
        assert len(wire) == case["checkpoint_wire_bytes"]
        assert hashlib.sha256(wire).hexdigest() == case["checkpoint_wire_sha256"]
        assert wire == reference_checkpoint_wire(prefix)

        product_root = resume_tree(checkpoint, suffix).to_bytes()
        assert product_root == resume_checkpoint_wire(wire, suffix)
        assert hashlib.sha256(product_root).hexdigest() == case["resumed_root_wire_sha256"]
