from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from sigma.tree import TreeProofIndex

CHUNK = 65_536


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
    raise AssertionError(name)


def test_sigma_tree_st2_kats():
    vector_path = Path("specification/test-vectors/sigma-tree-v1-st2.json")
    payload = json.loads(vector_path.read_text(encoding="utf-8"))
    assert payload["schema"] == "sigma-tree-v1-st2-kat"

    for case in payload["cases"]:
        data = _payload(case["source"])
        assert hashlib.sha256(data).hexdigest() == case["source_sha256"]
        index = TreeProofIndex(data)

        if case["kind"] == "inclusion":
            leaf_index = case["leaf_index"]
            start = leaf_index * CHUNK
            leaf = data[start : min(start + CHUNK, len(data))]
            proof = index.prove_leaf(leaf_index)
            wire = proof.to_bytes()
            assert len(leaf) == case["leaf_length"]
            assert len(proof.steps) == case["steps"]
            assert verify_inclusion_wire(leaf, wire)
        else:
            start = case["start"]
            length = case["length"]
            selected = data[start : start + length]
            proof = index.prove_range(start, length)
            wire = proof.to_bytes()
            assert len(proof.prefix) == case["prefix_bytes"]
            assert len(proof.suffix) == case["suffix_bytes"]
            assert len(proof.witnesses) == case["witnesses"]
            assert verify_range_wire(selected, wire)

        assert hashlib.sha256(proof.root.to_bytes()).hexdigest() == case["root_wire_sha256"]
        assert len(wire) == case["proof_wire_bytes"]
        assert hashlib.sha256(wire).hexdigest() == case["proof_wire_sha256"]
