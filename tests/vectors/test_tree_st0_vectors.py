import hashlib
import json
from pathlib import Path

from sigma.tree import build_tree


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
    raise AssertionError(name)


def test_sigma_tree_st0_kats():
    vector_path = Path("specification/test-vectors/sigma-tree-v1-st0.json")
    payload = json.loads(vector_path.read_text(encoding="utf-8"))
    assert payload["schema"] == "sigma-tree-v1-st0-kat"
    for case in payload["cases"]:
        data = _input(case["name"])
        assert len(data) == case["length"]
        assert hashlib.sha256(data).hexdigest() == case["sha256_input"]
        root = build_tree(data)
        assert root.leaf_count == case["leaf_count"]
        assert [d.hex() for d in root.digests] == case["digests"]
        assert hashlib.sha256(root.to_bytes()).hexdigest() == case["root_wire_sha256"]
