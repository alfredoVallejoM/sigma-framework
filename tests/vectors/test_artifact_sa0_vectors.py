from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.product_closure.generate_sa0_vectors import render

VECTOR_PATH = (
    Path(__file__).parents[2]
    / "specification"
    / "test-vectors"
    / "sigma-artifact-v1-sa0.json"
)


def test_sigma_artifact_sa0_vectors_are_frozen():
    payload = VECTOR_PATH.read_bytes()
    assert payload == render()
    assert (
        hashlib.sha256(payload).hexdigest()
        == "60a0405516dd55b5ce52f14a442c12f836128357ac7b838a28f8d7b5eb748631"
    )
