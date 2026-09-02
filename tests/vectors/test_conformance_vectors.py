import json
from pathlib import Path

from scripts.generate_conformance_vectors import generate

VECTOR_PATH = Path(__file__).parents[2] / "specification" / "test-vectors" / "conformance-v2-2.json"


def test_complete_conformance_vector_matches_generator() -> None:
    frozen = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert generate() == frozen
    assert len(frozen["suites"]) == 6
