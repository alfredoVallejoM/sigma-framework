import json
from pathlib import Path

import pytest

from scripts.generate_conformance_vectors import generate
from sigma.anchors import AnchorEvidence, CrossWideEvidence
from sigma.applications.kdf_argon2id import Argon2idParameters, SigmaPasswordRecord
from sigma.applications.pow import PowParameters
from sigma.applications.signed import SigmaSignedCommitmentV2
from sigma.outputs import SigmaDigestV2
from sigma.presets import paranoid_wide_v2_2, reference_v2_2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError

VECTOR_PATH = Path(__file__).parents[2] / "specification" / "test-vectors" / "conformance-v2-2.json"


def test_complete_conformance_vector_matches_generator() -> None:
    current = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert generate() == current
    assert current["format"] == "sigma-conformance-v2"
    assert current["normative_suite_family"] == "v2-2"
    assert len(current["suites"]) == 6
    assert len(current["applications"]["pow"]) == 3
    assert len(current["applications"]["kdf"]) == 4
    assert len(current["applications"]["signed"]) == 6
    assert len(current["negative"]) == 24


def test_normative_negative_corpus_is_rejected() -> None:
    current = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    reference_context = reference_v2_2(target_round=2, state_count=3)
    cross_context = paranoid_wide_v2_2(target_round=2, state_count=3)
    parsers = {
        "context": SigmaContextV2.from_bytes,
        "digest": SigmaDigestV2.from_bytes,
        "evidence-wide": lambda data: AnchorEvidence.from_bytes(data, reference_context),
        "evidence-cross": lambda data: CrossWideEvidence.from_bytes(data, cross_context),
        "pow": PowParameters.from_bytes,
        "kdf-parameters": Argon2idParameters.from_bytes,
        "kdf-record": SigmaPasswordRecord.from_bytes,
        "signed": SigmaSignedCommitmentV2.from_bytes,
    }
    for vector in current["negative"]:
        with pytest.raises(DecodeError):
            parsers[vector["codec"]](bytes.fromhex(vector["encoded_hex"]))
