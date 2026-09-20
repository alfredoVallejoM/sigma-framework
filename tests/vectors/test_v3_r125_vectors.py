from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path

from scripts.generate_v3_r125_corpus import render_corpus
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.v3 import evaluate_v3

CORPUS_PATH = (
    Path(__file__).parents[2]
    / "specification"
    / "test-vectors"
    / "conformance-v3-r12-5.json.gz.b64"
)

KATS = {
    "0x0321": "7a193b729984b4000d86ae97db449164dc7e1dbbde18f343216e2043d275e63b",
    "0x0323": "f20d6f602264a5b024651faa9da29a3adbb4f9df9345c19dcab82dc119193258",
    "0x0324": "a2305b9e18a873224ddedef1f6dd6938d199b0bdfc1b59dfd3d37fcd41ee3809",
}


def _document() -> dict[str, object]:
    decoded = gzip.decompress(base64.b64decode(CORPUS_PATH.read_text(encoding="ascii")))
    return json.loads(decoded.decode("utf-8"))


def test_r125_frozen_corpus_is_exactly_regenerable() -> None:
    decoded = gzip.decompress(base64.b64decode(CORPUS_PATH.read_text(encoding="ascii")))
    assert decoded.decode("utf-8") == render_corpus()


def test_r125_corpus_covers_all_history_suites_and_kats() -> None:
    document = _document()
    assert document["schema"] == "sigma-v3-conformance-r12-5-history"
    cases = document["cases"]
    assert isinstance(cases, list)
    assert {case["suite_id"] for case in cases} == set(KATS)
    assert {case["digest_sha256"] for case in cases} == set(KATS.values())
    for case in cases:
        assert case["t"] == 2
        assert case["k"] == 2
        assert len(case["histories_hex"]) == 4
        assert len(case["round_bindings_hex"]) == 3


def test_r125_corpus_matches_productive_digest_and_history() -> None:
    document = _document()
    cases = document["cases"]
    assert isinstance(cases, list)
    for case in cases:
        suite_id = SuiteIdV3(int(case["suite_id"], 16))
        message = bytes.fromhex(case["message_hex"])
        context = SigmaContextV3.for_suite(
            suite_id,
            salt=bytes.fromhex(case["salt_hex"]),
            challenge=bytes.fromhex(case["challenge_hex"]),
            application_context=bytes.fromhex(case["application_context_hex"]),
        )
        evaluation = evaluate_v3(context, BytesSource(message))
        assert [item.to_bytes().hex() for item in evaluation.histories] == case[
            "histories_hex"
        ]
        digest = digest_from_evaluation_v3(evaluation).to_bytes()
        assert digest.hex() == case["digest_hex"]
        assert hashlib.sha256(digest).hexdigest() == KATS[case["suite_id"]]
