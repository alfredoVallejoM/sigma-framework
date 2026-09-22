from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any

from reference.trajectory_audit_v3 import (
    MODE_COMPACT,
    MODE_FULL,
    audit_from_reference_evaluation,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    TrajectoryAuditModeV3,
    audit_from_evaluation_v3,
    project_digest_v3,
    verify_trajectory_audit_full_v3,
    verify_trajectory_audit_structure_v3,
)
from sigma.v3 import evaluate_v3

CORPUS_PATH = (
    Path(__file__).parents[2]
    / "specification"
    / "test-vectors"
    / "conformance-v3-r12-5.json.gz.b64"
)


def _document() -> dict[str, Any]:
    decoded = gzip.decompress(base64.b64decode(CORPUS_PATH.read_text(encoding="ascii")))
    return json.loads(decoded.decode("utf-8"))


def _reference_evaluation_from_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "states": tuple(bytes.fromhex(value) for value in case["states_hex"]),
        "round_layouts": tuple(
            bytes.fromhex(item["wire_hex"]) for item in case["round_layouts"]
        ),
        "histories": tuple(bytes.fromhex(value) for value in case["histories_hex"]),
        "round_bindings": tuple(
            bytes.fromhex(value) for value in case["round_bindings_hex"]
        ),
        "round_frames": tuple(
            bytes.fromhex(value) for value in case["round_frames_hex"]
        ),
        "branch_frames": tuple(
            tuple(bytes.fromhex(value) for value in group)
            for group in case["branch_frames_hex"]
        ),
        "branch_outputs": tuple(
            tuple(bytes.fromhex(value) for value in group)
            for group in case["branch_outputs_hex"]
        ),
        "fold_frames": tuple(
            bytes.fromhex(value) for value in case["fold_frames_hex"]
        ),
        "digest": bytes.fromhex(case["digest_hex"]),
        "binding": bytes.fromhex(case["binding_hex"]),
        "init_layout": bytes.fromhex(case["init_layout"]["wire_hex"]),
    }


def test_sv0_replays_entire_frozen_r125_corpus() -> None:
    document = _document()
    assert document["schema"] == "sigma-v3-conformance-r12-5-history"

    for case in document["cases"]:
        suite_id = SuiteIdV3(int(case["suite_id"], 16))
        message = bytes.fromhex(case["message_hex"])
        context = SigmaContextV3.for_suite(
            suite_id,
            salt=bytes.fromhex(case["salt_hex"]),
            challenge=bytes.fromhex(case["challenge_hex"]),
            application_context=bytes.fromhex(case["application_context_hex"]),
        )
        evaluation = evaluate_v3(context, BytesSource(message))
        reference = _reference_evaluation_from_case(case)

        compact = audit_from_evaluation_v3(
            evaluation, mode=TrajectoryAuditModeV3.COMPACT
        )
        full = audit_from_evaluation_v3(
            evaluation, mode=TrajectoryAuditModeV3.FULL
        )

        assert project_digest_v3(compact).to_bytes().hex() == case["digest_hex"]
        assert project_digest_v3(full).to_bytes().hex() == case["digest_hex"]
        assert [value.hex() for value in compact.histories] == case["histories_hex"]
        assert compact.states == tuple(reference["states"])
        assert len(compact.states) == case["t"] + case["k"]
        assert len(compact.rounds) == len(compact.states) - 1

        assert compact.to_bytes() == audit_from_reference_evaluation(
            reference, mode=MODE_COMPACT
        )
        assert full.to_bytes() == audit_from_reference_evaluation(
            reference, mode=MODE_FULL
        )

        assert verify_trajectory_audit_structure_v3(compact)
        assert verify_trajectory_audit_structure_v3(full)
        assert verify_trajectory_audit_full_v3(BytesSource(message), compact)
        assert verify_trajectory_audit_full_v3(BytesSource(message), full)
