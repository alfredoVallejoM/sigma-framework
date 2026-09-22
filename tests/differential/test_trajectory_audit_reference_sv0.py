from __future__ import annotations

import ast
from pathlib import Path

import pytest

from reference.independent_v3 import evaluate_suite
from reference.trajectory_audit_v3 import (
    MODE_COMPACT,
    MODE_FULL,
    audit_from_reference_evaluation,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import TrajectoryAuditModeV3, audit_from_evaluation_v3
from sigma.v3 import evaluate_v3

ALL_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


@pytest.mark.parametrize("suite_id", ALL_SUITES)
@pytest.mark.parametrize("message", [b"", b"sv0-reference", bytes(range(32))])
@pytest.mark.parametrize(
    "mode,reference_mode",
    (
        (TrajectoryAuditModeV3.COMPACT, MODE_COMPACT),
        (TrajectoryAuditModeV3.FULL, MODE_FULL),
    ),
)
def test_product_audit_matches_independent_reference(
    suite_id: SuiteIdV3,
    message: bytes,
    mode: TrajectoryAuditModeV3,
    reference_mode: int,
):
    salt = b"sv0-independent"
    challenge = b"challenge"
    application_context = b"tests/differential/sv0"

    context = SigmaContextV3.for_suite(
        suite_id,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    actual_evaluation = evaluate_v3(context, BytesSource(message))
    actual = audit_from_evaluation_v3(actual_evaluation, mode=mode)

    expected_evaluation = evaluate_suite(
        message,
        suite_id=int(suite_id),
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    expected = audit_from_reference_evaluation(
        expected_evaluation,
        mode=reference_mode,
    )
    assert actual.to_bytes() == expected


def test_independent_audit_encoder_never_imports_sigma() -> None:
    path = Path(__file__).parents[2] / "reference" / "trajectory_audit_v3.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(name == "sigma" or name.startswith("sigma.") for name in imported)
