from __future__ import annotations

import tempfile
from pathlib import Path

from experiments.r15_application_shadow import (
    SHADOW_E_NAMESPACE,
    run_application_shadow_suite_v3,
)
from scripts.check_r15_application_shadow import check_r15_application_shadow


def test_r15_e_application_shadow_gate() -> None:
    report = check_r15_application_shadow()
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["namespace"] == SHADOW_E_NAMESPACE
    assert report["attacks"] == ["PARAM-04", "PARAM-05", "PARAM-06"]


def test_application_shadow_writes_three_ledger_records() -> None:
    with tempfile.TemporaryDirectory(prefix="r15e-test-") as temporary:
        report = run_application_shadow_suite_v3(Path(temporary))
    assert report["records"] == 3
    assert isinstance(report["ledger_root"], str)
    assert len(report["ledger_root"]) == 64
