from __future__ import annotations

import tempfile
from pathlib import Path

from experiments.r15_reduced_shadow import (
    REDUCED_ATTACKS,
    SHADOW_D_NAMESPACE,
    execute_reduced_shadow_cell_v3,
    run_reduced_shadow_suite_v3,
    selected_reduced_shadow_cells_v3,
)
from scripts.check_r15_reduced_shadow import check_r15_reduced_shadow


def test_r15_d_shadow_gate_covers_reduced_campaign() -> None:
    report = check_r15_reduced_shadow()
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["namespace"] == SHADOW_D_NAMESPACE
    assert report["selected_cells"] == 32
    assert report["attacks"] == len(REDUCED_ATTACKS)


def test_reduced_shadow_cells_are_deterministic() -> None:
    for attack_id, cell in selected_reduced_shadow_cells_v3()[:12]:
        left = execute_reduced_shadow_cell_v3(attack_id, cell)
        right = execute_reduced_shadow_cell_v3(attack_id, cell)
        assert left == right


def test_reduced_shadow_suite_writes_complete_ledger() -> None:
    with tempfile.TemporaryDirectory(prefix="r15d-test-") as temporary:
        report = run_reduced_shadow_suite_v3(Path(temporary))
    assert report["records"] == 32
    assert isinstance(report["ledger_root"], str)
    assert len(report["ledger_root"]) == 64


def test_tmto_shadow_exercises_all_five_strategies() -> None:
    strategies = {
        cell.factors["strategy"]
        for attack_id, cell in selected_reduced_shadow_cells_v3()
        if attack_id in ("TMTO-01", "TMTO-02")
    }
    assert strategies == {"direct", "distinguished", "rho", "hellman", "rainbow"}
