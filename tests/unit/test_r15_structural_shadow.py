from __future__ import annotations

import tempfile
from pathlib import Path

from experiments.r15_structural_shadow import (
    SHADOW_NAMESPACE,
    STRUCTURAL_ATTACKS,
    execute_structural_shadow_cell_v3,
    run_structural_shadow_suite_v3,
    selected_shadow_cells_v3,
)
from scripts.check_r15_structural_shadow import check_r15_structural_shadow


def test_r15_c_shadow_gate_covers_structural_campaign() -> None:
    report = check_r15_structural_shadow()
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["namespace"] == SHADOW_NAMESPACE
    assert report["selected_cells"] == 33
    assert report["attacks"] == len(STRUCTURAL_ATTACKS)


def test_selected_shadow_cells_are_real_r141_cells() -> None:
    selected = selected_shadow_cells_v3()
    assert len(selected) == 33
    assert all(cell.cell_id.startswith(attack_id.lower()) for attack_id, cell in selected)


def test_each_shadow_cell_is_deterministic() -> None:
    for attack_id, cell in selected_shadow_cells_v3()[:10]:
        left = execute_structural_shadow_cell_v3(attack_id, cell)
        right = execute_structural_shadow_cell_v3(attack_id, cell)
        assert left == right


def test_shadow_suite_writes_complete_ledger() -> None:
    with tempfile.TemporaryDirectory(prefix="r15c-test-") as temporary:
        report = run_structural_shadow_suite_v3(Path(temporary))
    assert report["records"] == 33
    assert isinstance(report["ledger_root"], str)
    assert len(report["ledger_root"]) == 64


def test_branch06_fault_variants_are_all_exercised() -> None:
    faults = {
        cell.factors["fault"]
        for attack_id, cell in selected_shadow_cells_v3()
        if attack_id == "BRANCH-06"
    }
    assert faults == {
        "normal",
        "constant-first",
        "copied-first-two",
        "truncated-first",
        "omitted-last",
        "permuted",
    }
