from __future__ import annotations

from pathlib import Path

from experiments.r15_wave1_dataset import expected_wave1_runkeys
from experiments.r15_wave2_dataset import (
    WAVE2_EXPECTED_RUN_UNITS,
    expected_wave2_runkeys,
)
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def test_wave2_expected_runkeys_are_exact_and_unique(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    keys = expected_wave2_runkeys(configs)
    assert len(keys) == WAVE2_EXPECTED_RUN_UNITS == 49_664
    assert len(keys) == len(set(keys))
    assert {key.attack_id for key in keys} == {
        "HIST-01",
        "HIST-02",
        "HIST-03",
        "HIST-05",
        "HIST-06",
        "LAYOUT-04",
        "BRANCH-05",
        "BRANCH-06",
    }


def test_wave1_and_wave2_runkeys_are_disjoint(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    wave1 = set(expected_wave1_runkeys(configs))
    wave2 = set(expected_wave2_runkeys(configs))
    assert wave1.isdisjoint(wave2)
    assert len(wave1 | wave2) == 57_920
