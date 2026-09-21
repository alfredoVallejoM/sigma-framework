from __future__ import annotations

from pathlib import Path

from experiments.r15_wave1_dataset import (
    WAVE1_EXPECTED_RUN_UNITS,
    expected_wave1_runkeys,
)
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def test_wave1_expected_runkeys_are_exact_and_unique(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    keys = expected_wave1_runkeys(configs)
    assert len(keys) == WAVE1_EXPECTED_RUN_UNITS == 8_256
    assert len(keys) == len(set(keys))
    assert {key.attack_id for key in keys} == {"HIST-01", "PARAM-01", "PARAM-03"}
