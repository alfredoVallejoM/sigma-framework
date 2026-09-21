from __future__ import annotations

from pathlib import Path

from experiments.r15_wave1_dataset import expected_wave1_runkeys
from experiments.r15_wave2_dataset import expected_wave2_runkeys
from experiments.r15_wave3a_dataset import (
    WAVE3A_EXPECTED_RUN_UNITS,
    expected_wave3a_runkeys,
)
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def test_wave3a_expected_runkeys_are_exact_unique_and_exclude_red04(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    keys = expected_wave3a_runkeys(configs)
    assert len(keys) == WAVE3A_EXPECTED_RUN_UNITS == 74_240
    assert len(keys) == len(set(keys))
    attacks = {key.attack_id for key in keys}
    assert attacks == {"RED-02", "RED-03", "RED-05", "TMTO-01", "TMTO-02"}
    assert "RED-04" not in attacks


def test_wave1_wave2_wave3a_runkeys_are_pairwise_disjoint(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    wave1 = set(expected_wave1_runkeys(configs))
    wave2 = set(expected_wave2_runkeys(configs))
    wave3a = set(expected_wave3a_runkeys(configs))
    assert wave1.isdisjoint(wave2)
    assert wave1.isdisjoint(wave3a)
    assert wave2.isdisjoint(wave3a)
    assert len(wave1 | wave2 | wave3a) == 132_160
