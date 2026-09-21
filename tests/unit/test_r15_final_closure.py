from __future__ import annotations

from pathlib import Path

from experiments.r15_final_closure import (
    ENGINEERING_ATTACKS,
    MANDATORY_EXPECTED_ATTACKS,
    MANDATORY_EXPECTED_RUN_UNITS,
    _expected_runkeys,
)
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def test_final_mandatory_runkeys_are_exact_and_exclude_engineering(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    keys = _expected_runkeys(configs)
    assert len(keys) == MANDATORY_EXPECTED_RUN_UNITS == 145_088
    assert len(keys) == len(set(keys))
    attacks = {key.attack_id for key in keys}
    assert len(attacks) == MANDATORY_EXPECTED_ATTACKS == 18
    assert not (attacks & ENGINEERING_ATTACKS)
    assert {"STAT-01", "RED-04", "PARAM-02"}.issubset(attacks)
