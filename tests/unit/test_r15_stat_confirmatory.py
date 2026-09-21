from __future__ import annotations

import json
from pathlib import Path

from experiments.r15_stat_confirmatory import (
    _nist_flagged_lines,
    _practrand_counts,
    _selected_runs,
)
from experiments.r15_stat_dataset import (
    EXPECTED_STAT_RUN_UNITS,
    expected_stat_runkeys,
)
from experiments.r141_schema import config_from_dict_r141
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def test_stat_expected_runkeys_are_exact_and_unique(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    keys = expected_stat_runkeys(configs)
    assert len(keys) == EXPECTED_STAT_RUN_UNITS == 1_536
    assert len(keys) == len(set(keys))
    assert {key.attack_id for key in keys} == {"STAT-01"}


def test_stat_sharding_selects_three_streams_per_construction_shard(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    config = config_from_dict_r141(
        json.loads((configs / "stat-01.json").read_text(encoding="utf-8"))
    )
    for shard in range(64):
        selected = _selected_runs(
            config,
            construction="SHA512",
            shard_index=shard,
            shard_count=64,
        )
        assert len(selected) == 3


def test_nist_flag_parser_counts_only_flagged_result_lines() -> None:
    report = """
    ------------------------------------------------------------------
    10 0 0 0 0 0 0 0 0 0 0.534146  510/512 Frequency
    0  0 0 0 0 0 0 0 0 0 0.000010 * 490/512 * Runs
    **********************
    """
    assert _nist_flagged_lines(report) == 1


def test_practrand_parser_separates_fail_and_suspicious() -> None:
    output = """
    [Low1/32]Gap R= +7.0 p = 1e-6 suspicious
    [Low4/32]BCFN R= +20 p = 1e-15 FAIL !!!
    another R= +6.3 p = 1e-5 VERY SUSPICIOUS
    ...and 50 test result(s) without anomalies
    """
    fail, suspicious = _practrand_counts(output)
    assert fail == 1
    assert suspicious == 2
