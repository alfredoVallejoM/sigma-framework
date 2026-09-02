import importlib.util

import pytest

from experiments.exp12_kdf import run, summarize


@pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None, reason="optional argon2-cffi absent"
)
def test_kdf_campaign_compares_registered_modes_at_same_argon_budget() -> None:
    records = run(
        {
            "candidates": 2,
            "master_seed": "test",
            "memory_kib": [1024],
            "modes": ["argon2id", "argon2id+wide", "argon2id+deep-vector"],
            "parallelism": 1,
            "repetitions": 1,
            "time_cost": [1],
        }
    )
    assert {record["mode"] for record in records} == {
        "argon2id",
        "argon2id+wide",
        "argon2id+deep-vector",
    }
    groups = summarize(records)
    assert len(groups) == 2
    assert all(group["same_argon2_budget"] for group in groups)
    assert all(group["all_matches_found"] for group in groups)
    assert all(group["median_postprocess_component_ns"] > 0 for group in groups)
