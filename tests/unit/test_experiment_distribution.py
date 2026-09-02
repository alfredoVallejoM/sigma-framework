import math

import pytest

from experiments.exp08_distribution import _gammaincc, run, summarize


def test_gamma_survival_known_special_cases() -> None:
    assert math.isclose(_gammaincc(1.0, 2.0), math.exp(-2.0), rel_tol=1e-12)
    assert _gammaincc(2.0, 0.0) == 1.0


def test_distribution_experiment_publishes_every_p_value() -> None:
    records = run(
        {
            "constructions": ["sha256", "sigma-wide"],
            "corpora": ["counter"],
            "message_bytes": 8,
            "messages": 32,
        }
    )
    groups = summarize(records)
    assert len(records) == 64
    assert len(groups) == 2
    assert all(len(group["p_values"]) == 4 for group in groups)
    assert all(group["unique_outputs"] == 32 for group in groups)


def test_revised_distribution_keeps_states_and_streams_separate() -> None:
    records = run(
        {
            "constructions": ["sha512", "sigma-deep-vector"],
            "corpora": ["counter"],
            "message_bytes": 8,
            "messages": 8,
            "streams": 2,
            "suite_family": "v2-2",
        }
    )
    groups = summarize(records)
    sigma_domains = {
        str(record["domain"])
        for record in records
        if record["construction"] == "sigma-deep-vector"
    }
    assert sigma_domains == {"state-0", "state-1"}
    assert len(groups) == 6
    assert all(group["stream_count"] == 2 for group in groups)
    assert all(group["p_value_count"] == 8 for group in groups)
    assert all(0 <= group["uniformity_ks_statistic"] <= 1 for group in groups)


def test_distribution_rejects_empty_stream_grid() -> None:
    with pytest.raises(ValueError, match="streams must be positive"):
        run(
            {
                "constructions": ["sha512"],
                "corpora": ["counter"],
                "message_bytes": 8,
                "streams": 0,
            }
        )
