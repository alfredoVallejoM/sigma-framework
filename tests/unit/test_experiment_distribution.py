import math

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
