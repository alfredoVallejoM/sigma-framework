from experiments.exp09_performance import run, summarize


def test_performance_experiment_separates_operations_and_reports_intervals() -> None:
    records = run(
        {
            "constructions": ["sha256", "sigma-wide"],
            "master_seed": "test",
            "operations": ["full-hash", "anchor", "rounds", "serialization", "verification"],
            "processes": 1,
            "repetitions": 2,
            "sizes": [0, 8],
            "warmups": 1,
        }
    )
    assert {record["operation"] for record in records} == {
        "full-hash",
        "anchor",
        "rounds",
        "serialization",
        "verification",
    }
    groups = summarize(records)
    assert all(group["bootstrap_median_low_ns"] <= group["median_ns"] for group in groups)
    assert all(group["median_ns"] <= group["bootstrap_median_high_ns"] for group in groups)
