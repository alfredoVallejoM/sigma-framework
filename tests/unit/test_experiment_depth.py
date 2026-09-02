from experiments.exp06_depth import run, summarize


def test_depth_experiment_records_exact_adaptive_levels_and_work() -> None:
    records = run(
        {
            "candidate_counts": [1],
            "candidate_workers": [1],
            "master_seed": "test",
            "message_bytes": 8,
            "profiles": ["wide-once", "deep"],
            "repetitions": 1,
            "state_counts": [2],
            "target_rounds": [3],
        }
    )
    assert len(records) == 2
    wide, deep = records
    assert wide["critical_levels"] == deep["critical_levels"] == 4
    assert wide["round_queries"] == 4
    assert deep["round_queries"] == 20
    assert deep["model_parallel_round_span_queries"] == 8
    assert len(summarize(records)) == 2
