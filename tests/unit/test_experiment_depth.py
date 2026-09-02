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


def test_revised_depth_counts_vector_work_span_and_speedup() -> None:
    records = run(
        {
            "candidate_counts": [1, 2],
            "candidate_workers": [1, 2],
            "master_seed": "revised",
            "message_bytes": 8,
            "profiles": ["wide-once", "deep", "deep-vector"],
            "repetitions": 1,
            "state_counts": [2],
            "suite_family": "v2-2",
            "target_rounds": [3],
        }
    )
    single = {
        record["profile"]: record
        for record in records
        if record["candidates"] == 1 and record["candidate_workers"] == 1
    }
    assert single["wide-once"]["total_primitive_queries"] == 7
    assert single["deep"]["total_primitive_queries"] == 29
    assert single["deep-vector"]["total_primitive_queries"] == 28
    assert single["deep-vector"]["model_parallel_round_span_queries"] == 4
    groups = summarize(records)
    assert all(group["speedup_vs_worker1"] is not None for group in groups)
    assert all(group["median_anchor_wall_ns_sum"] > 0 for group in groups)
    assert all(group["median_round_wall_ns_sum"] > 0 for group in groups)
    assert all(group["quality_control_passed"] for group in groups)
    assert all(group["robust_regression_cells"] >= 1 for group in groups)
    assert all("robust_precomputed_round_slope_ns_per_level" in group for group in groups)
