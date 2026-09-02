from experiments.exp10_memory import _fit_models, run, summarize


def test_memory_model_selection_distinguishes_constant_and_linear() -> None:
    sizes = [1.0, 2.0, 4.0, 8.0, 16.0]
    assert _fit_models(sizes, [10.0] * 5)["selected_model"] == "constant"
    assert _fit_models(sizes, [2 * value + 3 for value in sizes])["selected_model"] == "linear"


def test_memory_experiment_uses_fresh_process_and_records_scope() -> None:
    records = run(
        {
            "io_chunks": [1024],
            "profiles": ["stream-wide", "tree-wide"],
            "repetitions": 1,
            "sizes": [0, 2048],
            "timeout_seconds": 30,
        }
    )
    assert len(records) == 4
    assert all(record["rss_scope"] == "current-process" for record in records)
    assert all(record["peak_allocated_bytes"] > 0 for record in records)
    summaries = summarize(records)
    assert len(summaries) == 6
    assert {group["dimension"] for group in summaries} == {"message_bytes", "target_round"}


def test_memory_experiment_models_depth_and_trace_policy_separately() -> None:
    records = run(
        {
            "io_chunks": [1024],
            "profiles": ["stream-wide"],
            "repetitions": 2,
            "sizes": [0],
            "state_counts": [3],
            "target_rounds": [16, 256],
            "trace_policies": ["none", "full"],
            "timeout_seconds": 30,
        }
    )
    assert len(records) == 8
    assert all(
        record["trace_entries"] == 0 for record in records if record["trace_policy"] == "none"
    )
    assert all(
        record["trace_entries"] > 0 for record in records if record["trace_policy"] == "full"
    )
    depth = [group for group in summarize(records) if group["dimension"] == "target_round"]
    assert len(depth) == 2


def test_revised_memory_experiment_covers_final_modes() -> None:
    profiles = ["wide-v2-2", "cross-wide-v2-2", "deep-v2-2", "deep-vector-v2-2"]
    records = run(
        {
            "io_chunks": [1024],
            "profiles": profiles,
            "repetitions": 1,
            "sizes": [0],
            "state_counts": [2],
            "target_rounds": [1],
            "trace_policies": ["none"],
            "timeout_seconds": 30,
        }
    )
    assert {record["profile"] for record in records} == set(profiles)
    assert all(record["rss_scope"] == "current-process" for record in records)
    assert all(record["disk_temporary_bytes"] == 0 for record in records)
    assert all("tracemalloc_peak" in group["memory_models"] for group in summarize(records))
