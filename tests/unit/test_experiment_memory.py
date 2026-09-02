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
    assert len(summarize(records)) == 2
