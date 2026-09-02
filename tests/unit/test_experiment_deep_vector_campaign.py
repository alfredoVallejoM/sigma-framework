from experiments.exp18_deep_vector import run, summarize


def test_fold_vector_campaign_models_segments_faults_and_widths() -> None:
    records = run(
        {
            "branch_counts": [2],
            "faults": ["normal", "constant-fold", "omitted-last"],
            "master_seed": "test",
            "max_candidates": 128,
            "repetitions": 2,
            "state_counts": [1, 2],
            "target_rounds": [1, 2],
            "widths": [4],
        }
    )
    assert {record["mode"] for record in records} == {"deep-fold", "deep-vector"}
    assert {record["state_count"] for record in records} == {1, 2}
    assert all(record["primitive_queries"] > 0 for record in records)
    assert all(record["conservative_bits"] <= record["physical_bits"] for record in records)
    assert not any(
        record["mode"] == "deep-vector" and record["fault"] == "constant-fold" for record in records
    )
    assert all(group["restricted_mean_candidates"] > 0 for group in summarize(records))


def test_constant_fold_collides_immediately() -> None:
    records = run(
        {
            "branch_counts": [2],
            "faults": ["constant-fold"],
            "master_seed": "constant",
            "max_candidates": 16,
            "repetitions": 2,
            "widths": [8],
        }
    )
    assert all(record["mode"] == "deep-fold" for record in records)
    assert all(record["candidates"] == 2 for record in records)
    assert all(record["conservative_bits"] == 0 for record in records)
