from experiments.exp01_canonicality import run


def test_exp01_large_path_streams_without_semantic_divergence() -> None:
    records = run(
        {
            "schema_version": 1,
            "experiment": "EXP-01",
            "master_seed": "test",
            "max_in_memory_bytes": 8,
            "presets": ["lightweight-v2-2", "simultaneous-v2-2"],
            "sizes": [9],
            "state_count": 2,
            "target_round": 1,
            "workers": [1, 2],
        }
    )
    assert records
    assert all(record["anchor_match"] for record in records)
    assert all(record["digest_match"] for record in records)
    assert all(record["transcript_match"] for record in records)
