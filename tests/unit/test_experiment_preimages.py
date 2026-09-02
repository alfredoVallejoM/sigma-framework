from experiments.exp20_preimages import run, summarize


def test_preimage_campaign_separates_games_attackers_and_query_classes() -> None:
    records = run(
        {
            "anchor_multipliers": [1, 2],
            "attackers": ["random-search", "exhaustive", "inversion-table"],
            "constructions": ["simple", "reinjected", "deep-vector"],
            "games": ["preimage", "second-preimage", "multi-target"],
            "master_seed": "test",
            "max_candidates": 64,
            "repetitions": 1,
            "state_counts": [1, 2],
            "target_counts": [1, 2],
            "target_kinds": ["regular-image", "uniform"],
            "widths": [3, 4],
        }
    )
    assert {record["game"] for record in records} == {
        "preimage",
        "second-preimage",
        "multi-target",
    }
    assert {record["attacker"] for record in records} == {
        "random-search",
        "exhaustive",
        "inversion-table",
    }
    assert all(record["anchor_queries"] >= record["candidates"] for record in records)
    assert all(record["round_queries"] >= record["candidates"] for record in records)
    assert all(record["memory_entries"] >= 1 for record in records)
    groups = summarize(records)
    assert all(group["restricted_mean_candidates"] > 0 for group in groups)
    assert all(group["work_exponent_width_cells"] >= 1 for group in groups)


def test_second_preimage_never_uses_uniform_target() -> None:
    records = run(
        {
            "master_seed": "second",
            "max_candidates": 16,
            "repetitions": 1,
            "state_counts": [1],
            "target_kinds": ["regular-image", "uniform"],
            "widths": [3],
        }
    )
    assert not any(
        record["game"] == "second-preimage" and record["target_kind"] == "uniform"
        for record in records
    )
