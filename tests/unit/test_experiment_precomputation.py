from experiments.exp17_precomputation import run, summarize


def test_precomputation_campaign_covers_registered_attackers() -> None:
    strategies = [
        "direct-table",
        "distinguished-points",
        "rho",
        "hellman",
        "rainbow",
        "multicollision",
    ]
    records = run(
        {
            "anchor_counts": [2, 3],
            "chain_length": 4,
            "distinguished_bits": 2,
            "master_seed": "test",
            "repetitions": 2,
            "strategies": strategies,
            "table_entries": 16,
            "widths": [6],
        }
    )
    assert {record["strategy"] for record in records} == set(strategies)
    assert {record["construction"] for record in records} == {"stationary", "reinjected"}
    assert all(record["total_queries"] > 0 for record in records)
    assert all(record["parallel_depth"] > 0 for record in records)
    assert all(0 <= record["reuse_rate"] <= 1 for record in records)
    groups = summarize(records)
    assert len(groups) == len(strategies) * 2 * 2


def test_stationary_direct_table_is_fully_reusable_across_anchors() -> None:
    records = run(
        {
            "anchor_counts": [3],
            "distinguished_bits": 2,
            "master_seed": "control",
            "repetitions": 1,
            "strategies": ["direct-table"],
            "table_entries": 16,
            "widths": [8],
        }
    )
    stationary = next(record for record in records if record["construction"] == "stationary")
    assert stationary["reuse_rate"] == 1.0
