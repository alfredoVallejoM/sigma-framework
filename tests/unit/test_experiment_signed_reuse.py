from experiments.exp19_signed_reuse import run, summarize


def test_signed_reuse_separates_anchor_state_and_verification_work() -> None:
    records = run(
        {
            "anchor_multipliers": [1, 2],
            "master_seed": "test",
            "max_candidates": 256,
            "repetitions": 2,
            "state_counts": [1, 2],
            "target_rounds": [1, 3],
            "widths": [4],
        }
    )
    assert {record["commitment"] for record in records} == {
        "one-state",
        "multi-state",
        "anchor-and-states",
    }
    assert {record["anchor_bits"] for record in records} == {4, 8}
    assert all(record["signature_algorithm"] == "Ed25519-not-reduced" for record in records)
    assert all(record["signature_semantics"] == "reuse-event-only" for record in records)
    assert all(
        record["primitive_queries"] >= record["verification_primitive_queries"]
        for record in records
    )
    assert all(
        record["conservative_bottleneck_bits"] <= record["signed_physical_bits"]
        for record in records
    )
    assert all(group["restricted_mean_candidates"] > 0 for group in summarize(records))
