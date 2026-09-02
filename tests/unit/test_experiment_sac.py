from experiments.exp07_sac import run, summarize


def test_sac_experiment_separates_layers_and_builds_bit_matrix() -> None:
    records = run(
        {
            "input_bit_stride": 4,
            "master_seed": "test",
            "message_bytes": 1,
            "samples": 4,
            "state_count": 2,
            "target_round": 1,
        }
    )
    summaries = summarize(records)
    layers = {item["layer"] for item in summaries}
    assert {
        "primitive-sha512",
        "anchor-roots",
        "initial-state",
        "state-after-1-transitions",
        "digest-multistate",
        "digest-no-reinjection",
    } <= layers
    assert all(item["cells"] == item["input_bits"] * item["output_bits"] for item in summaries)
    assert all(0 <= item["structural_coverage"] <= 1 for item in summaries)
