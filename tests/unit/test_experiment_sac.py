from experiments.exp07_sac import run, summarize


def test_sac_experiment_separates_layers_and_builds_bit_matrix() -> None:
    records = run(
        {
            "input_bit_stride": 4,
            "master_seed": "test",
            "message_bytes": 1,
            "preset": "paranoid-wide-v2-2",
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
    assert all(0 <= item["max_absolute_bic_correlation"] <= 1 for item in summaries)
    assert all(item["simultaneous_bias_radius"] > 0 for item in summaries)


def test_revised_sac_separates_modes_in_summary() -> None:
    records = []
    for preset in (
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    ):
        records.extend(
            run(
                {
                    "bic_output_stride": 64,
                    "input_bit_stride": 4,
                    "master_seed": "revised",
                    "message_bytes": 1,
                    "preset": preset,
                    "samples": 4,
                    "state_count": 2,
                    "target_round": 1,
                }
            )
        )
    groups = summarize(records)
    assert {group["preset"] for group in groups} == {
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    }
    assert any(str(group["layer"]).startswith("round-") for group in groups)
    round_groups = [group for group in groups if str(group["layer"]).startswith("round-")]
    assert all(group["diffusion_round"] is not None for group in round_groups)
    assert all(group["diffusion_velocity"] is not None for group in round_groups)
    assert all(group["sample_requirement_met"] is False for group in groups)
