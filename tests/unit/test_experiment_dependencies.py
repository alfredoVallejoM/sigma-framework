from experiments.exp05_dependencies import run, summarize


def test_dependency_experiment_covers_message_anchor_state_index_and_context() -> None:
    records = run(
        {
            "component_bit_stride": 512,
            "input_bit_stride": 8,
            "master_seed": "test",
            "message_bytes": 1,
            "samples": 1,
        }
    )
    perturbations = {record["perturbation"] for record in records}
    assert {"message-bit", "state-bit", "round-index", "context"} <= perturbations
    assert any(str(value).startswith("root-") for value in perturbations)
    assert any(str(value).startswith("cross-") for value in perturbations)
    assert all(record["changed_bits"] > 0 for record in records if record["component"] == "digest")
    assert all(0.0 <= group["mean_flip_probability"] <= 1.0 for group in summarize(records))
