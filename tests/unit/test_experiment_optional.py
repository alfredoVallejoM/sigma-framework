from experiments.exp14_faults import run as run_faults
from experiments.exp14_faults import summarize as summarize_faults


def test_fault_study_detects_every_sampled_fault() -> None:
    records = run_faults(
        {
            "master_seed": "test",
            "message_bytes": 8,
            "presets": ["lightweight-v2-2"],
            "state_count": 2,
            "target_round": 1,
            "trials": 2,
        }
    )
    assert all(group["detection_rate"] == 1 for group in summarize_faults(records))


def test_revised_fault_study_covers_structural_and_round_faults() -> None:
    records = run_faults(
        {
            "master_seed": "revised",
            "message_bytes": 8,
            "presets": ["paranoid-deep-v2-2", "paranoid-deep-vector-v2-2"],
            "state_count": 2,
            "target_round": 2,
            "trials": 2,
        }
    )
    assert {row["model"] for row in records} >= {
        "branch-omission",
        "branch-reorder",
        "digest-truncation",
        "fold-corruption",
        "incorrect-index",
        "repeated-round",
        "vector-corruption",
    }
    assert all(row["detected"] for row in records)
    assert all(group["quality_control_passed"] for group in summarize_faults(records))
    assert all(group["mean_propagation_levels"] >= 0 for group in summarize_faults(records))
