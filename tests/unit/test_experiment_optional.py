from experiments.exp14_faults import run as run_faults
from experiments.exp14_faults import summarize as summarize_faults
from experiments.exp15_psi import run as run_psi
from experiments.exp15_psi import summarize as summarize_psi


def test_fault_study_detects_every_sampled_fault() -> None:
    records = run_faults(
        {
            "master_seed": "test",
            "message_bytes": 8,
            "state_count": 2,
            "target_round": 1,
            "trials": 2,
        }
    )
    assert all(group["detection_rate"] == 1 for group in summarize_faults(records))


def test_psi_study_records_dimension_and_baseline() -> None:
    records = run_psi(
        {
            "master_seed": "test",
            "collision_widths": [4],
            "differential_trials": 2,
            "max_candidates": 100,
        }
    )
    summary = summarize_psi(records)
    assert summary[0]["non_bijective_by_pigeonhole"] is True
    assert {row["kind"] for row in records} >= {
        "reduced-collision",
        "psi-differential",
        "sha512-differential",
    }
