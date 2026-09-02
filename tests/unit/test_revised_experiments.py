import json
from pathlib import Path

import pytest

from experiments.runner import RUNNERS, SUMMARIZERS


@pytest.mark.parametrize("number", [17, 18, 19, 20, 21])
def test_revised_smoke_experiment_is_deterministic_and_summarizable(number: int) -> None:
    path = Path(f"experiments/configs/exp{number:02d}-smoke.json")
    config = json.loads(path.read_text(encoding="utf-8"))
    experiment = str(config["experiment"])
    first = RUNNERS[experiment](config)
    second = RUNNERS[experiment](config)
    assert first
    assert first == second
    assert SUMMARIZERS[experiment](first)


def test_exp21_has_no_structural_violation() -> None:
    config = json.loads(Path("experiments/configs/exp21-smoke.json").read_text(encoding="utf-8"))
    records = RUNNERS["EXP-21"](config)
    assert len(records) >= 100
    assert all(record["invariant_match"] is True for record in records)


def test_exp01r_pilot_exercises_independent_consumer_for_all_v22_suites() -> None:
    source = json.loads(
        Path("experiments/configs/pilots/exp01r-v2-2.json").read_text(encoding="utf-8")
    )
    records = []
    for task in source["execution"]["tasks"]:
        config = {key: value for key, value in source.items() if key != "execution"}
        config.update(task["overrides"])
        records.extend(RUNNERS["EXP-01"](config))
    independent = [record for record in records if record["adapter"] == "independent-consumer"]
    assert {record["preset"] for record in independent} == {
        "reference-v2-2",
        "lightweight-v2-2",
        "simultaneous-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    }
    assert all(record["anchor_match"] for record in independent)
    assert all(record["digest_match"] for record in independent)
    assert all(record["transcript_match"] for record in independent)


def test_exp05r_covers_wide_deep_and_vector_components() -> None:
    source = json.loads(
        Path("experiments/configs/pilots/exp05r-modes.json").read_text(encoding="utf-8")
    )
    records = []
    for task in source["execution"]["tasks"]:
        config = {key: value for key, value in source.items() if key != "execution"}
        config.update(task["overrides"])
        records.extend(RUNNERS["EXP-05"](config))
    assert {record["preset"] for record in records} == {
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    }
    assert any(str(record["component"]).startswith("round-") for record in records)
    invariants = [record for record in records if "invariant_match" in record]
    assert invariants
    assert all(record["invariant_match"] for record in invariants)
    groups = SUMMARIZERS["EXP-05"](records)
    assert all(0.0 <= group["output_bit_coverage"] <= 1.0 for group in groups)
    assert all(group["quality_control_passed"] for group in groups)
