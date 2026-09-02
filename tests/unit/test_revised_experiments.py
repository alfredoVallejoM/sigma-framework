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
