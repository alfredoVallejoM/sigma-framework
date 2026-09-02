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
