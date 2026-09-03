import json
from pathlib import Path

import pytest

from experiments.runner import _task_plan
from experiments.schema import SCHEMAS, validate_config


def test_every_final_pilot_has_a_closed_current_schema() -> None:
    paths = sorted(Path("experiments/configs/pilots").glob("*.json"))
    assert paths
    seen = set()
    for path in paths:
        config = json.loads(path.read_text(encoding="utf-8"))
        assert validate_config(config) == config
        seen.add(config["experiment"])
    assert seen <= set(SCHEMAS)


def test_schema_rejects_unknown_missing_wrong_version_and_task_override() -> None:
    valid = {
        "experiment": "EXP-01",
        "master_seed": "schema-test",
        "presets": ["reference-v2-2"],
        "schema_version": 1,
        "sizes": [0],
        "workers": [1],
    }
    for mutation in (
        {**valid, "unknown": True},
        {key: value for key, value in valid.items() if key != "workers"},
        {**valid, "schema_version": 2},
        {
            **valid,
            "execution": {"tasks": [{"label": "bad", "overrides": {"master_seed": "replace"}}]},
        },
    ):
        with pytest.raises(ValueError):
            validate_config(mutation)


def test_effective_task_rejects_invalid_v22_values_before_execution() -> None:
    config = {
        "execution": {"tasks": [{"label": "bad", "overrides": {"presets": ["retired-suite"]}}]},
        "experiment": "EXP-01",
        "master_seed": "schema-task-test",
        "presets": [],
        "schema_version": 1,
        "sizes": [0],
        "workers": [1],
    }
    validate_config(config)
    with pytest.raises(ValueError, match=r"unsupported v2\.2 preset"):
        _task_plan(config)


def test_exp20_effective_tasks_reject_semantically_empty_cells() -> None:
    base = {
        "anchor_multipliers": [1],
        "attackers": ["random-search"],
        "constructions": ["reinjected"],
        "experiment": "EXP-20",
        "games": ["second-preimage"],
        "master_seed": "schema-exp20-test",
        "max_candidates": 16,
        "repetitions": 1,
        "schema_version": 1,
        "state_counts": [1],
        "target_counts": [1],
        "target_kinds": ["uniform"],
        "widths": [3],
    }
    with pytest.raises(ValueError, match="regular-image"):
        validate_config(base)
    with pytest.raises(ValueError, match=r"target_counts=\[1\]"):
        validate_config(
            {
                **base,
                "games": ["preimage"],
                "target_counts": [4],
                "target_kinds": ["regular-image"],
            }
        )


def test_confirmatory_schema_requires_v22_artifact_and_preregistered_fields() -> None:
    config = {
        "campaign": "confirmatory-v2-2",
        "experiment": "EXP-21",
        "master_seed": "confirmatory",
        "presets": ["reference-v2-2"],
        "schema_version": 1,
    }
    with pytest.raises(ValueError, match="suite_family"):
        validate_config(config)
    config["suite_family"] = "v2-2"
    with pytest.raises(ValueError, match="artifact_path"):
        validate_config(config)
    config["artifact_path"] = "artifacts/sigma_framework-2.2.0a1-py3-none-any.whl"
    with pytest.raises(ValueError, match="preregistration"):
        validate_config(config)
    config["preregistration"] = {
        "path": "experiments/preregistration-v2-2.md",
        "sha256": "0" * 64,
        "status": "frozen",
    }
    with pytest.raises(ValueError, match="freeze_manifest"):
        validate_config(config)
    config["freeze_manifest"] = "experiments/configs/confirmatory-frozen/freeze.json"
    assert validate_config(config) == config
