import json
from pathlib import Path

import pytest

from experiments.schema import validate_config
from scripts.prepare_confirmatory import prepare

EXPECTED_TASKS = {
    "exp01r-v2-2.json": 72,
    "exp02r-controls.json": 480,
    "exp03r-controls.json": 72,
    "exp04r-fault-matrix.json": 567,
    "exp05r-modes.json": 3,
    "exp06r-work-span.json": 576,
    "exp07r-sac-bic.json": 3,
    "exp08r-independent-streams.json": 18,
    "exp09r-operation-matrix.json": 205,
    "exp10-lib02.json": 10,
    "exp10r-memory-matrix.json": 810,
    "exp11r-parallel-nonces.json": 4,
    "exp11r-protocol-attacks.json": 18,
    "exp12r-mode-budget.json": 16,
    "exp14r-fault-matrix.json": 4,
    "exp17r-attacker-frontier.json": 54,
    "exp18r-fold-vector-segments.json": 288,
    "exp19r-signed-reuse.json": 144,
    "exp20r-preimage-games.json": 1_944,
    "exp21r-domains.json": 1,
}


def test_prepare_requires_human_freeze_and_emits_closed_configs(tmp_path: Path) -> None:
    preregistration = tmp_path / "preregistration.md"
    preregistration.write_text(
        "Status: **draft**\n\nLater change this to `Status: **frozen**`.\n", encoding="utf-8"
    )
    output = tmp_path / "confirmatory-frozen"
    with pytest.raises(ValueError, match="frozen"):
        prepare(
            preregistration,
            Path("experiments/configs/pilots"),
            output,
            "artifacts/sigma_framework-2.2.0a1-py3-none-any.whl",
        )

    preregistration.write_text("Status: **frozen**\n", encoding="utf-8")
    written = prepare(
        preregistration,
        Path("experiments/configs/pilots"),
        output,
        "artifacts/sigma_framework-2.2.0a1-py3-none-any.whl",
    )
    assert len(written) == 20
    assert sum(EXPECTED_TASKS.values()) == 5_289
    for path in written:
        config = json.loads(path.read_text(encoding="utf-8"))
        assert validate_config(config) == config
        assert config["campaign"] == "confirmatory-v2-2"
        assert config["preregistration"]["status"] == "frozen"
        assert len(config["execution"].get("tasks", [None])) == EXPECTED_TASKS[path.name]

    exp09 = json.loads((output / "exp09r-operation-matrix.json").read_text(encoding="utf-8"))
    sigma_constructions = {
        "sigma-wide",
        "sigma-cross",
        "sigma-deep",
        "sigma-deep-vector",
    }
    file_operations = {"full-hash", "file-hot", "file-cold"}
    for task in exp09["execution"]["tasks"]:
        overrides = task["overrides"]
        construction = overrides["constructions"][0]
        operation = overrides["operations"][0]
        assert construction in sigma_constructions or operation in file_operations

    exp20 = json.loads((output / "exp20r-preimage-games.json").read_text(encoding="utf-8"))
    for task in exp20["execution"]["tasks"]:
        overrides = task["overrides"]
        game = overrides["games"][0]
        target_kind = overrides["target_kinds"][0]
        target_count = overrides["target_counts"][0]
        assert game != "second-preimage" or target_kind == "regular-image"
        assert game == "multi-target" or target_count == 1

    with pytest.raises(ValueError, match="not empty"):
        prepare(
            preregistration,
            Path("experiments/configs/pilots"),
            output,
            "artifacts/sigma_framework-2.2.0a1-py3-none-any.whl",
        )
