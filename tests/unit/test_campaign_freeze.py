import json
from pathlib import Path

import pytest

from experiments.common import sha256_file
from experiments.freeze import create_freeze, verify_freeze


def _frozen_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    preregistration = tmp_path / "preregistration.md"
    preregistration.write_text("# Protocol\n\nStatus: **frozen**\n", encoding="utf-8")
    freeze = tmp_path / "freeze.json"
    config = tmp_path / "exp21.json"
    config.write_text(
        json.dumps(
            {
                "artifact_path": "sigma-framework.whl",
                "campaign": "confirmatory-v2-2",
                "experiment": "EXP-21",
                "freeze_manifest": str(freeze),
                "master_seed": "frozen-seed",
                "preregistration": {
                    "path": str(preregistration),
                    "sha256": sha256_file(preregistration),
                    "status": "frozen",
                },
                "presets": ["reference-v2-2"],
                "schema_version": 1,
                "suite_family": "v2-2",
            }
        ),
        encoding="utf-8",
    )
    return preregistration, config, freeze


def test_freeze_binds_human_review_protocol_and_configs(tmp_path: Path) -> None:
    preregistration, config, freeze = _frozen_files(tmp_path)
    record = create_freeze(
        preregistration,
        [config],
        freeze,
        reviewed_by="Review Board",
        reviewed_at="2026-09-03T12:00:00+02:00",
    )
    assert verify_freeze(freeze) == record
    assert record["reviewed_by"] == "Review Board"
    assert record["configs"]["exp21.json"] == sha256_file(config)


def test_freeze_rejects_draft_naive_timestamp_and_tampering(tmp_path: Path) -> None:
    preregistration, config, freeze = _frozen_files(tmp_path)
    preregistration.write_text(
        "Status: **draft**\n\nLater change this to `Status: **frozen**`.\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="frozen"):
        create_freeze(
            preregistration,
            [config],
            freeze,
            reviewed_by="Reviewer",
            reviewed_at="2026-09-03T12:00:00+02:00",
        )

    preregistration.write_text("Status: **frozen**\n", encoding="utf-8")
    with pytest.raises(ValueError, match="timezone"):
        create_freeze(
            preregistration,
            [config],
            freeze,
            reviewed_by="Reviewer",
            reviewed_at="2026-09-03T12:00:00",
        )

    data = json.loads(config.read_text(encoding="utf-8"))
    data["preregistration"]["sha256"] = sha256_file(preregistration)
    config.write_text(json.dumps(data), encoding="utf-8")
    create_freeze(
        preregistration,
        [config],
        freeze,
        reviewed_by="Reviewer",
        reviewed_at="2026-09-03T12:00:00Z",
    )
    config.write_text(config.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="mismatch"):
        verify_freeze(freeze)
