from __future__ import annotations

import json
from pathlib import Path

from scripts.run_r15_local import shard_complete, task_command, task_output_dir


def _python(workspace: Path, source: str) -> None:
    path = workspace / "venvs" / source / "bin" / "python"
    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8")


def test_factor_sets_have_distinct_resumable_paths(tmp_path: Path) -> None:
    base = {
        "campaign": "amendment",
        "key": "red04",
        "phase": 1,
        "shard_index": 0,
    }
    first = task_output_dir(
        tmp_path,
        {**base, "factors": ["construction=r12", "policy=same-persistent"]},
    )
    second = task_output_dir(
        tmp_path,
        {**base, "factors": ["construction=r125", "policy=same-persistent"]},
    )
    assert first != second


def test_complete_shard_requires_report_raw_and_receipt(tmp_path: Path) -> None:
    output = tmp_path / "shard"
    (output / "raw").mkdir(parents=True)
    (output / "receipts").mkdir()
    (output / "shard-report.json").write_text(
        json.dumps({"selected_run_units": 1, "written_records": 1}),
        encoding="utf-8",
    )
    assert not shard_complete(output)
    (output / "raw" / "record.json").write_text("{}", encoding="utf-8")
    (output / "receipts" / "record.json").write_text("{}", encoding="utf-8")
    assert shard_complete(output)


def test_internal_command_uses_frozen_bundle_and_interpreter(tmp_path: Path) -> None:
    _python(tmp_path, "base")
    task = {
        "campaign": "wave1",
        "config": "hist-01.json",
        "factors": ["mode=conditional-crossing"],
        "key": "hist01b",
        "phase": 1,
        "shard_index": 2,
        "shard_count": 8,
    }
    command = task_command(tmp_path, task, tmp_path / "output")
    assert command[0] == str(tmp_path / "venvs" / "base" / "bin" / "python")
    assert str(tmp_path / "bundles" / "base" / "execution-manifest.json") in command
    assert command[-2:] == ["--factor", "mode=conditional-crossing"]


def test_stat_command_is_single_construction_and_64_way_shard(tmp_path: Path) -> None:
    _python(tmp_path, "stat")
    task = {
        "campaign": "stat",
        "construction": "R12.5-vector",
        "key": "R12.5-vector",
        "phase": 1,
        "shard_index": 63,
        "shard_count": 64,
    }
    command = task_command(tmp_path, task, tmp_path / "output")
    assert command[command.index("--construction") + 1] == "R12.5-vector"
    assert command[command.index("--shard-count") + 1] == "64"
