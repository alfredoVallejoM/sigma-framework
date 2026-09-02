import csv
import gzip
import json
import subprocess
import sys
import time
from pathlib import Path


def _run(config: Path, output: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "experiments.runner", str(config), str(output), *extra],
        check=False,
        capture_output=True,
        text=True,
    )


def test_exp01_runner_writes_raw_summary_and_manifest(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "experiment": "EXP-01",
                "master_seed": "test-seed",
                "presets": ["lightweight-v2", "simultaneous-v2"],
                "sizes": [0, 65],
                "workers": [1, 2],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "run"
    result = _run(config, output)
    assert result.returncode == 0, result.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    with gzip.open(output / "observations.csv.gz", "rt", encoding="utf-8") as source:
        records = list(csv.DictReader(source))
    assert summary["passed"] is True
    assert summary["failures"] == 0
    assert summary["observations"] == len(records)
    assert manifest["master_seed"] == "test-seed"
    assert set(manifest["artifacts"]) == {
        "config.json",
        "observations.csv.gz",
        "summary.json",
    }
    assert (
        json.loads((output / "config.json").read_text(encoding="utf-8"))["master_seed"]
        == "test-seed"
    )
    assert all(record["digest_match"] == "True" for record in records)


def test_runner_partitions_tasks_and_resume_does_not_repeat_them(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "experiment": "EXP-01",
                "execution": {
                    "tasks": [
                        {"label": "empty", "overrides": {"sizes": [0]}},
                        {"label": "boundary", "overrides": {"sizes": [65]}},
                    ]
                },
                "master_seed": "partition-seed",
                "presets": ["lightweight-v2"],
                "sizes": [],
                "workers": [1],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "partitioned"
    first = _run(config, output)
    assert first.returncode == 0, first.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["tasks"] == {
        "censored": 0,
        "completed": 2,
        "error": 0,
        "planned": 2,
        "success": 2,
        "timeout": 0,
    }
    result_paths = sorted((output / "tasks").glob("*/result.json"))
    assert len(result_paths) == 2
    task_seeds = {
        json.loads(path.read_text(encoding="utf-8"))["master_seed"]
        for path in (output / "tasks").glob("*/config.json")
    }
    assert len(task_seeds) == 2
    assert "partition-seed" not in task_seeds
    contents = [path.read_bytes() for path in result_paths]
    mtimes = [path.stat().st_mtime_ns for path in result_paths]

    time.sleep(0.01)
    resumed = _run(config, output, "--resume")
    assert resumed.returncode == 0, resumed.stderr
    assert [path.read_bytes() for path in result_paths] == contents
    assert [path.stat().st_mtime_ns for path in result_paths] == mtimes

    changed = json.loads(config.read_text(encoding="utf-8"))
    changed["master_seed"] = "different-seed"
    config.write_text(json.dumps(changed), encoding="utf-8")
    rejected = _run(config, output, "--resume")
    assert rejected.returncode == 2
    assert "byte-identical canonical config.json" in rejected.stderr


def test_runner_records_task_error_without_losing_a_successful_partition(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "experiment": "EXP-01",
                "execution": {
                    "tasks": [
                        {"label": "valid", "overrides": {"presets": ["lightweight-v2"]}},
                        {"label": "invalid", "overrides": {"presets": ["not-a-preset"]}},
                    ]
                },
                "master_seed": "error-seed",
                "presets": [],
                "sizes": [0],
                "workers": [1],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "errored"
    result = _run(config, output)
    assert result.returncode == 1, result.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["execution_complete"] is False
    assert summary["observations"] > 0
    assert summary["tasks"]["success"] == 1
    assert summary["tasks"]["error"] == 1
    error_result = next(
        json.loads(path.read_text(encoding="utf-8"))
        for path in (output / "tasks").glob("*/result.json")
        if '"status": "error"' in path.read_text(encoding="utf-8")
    )
    stderr = output / "tasks" / error_result["task_id"] / "stderr.log"
    assert "not-a-preset" in stderr.read_text(encoding="utf-8")


def test_runner_distinguishes_timeout_and_right_censoring(tmp_path: Path) -> None:
    base = {
        "experiment": "EXP-02",
        "master_seed": "state-seed",
        "widths": [8],
        "state_counts": [1],
        "target_rounds": [1],
        "anchor_multipliers": [1],
        "constructions": ["simple-single"],
        "repetitions": 1,
        "max_candidates": 1,
    }
    config = tmp_path / "config.json"
    config.write_text(json.dumps(base), encoding="utf-8")

    censored_output = tmp_path / "censored"
    censored = _run(config, censored_output)
    assert censored.returncode == 0, censored.stderr
    censored_summary = json.loads((censored_output / "summary.json").read_text(encoding="utf-8"))
    assert censored_summary["passed"] is True
    assert censored_summary["tasks"]["censored"] == 1

    timeout_output = tmp_path / "timeout"
    timed_out = _run(config, timeout_output, "--task-timeout", "0.000001")
    assert timed_out.returncode == 1, timed_out.stderr
    timeout_summary = json.loads((timeout_output / "summary.json").read_text(encoding="utf-8"))
    assert timeout_summary["execution_complete"] is False
    assert timeout_summary["tasks"]["timeout"] == 1

    recovered = _run(config, timeout_output, "--resume", "--task-timeout", "10")
    assert recovered.returncode == 0, recovered.stderr
    recovered_summary = json.loads(
        (timeout_output / "summary.json").read_text(encoding="utf-8")
    )
    assert recovered_summary["execution_complete"] is True
    assert recovered_summary["tasks"]["censored"] == 1
    attempts = list((timeout_output / "tasks").glob("*/attempts/0001-result.json"))
    assert len(attempts) == 1
    assert json.loads(attempts[0].read_text(encoding="utf-8"))["status"] == "timeout"


def test_runner_blocks_unfrozen_confirmatory_config_before_execution(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "campaign": "confirmatory-v2-2",
                "experiment": "EXP-01",
                "master_seed": "must-not-run",
                "presets": ["lightweight-v2-2"],
                "sizes": [0],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "blocked"
    result = _run(config, output)
    assert result.returncode == 2
    assert "frozen preregistration" in result.stderr
    assert not output.exists()
