"""Deterministic, resumable and auditable experiment scheduler."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .common import canonical_json, environment_manifest, host_measurement_state, sha256_file
from .exp01_canonicality import run as run_exp01
from .exp02_collisions import run as run_exp02
from .exp02_collisions import summarize as summarize_exp02
from .exp03_persistence import run as run_exp03
from .exp03_persistence import summarize as summarize_exp03
from .exp04_anchor_robustness import run as run_exp04
from .exp04_anchor_robustness import summarize as summarize_exp04
from .exp05_dependencies import run as run_exp05
from .exp05_dependencies import summarize as summarize_exp05
from .exp06_depth import run as run_exp06
from .exp06_depth import summarize as summarize_exp06
from .exp07_sac import run as run_exp07
from .exp07_sac import summarize as summarize_exp07
from .exp08_distribution import run as run_exp08
from .exp08_distribution import summarize as summarize_exp08
from .exp09_performance import run as run_exp09
from .exp09_performance import summarize as summarize_exp09
from .exp10_memory import run as run_exp10
from .exp10_memory import summarize as summarize_exp10
from .exp11_pow import run as run_exp11
from .exp11_pow import summarize as summarize_exp11
from .exp12_kdf import run as run_exp12
from .exp12_kdf import summarize as summarize_exp12
from .exp14_faults import run as run_exp14
from .exp14_faults import summarize as summarize_exp14
from .exp15_psi import run as run_exp15
from .exp15_psi import summarize as summarize_exp15

RUNNERS: dict[str, Callable[[dict[str, Any]], list[dict[str, Any]]]] = {
    "EXP-01": run_exp01,
    "EXP-02": run_exp02,
    "EXP-03": run_exp03,
    "EXP-04": run_exp04,
    "EXP-05": run_exp05,
    "EXP-06": run_exp06,
    "EXP-07": run_exp07,
    "EXP-08": run_exp08,
    "EXP-09": run_exp09,
    "EXP-10": run_exp10,
    "EXP-11": run_exp11,
    "EXP-12": run_exp12,
    "EXP-14": run_exp14,
    "EXP-15": run_exp15,
}
SUMMARIZERS: dict[str, Callable[[list[dict[str, Any]]], list[dict[str, Any]]]] = {
    "EXP-02": summarize_exp02,
    "EXP-03": summarize_exp03,
    "EXP-04": summarize_exp04,
    "EXP-05": summarize_exp05,
    "EXP-06": summarize_exp06,
    "EXP-07": summarize_exp07,
    "EXP-08": summarize_exp08,
    "EXP-09": summarize_exp09,
    "EXP-10": summarize_exp10,
    "EXP-11": summarize_exp11,
    "EXP-12": summarize_exp12,
    "EXP-14": summarize_exp14,
    "EXP-15": summarize_exp15,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_bytes(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(value)
    os.replace(temporary, path)


def _atomic_json(path: Path, value: object, *, pretty: bool = True) -> None:
    encoded = (
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        if pretty
        else canonical_json(value) + b"\n"
    )
    _atomic_bytes(path, encoded)


def _task_plan(config: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    execution = config.get("execution", {})
    if not isinstance(execution, dict):
        raise ValueError("execution must be an object")
    declared = execution.get("tasks")
    if declared is None:
        declarations: list[dict[str, Any]] = [{"label": "complete-config", "overrides": {}}]
        base = dict(config)
    else:
        if not isinstance(declared, list) or not declared:
            raise ValueError("execution.tasks must be a non-empty list")
        declarations = declared
        base = {key: value for key, value in config.items() if key != "execution"}

    tasks: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for ordinal, declaration in enumerate(declarations):
        if not isinstance(declaration, dict):
            raise ValueError("each execution task must be an object")
        unknown = set(declaration) - {"label", "overrides"}
        if unknown:
            raise ValueError(f"unknown execution task fields: {sorted(unknown)}")
        label = declaration.get("label", f"task-{ordinal:04d}")
        overrides = declaration.get("overrides", {})
        if not isinstance(label, str) or not label:
            raise ValueError("execution task label must be a non-empty string")
        if not isinstance(overrides, dict):
            raise ValueError("execution task overrides must be an object")
        effective = {**base, **overrides}
        if effective.get("experiment") != config["experiment"]:
            raise ValueError("execution tasks cannot change the experiment")
        identity = {"config": effective, "label": label, "ordinal": ordinal}
        identifier = hashlib.sha256(b"sigma-exp-task-v2\0" + canonical_json(identity)).hexdigest()
        if identifier in identifiers:
            raise ValueError(f"duplicate task identifier: {identifier}")
        identifiers.add(identifier)
        tasks.append({"config": effective, "id": identifier, "label": label, "ordinal": ordinal})
    return tasks, execution


def _read_task_result(path: Path, identifier: str) -> dict[str, Any]:
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict) or result.get("task_id") != identifier:
        raise ValueError(f"invalid task result: {path}")
    if result.get("status") not in {"success", "censored", "error", "timeout"}:
        raise ValueError(f"invalid task status: {path}")
    return result


def _run_task(task: dict[str, Any], tasks_root: Path, timeout: float | None) -> dict[str, Any]:
    identifier = str(task["id"])
    task_dir = tasks_root / identifier
    task_dir.mkdir(parents=True, exist_ok=True)
    config_path = task_dir / "config.json"
    payload_path = task_dir / "payload.json"
    result_path = task_dir / "result.json"
    stdout_path = task_dir / "stdout.log"
    stderr_path = task_dir / "stderr.log"
    _atomic_json(config_path, task["config"], pretty=False)
    started = _utc_now()
    host_start = host_measurement_state()
    command = [sys.executable, "-m", "experiments.task_worker", str(config_path), str(payload_path)]
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=timeout
        )
        _atomic_bytes(stdout_path, completed.stdout.encode())
        _atomic_bytes(stderr_path, completed.stderr.encode())
        records: object = []
        status = "error"
        if completed.returncode == 0 and payload_path.is_file():
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            records = payload.get("records") if isinstance(payload, dict) else None
            if isinstance(records, list) and records:
                status = (
                    "censored"
                    if any(
                        isinstance(record, dict) and record.get("censored") is True
                        for record in records
                    )
                    else "success"
                )
            else:
                records = []
        result = {
            "ended_utc": _utc_now(),
            "label": task["label"],
            "ordinal": task["ordinal"],
            "records": records,
            "returncode": completed.returncode,
            "schema": "sigma-experiment-task-result-v2",
            "started_utc": started,
            "status": status,
            "task_id": identifier,
            "host_measurements": [host_start, host_measurement_state()],
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.encode() if isinstance(exc.stdout, str) else exc.stdout or b""
        stderr = exc.stderr.encode() if isinstance(exc.stderr, str) else exc.stderr or b""
        _atomic_bytes(stdout_path, stdout)
        _atomic_bytes(stderr_path, stderr)
        result = {
            "ended_utc": _utc_now(),
            "label": task["label"],
            "ordinal": task["ordinal"],
            "records": [],
            "returncode": None,
            "schema": "sigma-experiment-task-result-v2",
            "started_utc": started,
            "status": "timeout",
            "task_id": identifier,
            "timeout_seconds": timeout,
            "host_measurements": [host_start, host_measurement_state()],
        }
    payload_path.unlink(missing_ok=True)
    _atomic_json(result_path, result)
    return result


def _write_observations(path: Path, records: list[dict[str, Any]]) -> None:
    fields = sorted({key for record in records for key in record})
    buffer = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as gzip_target,
        io.TextIOWrapper(gzip_target, encoding="utf-8", newline="") as target,
    ):
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    _atomic_bytes(path, buffer.getvalue())


def _false_values(items: list[dict[str, Any]], predicate: Callable[[str], bool]) -> int:
    return sum(value is False for item in items for key, value in item.items() if predicate(key))


def execute(
    config_path: Path,
    output: Path,
    command: list[str],
    *,
    resume: bool = False,
    task_timeout: float | None = None,
    require_clean_tag: bool = False,
) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("master_seed"), str):
        raise ValueError("config must be an object with a string master_seed")
    experiment = config.get("experiment")
    if experiment not in RUNNERS:
        raise ValueError(f"unsupported experiment: {experiment!r}")
    tasks, execution = _task_plan(config)
    configured_timeout = execution.get("timeout_seconds")
    timeout = task_timeout if task_timeout is not None else configured_timeout
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
    ):
        raise ValueError("task timeout must be a positive number")

    config_copy = output / "config.json"
    expected_config = canonical_json(config) + b"\n"
    if output.exists() and any(output.iterdir()):
        if not resume:
            raise ValueError(f"output directory is not empty: {output}")
        if not config_copy.is_file() or config_copy.read_bytes() != expected_config:
            raise ValueError("resume requires a byte-identical canonical config.json")
    else:
        output.mkdir(parents=True, exist_ok=True)
        _atomic_bytes(config_copy, expected_config)

    manifest = environment_manifest(config, command)
    strict_source = require_clean_tag or execution.get("require_clean_tag") is True
    if strict_source and not manifest["publishable_source"]:
        raise ValueError("publishable execution requires a clean exact tag and artifact_path hash")

    tasks_root = output / "tasks"
    tasks_root.mkdir(exist_ok=True)
    results: list[dict[str, Any]] = []
    for task in tasks:
        result_path = tasks_root / str(task["id"]) / "result.json"
        if resume and result_path.is_file():
            results.append(_read_task_result(result_path, str(task["id"])))
        else:
            results.append(_run_task(task, tasks_root, float(timeout) if timeout else None))

    records = [
        record
        for result in results
        if result["status"] in {"success", "censored"}
        for record in result["records"]
        if isinstance(record, dict)
    ]
    raw_path = output / "observations.csv.gz"
    if records:
        _write_observations(raw_path, records)
    else:
        _atomic_bytes(raw_path, gzip.compress(b"", mtime=0))

    groups = SUMMARIZERS[experiment](records) if records and experiment in SUMMARIZERS else []
    invariant_failures = _false_values(records, lambda key: key.endswith("_match"))
    hypothesis_values = [
        value
        for group in groups
        for key, value in group.items()
        if key.startswith("compatible_") and isinstance(value, bool)
    ]
    hypothesis_outcome = (
        "not-applicable"
        if not hypothesis_values
        else "supported"
        if all(hypothesis_values)
        else "not-supported"
    )
    quality_failures = _false_values(
        [*records, *groups],
        lambda key: (
            key == "quality_control_passed" or (key.startswith("qc_") and key.endswith("_passed"))
        ),
    )
    statuses = {
        status: sum(result["status"] == status for result in results)
        for status in ("success", "censored", "error", "timeout")
    }
    execution_complete = statuses["error"] == 0 and statuses["timeout"] == 0
    failures = invariant_failures + quality_failures + statuses["error"] + statuses["timeout"]
    summary = {
        "execution_complete": execution_complete,
        "experiment": experiment,
        "failures": failures,
        "groups": groups,
        "hypothesis_outcome": hypothesis_outcome,
        "invariants_passed": invariant_failures == 0,
        "observations": len(records),
        "passed": execution_complete and invariant_failures == 0 and quality_failures == 0,
        "quality_controls_passed": quality_failures == 0,
        "schema": "sigma-experiment-summary-v2",
        "tasks": {"completed": sum(statuses.values()), "planned": len(tasks), **statuses},
    }
    summary_path = output / "summary.json"
    _atomic_json(summary_path, summary)
    manifest["completed_utc"] = _utc_now()
    manifest["host_measurement_state_end"] = host_measurement_state()
    manifest["task_artifacts"] = {
        str(path.relative_to(output)): sha256_file(path)
        for path in sorted(tasks_root.rglob("*"))
        if path.is_file()
    }
    manifest["task_plan"] = [
        {key: task[key] for key in ("id", "label", "ordinal")} for task in tasks
    ]
    manifest["artifacts"] = {
        config_copy.name: sha256_file(config_copy),
        raw_path.name: sha256_file(raw_path),
        summary_path.name: sha256_file(summary_path),
    }
    _atomic_json(output / "manifest.json", manifest)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--task-timeout", type=float)
    parser.add_argument("--require-clean-tag", action="store_true")
    args = parser.parse_args()
    try:
        summary = execute(
            args.config,
            args.output,
            sys.argv,
            resume=args.resume,
            task_timeout=args.task_timeout,
            require_clean_tag=args.require_clean_tag,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
