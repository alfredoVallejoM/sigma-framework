#!/usr/bin/env python3
"""Run the frozen R15 local campaign queue without GitHub Actions."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Iterable

from scripts.r15_local_plan import _load, tasks, validate

CAMPAIGN_ORDER = ("wave1", "wave2", "wave3a", "amendment", "stat", "engineering")
DATASET_MODULES = {
    "wave1": "experiments.r15_wave1_dataset",
    "wave2": "experiments.r15_wave2_dataset",
    "wave3a": "experiments.r15_wave3a_dataset",
    "amendment": "experiments.r15_internal_amendment_dataset",
    "stat": "experiments.r15_stat_dataset",
}
SUMMARY_NAMES = {
    "wave1": "wave1-summary.json",
    "wave2": "wave2-summary.json",
    "wave3a": "wave3a-summary.json",
    "amendment": "internal-amendment-summary.json",
    "stat": "stat-summary.json",
    "engineering": "engineering-summary.json",
}


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_workspace(root: Path) -> Path:
    return root.parent / f"{root.name}-r15-local-data"


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)


def task_output_dir(workspace: Path, task: dict[str, Any]) -> Path:
    factors = task.get("factors", [])
    suffix = "__".join(_slug(str(item).replace("=", "-")) for item in factors)
    key = _slug(str(task["key"]))
    if suffix:
        key = f"{key}__{suffix}"
    return (
        workspace
        / "shards"
        / str(task["campaign"])
        / f"phase-{int(task['phase']):02d}"
        / key
        / f"shard-{int(task['shard_index']):03d}"
    )


def shard_complete(path: Path) -> bool:
    report_path = path / "shard-report.json"
    if not report_path.is_file():
        return False
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    written = report.get("written_records", report.get("observed_records"))
    selected = report.get("selected_run_units", written)
    if not isinstance(written, int) or written <= 0 or written != selected:
        return False
    return any((path / "raw").rglob("*.json")) and any((path / "receipts").rglob("*.json"))


def _python(workspace: Path, source: str) -> Path:
    candidate = workspace / "venvs" / source / "bin" / "python"
    if not candidate.is_file():
        raise FileNotFoundError(f"missing campaign interpreter: {candidate}")
    return candidate


def task_command(workspace: Path, task: dict[str, Any], output: Path) -> list[str]:
    campaign = str(task["campaign"])
    report = output / "shard-report.json"
    if campaign in {"wave1", "wave2", "wave3a", "amendment"}:
        source = "amendment" if campaign == "amendment" else "base"
        bundle = workspace / "bundles" / source
        command = [
            str(_python(workspace, source)),
            "-I",
            "-m",
            "experiments.r15_confirmatory_internal",
            "--config",
            str(bundle / "configs" / str(task["config"])),
            "--execution-manifest",
            str(bundle / "execution-manifest.json"),
            "--output",
            str(output),
            "--shard-index",
            str(task["shard_index"]),
            "--shard-count",
            str(task["shard_count"]),
            "--report",
            str(report),
        ]
        for factor in task.get("factors", []):
            command.extend(("--factor", str(factor)))
        return command
    if campaign == "engineering":
        return [
            str(_python(workspace, "engineering")),
            "-I",
            "-m",
            "experiments.r15_application_engineering",
            "run",
            "--attack",
            str(task["attack"]),
            "--shard-index",
            str(task["shard_index"]),
            "--shard-count",
            str(task["shard_count"]),
            "--controller-commit",
            "3d69f74850a401f4d4f6738e2b397f7e6f3ee430",
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    if campaign == "stat":
        bundle = workspace / "bundles" / "stat"
        return [
            str(_python(workspace, "stat")),
            "-I",
            "-m",
            "experiments.r15_stat_confirmatory",
            "--config",
            str(bundle / "configs" / "stat-01.json"),
            "--execution-manifest",
            str(bundle / "execution-manifest.json"),
            "--nist-binary",
            str(bundle / "tools" / "nist" / "assess"),
            "--nist-root",
            str(bundle / "tools" / "nist"),
            "--practrand-binary",
            str(bundle / "tools" / "practrand" / "RNG_test"),
            "--construction",
            str(task["construction"]),
            "--shard-index",
            str(task["shard_index"]),
            "--shard-count",
            str(task["shard_count"]),
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    raise ValueError(f"unsupported campaign: {campaign}")


def _archive_incomplete(workspace: Path, task: dict[str, Any], output: Path) -> None:
    log = output / "driver.log"
    if log.is_file():
        destination = workspace / "failures" / str(task["campaign"])
        destination.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        shutil.copy2(log, destination / f"{_slug(str(task['task_id']))}-{stamp}.log")
    if output.exists():
        shutil.rmtree(output)


def run_task(root: Path, workspace: Path, task: dict[str, Any]) -> dict[str, Any]:
    output = task_output_dir(workspace, task)
    if shard_complete(output):
        return {"task_id": task["task_id"], "status": "skipped"}
    _archive_incomplete(workspace, task, output)
    output.mkdir(parents=True, exist_ok=False)
    command = task_command(workspace, task, output)
    with (output / "driver.log").open("wb") as log:
        result = subprocess.run(
            command,
            cwd=workspace,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
            env={**os.environ, "PYTHONHASHSEED": "0"},
        )
    if result.returncode != 0 or not shard_complete(output):
        raise RuntimeError(
            f"shard failed: {task['task_id']} (exit={result.returncode}, "
            f"log={output / 'driver.log'})"
        )
    return {"task_id": task["task_id"], "status": "completed"}


def _run_phase(
    root: Path,
    workspace: Path,
    selected: list[dict[str, Any]],
    workers: int,
) -> dict[str, int]:
    counts = {"completed": 0, "skipped": 0}
    pending = iter(selected)
    futures: dict[Future[dict[str, Any]], dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for task in pending:
            futures[executor.submit(run_task, root, workspace, task)] = task
            if len(futures) == workers:
                break
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                futures.pop(future)
                result = future.result()
                counts[str(result["status"])] += 1
                try:
                    task = next(pending)
                except StopIteration:
                    continue
                futures[executor.submit(run_task, root, workspace, task)] = task
    return counts


def run_campaigns(
    root: Path,
    workspace: Path,
    plan: dict[str, Any],
    campaigns: Iterable[str],
    workers: int,
) -> dict[str, object]:
    expanded = tasks(plan)
    result: dict[str, object] = {}
    for campaign in campaigns:
        campaign_tasks = [item for item in expanded if item["campaign"] == campaign]
        phase_result: dict[str, dict[str, int]] = {}
        for phase in sorted({int(item["phase"]) for item in campaign_tasks}):
            selected = [item for item in campaign_tasks if int(item["phase"]) == phase]
            phase_workers = 1 if campaign == "stat" else workers
            phase_result[str(phase)] = _run_phase(root, workspace, selected, phase_workers)
        result[campaign] = phase_result
    return result


def _controller_commit(root: Path) -> str:
    return subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def audit_campaign(root: Path, workspace: Path, campaign: str) -> dict[str, Any]:
    output = workspace / "datasets" / campaign
    output.mkdir(parents=True, exist_ok=True)
    shards = workspace / "shards" / campaign
    report = output / "audit-report.json"
    if campaign == "engineering":
        command = [
            sys.executable,
            "-m",
            "experiments.r15_application_engineering",
            "audit",
            "--shards",
            str(shards),
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    else:
        bundle_name = (
            "amendment" if campaign == "amendment" else ("stat" if campaign == "stat" else "base")
        )
        bundle = workspace / "bundles" / bundle_name
        command = [
            sys.executable,
            "-m",
            DATASET_MODULES[campaign],
            "--shards",
            str(shards),
            "--configs",
            str(bundle / "configs"),
            "--execution-manifest",
            str(bundle / "execution-manifest.json"),
            "--output",
            str(output),
            "--report",
            str(report),
        ]
        if campaign in {"wave2", "wave3a"}:
            command.extend(("--controller-commit", _controller_commit(root)))
    result = subprocess.run(command, cwd=root, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{campaign} dataset audit failed with exit {result.returncode}")
    summary = output / SUMMARY_NAMES[campaign]
    if not summary.is_file():
        raise RuntimeError(f"{campaign} audit did not produce {summary}")
    return json.loads(summary.read_text(encoding="utf-8"))


def final_closure(root: Path, workspace: Path) -> dict[str, Any]:
    output = workspace / "datasets" / "final"
    output.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "experiments.r15_final_closure"]
    for campaign in ("wave1", "wave2", "wave3a", "amendment", "stat"):
        command.extend(("--dataset", str(workspace / "datasets" / campaign)))
    command.extend(
        (
            "--configs",
            str(workspace / "bundles" / "base" / "configs"),
            "--output",
            str(output),
            "--report",
            str(output / "audit-report.json"),
        )
    )
    result = subprocess.run(command, cwd=root, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"R15 final closure failed with exit {result.returncode}")
    summary = output / "r15-final-summary.json"
    return json.loads(summary.read_text(encoding="utf-8"))


def check_local(root: Path, workspace: Path, plan: dict[str, Any]) -> dict[str, Any]:
    result = validate(root, plan)
    required = {
        "base": ("execution-manifest.json",),
        "amendment": ("execution-manifest.json",),
        "engineering": (),
        "stat": (),
    }
    missing: list[str] = []
    for source, files in required.items():
        interpreter = workspace / "venvs" / source / "bin" / "python"
        if not interpreter.is_file():
            missing.append(str(interpreter))
        for name in files:
            candidate = workspace / "bundles" / source / name
            if not candidate.is_file():
                missing.append(str(candidate))
    result["workspace"] = str(workspace)
    result["missing"] = missing
    result["passed"] = bool(result["passed"] and not missing)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "audit", "final"))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--campaign", action="append", choices=CAMPAIGN_ORDER)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    root = _root()
    workspace = (args.workspace or _default_workspace(root)).resolve()
    plan = _load(root)
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if args.command == "check":
        payload = check_local(root, workspace, plan)
    elif args.command == "run":
        selected = args.campaign or list(CAMPAIGN_ORDER)
        payload = run_campaigns(root, workspace, plan, selected, args.workers)
    elif args.command == "audit":
        selected = args.campaign or list(CAMPAIGN_ORDER)
        payload = {campaign: audit_campaign(root, workspace, campaign) for campaign in selected}
    else:
        payload = final_closure(root, workspace)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
