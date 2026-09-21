#!/usr/bin/env python3
"""Validate and materialize the local R15 campaign queue.

This utility never executes GitHub Actions and never changes scientific inputs.
It expands experiments/r15-local-campaigns.json into an explicit task list and
can report resumable progress from a local workspace.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

PLAN = Path("experiments/r15-local-campaigns.json")
BASE_COMMIT = "80214afde29b3596af83265e18c1e2926e14dd2f"
AMENDMENT_COMMIT = "108f0434a07d85fd6798b1bdb1d306a6cb3293cf"


def _root() -> Path:
    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return Path(proc.stdout.strip()).resolve()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()


def _load(root: Path) -> dict[str, Any]:
    value = json.loads((root / PLAN).read_text(encoding="utf-8"))
    if value.get("schema") != "sigma-v3-r15-local-campaign-plan-v1":
        raise RuntimeError("unexpected local R15 campaign plan schema")
    return value


def _job_count(plan: dict[str, Any], campaign: str) -> int:
    item = plan["campaigns"][campaign]
    if campaign in {"wave1", "wave2", "wave3a"}:
        return sum(int(job["shards"]) for job in item["jobs"])
    if campaign == "amendment":
        return sum(int(job["shards"]) * len(job["factor_sets"]) for job in item["jobs"])
    if campaign == "engineering":
        return int(item["shards_per_attack"]) * len(item["attacks"])
    if campaign == "stat":
        return int(item["shards_per_construction"]) * len(item["constructions"])
    raise ValueError(campaign)


def validate(root: Path, plan: dict[str, Any]) -> dict[str, Any]:
    workflow_root = root / ".github" / "workflows"
    workflows = []
    if workflow_root.exists():
        workflows = sorted(
            str(path.relative_to(root))
            for path in workflow_root.iterdir()
            if path.is_file()
        )
    if workflows:
        raise RuntimeError(f"GitHub Actions workflows are present: {workflows}")

    expected = plan["expected_run_units"]
    mandatory = sum(int(expected[name]) for name in ("wave1", "wave2", "wave3a", "amendment", "stat"))
    if mandatory != int(expected["mandatory_total"]) or mandatory != 145088:
        raise RuntimeError("mandatory RunKey cardinality drifted")

    campaigns = ("wave1", "wave2", "wave3a", "amendment", "stat", "engineering")
    counts = {name: _job_count(plan, name) for name in campaigns}
    for name, count in counts.items():
        frozen = int(plan["campaigns"][name]["expected_shard_jobs"])
        if count != frozen:
            raise RuntimeError(f"{name} shard-job count drifted: {count} != {frozen}")
    if sum(counts.values()) != int(plan["total_shard_jobs"]) or sum(counts.values()) != 1760:
        raise RuntimeError("total local shard-job count drifted")

    base = _git(root, "rev-list", "-n", "1", "sigma-v3-r14-freeze-v1")
    amendment = _git(root, "rev-list", "-n", "1", "sigma-v3-r15-internal-amendment-v1")
    if base != BASE_COMMIT:
        raise RuntimeError(f"base tag drifted: {base}")
    if amendment != AMENDMENT_COMMIT:
        raise RuntimeError(f"amendment tag drifted: {amendment}")

    return {
        "passed": True,
        "actions_workflows": 0,
        "mandatory_run_units": mandatory,
        "shard_jobs": counts,
        "total_shard_jobs": sum(counts.values()),
        "base_commit": base,
        "amendment_commit": amendment,
    }


def _append_tasks(tasks: list[dict[str, Any]], plan: dict[str, Any]) -> None:
    campaigns = plan["campaigns"]

    for campaign in ("wave1", "wave2", "wave3a"):
        item = campaigns[campaign]
        phase_map: dict[str, int] = {}
        for index, phase in enumerate(item.get("phases", []), start=1):
            for key in phase:
                phase_map[str(key)] = index
        for job in item["jobs"]:
            key = str(job["key"])
            for shard in range(int(job["shards"])):
                tasks.append(
                    {
                        "campaign": campaign,
                        "classification": item["classification"],
                        "phase": phase_map.get(key, 1),
                        "key": key,
                        "config": job["config"],
                        "factors": list(job.get("factors", [])),
                        "shard_index": shard,
                        "shard_count": int(job["shards"]),
                    }
                )

    item = campaigns["amendment"]
    phase_map = {
        str(key): index
        for index, phase in enumerate(item["phases"], start=1)
        for key in phase
    }
    for job in item["jobs"]:
        key = str(job["key"])
        for factor_set in job["factor_sets"]:
            for shard in range(int(job["shards"])):
                tasks.append(
                    {
                        "campaign": "amendment",
                        "classification": item["classification"],
                        "phase": phase_map[key],
                        "key": key,
                        "config": job["config"],
                        "factors": list(factor_set),
                        "shard_index": shard,
                        "shard_count": int(job["shards"]),
                    }
                )

    item = campaigns["stat"]
    for construction in item["constructions"]:
        for shard in range(int(item["shards_per_construction"])):
            tasks.append(
                {
                    "campaign": "stat",
                    "classification": item["classification"],
                    "phase": 1,
                    "key": str(construction),
                    "construction": str(construction),
                    "shard_index": shard,
                    "shard_count": int(item["shards_per_construction"]),
                }
            )

    item = campaigns["engineering"]
    for attack in item["attacks"]:
        for shard in range(int(item["shards_per_attack"])):
            tasks.append(
                {
                    "campaign": "engineering",
                    "classification": item["classification"],
                    "phase": 1,
                    "key": str(attack),
                    "attack": str(attack),
                    "shard_index": shard,
                    "shard_count": int(item["shards_per_attack"]),
                }
            )


def tasks(plan: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    _append_tasks(result, plan)
    if len(result) != 1760:
        raise RuntimeError(f"expanded task queue drifted: {len(result)} != 1760")
    for index, item in enumerate(result):
        item["ordinal"] = index
        item["task_id"] = (
            f"{item['campaign']}:{item['phase']}:{item['key']}:"
            f"{item['shard_index']:03d}/{item['shard_count']:03d}"
        )
    return result


def status(plan: dict[str, Any], workspace: Path) -> dict[str, Any]:
    expanded = tasks(plan)
    expected: dict[str, int] = {}
    for item in expanded:
        campaign = str(item["campaign"])
        expected[campaign] = expected.get(campaign, 0) + 1

    complete: dict[str, int] = {}
    for campaign in expected:
        root = workspace / "shards" / campaign
        complete[campaign] = len(list(root.glob("**/shard-report.json"))) if root.exists() else 0

    datasets = {}
    for campaign in expected:
        root = workspace / "datasets" / campaign
        datasets[campaign] = sorted(path.name for path in root.glob("*summary.json")) if root.exists() else []

    return {
        "workspace": str(workspace),
        "campaigns": {
            name: {
                "complete_shards": complete[name],
                "expected_shards": expected[name],
                "dataset_summaries": datasets[name],
            }
            for name in expected
        },
        "final_summary": str(workspace / "datasets" / "final" / "r15-final-summary.json"),
        "final_ready": (workspace / "datasets" / "final" / "r15-final-summary.json").is_file(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "tasks", "status", "workflow-refs"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args()

    root = _root()
    plan = _load(root)

    if args.command == "validate":
        print(json.dumps(validate(root, plan), indent=2, sort_keys=True))
        return 0

    if args.command == "tasks":
        validate(root, plan)
        values = tasks(plan)
        text = "".join(json.dumps(item, sort_keys=True) + "\n" for item in values)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
            print(json.dumps({"tasks": len(values), "output": str(args.output)}, sort_keys=True))
        else:
            print(text, end="")
        return 0

    if args.command == "status":
        workspace = (
            args.workspace
            or (root.parent / f"{root.name}-r15-local-data")
        ).resolve()
        print(json.dumps(status(plan, workspace), indent=2, sort_keys=True))
        return 0

    refs = {
        name: item["workflow_reference"]
        for name, item in plan["campaigns"].items()
        if "workflow_reference" in item
    }
    refs["final"] = plan["final_closure"]["workflow_reference"]
    print(json.dumps(refs, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
