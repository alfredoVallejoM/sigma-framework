"""Derive an auditable resource envelope from a completed pilot run."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any


def _seconds(result: dict[str, Any]) -> float:
    start = datetime.fromisoformat(str(result["started_utc"]))
    end = datetime.fromisoformat(str(result["ended_utc"]))
    return (end - start).total_seconds()


def estimate(run: Path, planned_tasks: int | None = None) -> dict[str, Any]:
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    paths = sorted((run / "tasks").glob("*/result.json"))
    if not paths:
        raise ValueError("pilot contains no completed task partitions")
    results = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    durations = [_seconds(result) for result in results]
    disk_bytes = sum(path.stat().st_size for path in run.rglob("*") if path.is_file())
    target = planned_tasks or len(results)
    if target <= 0:
        raise ValueError("planned_tasks must be positive")
    rss = [
        usage["max_rss_platform_units"]
        for result in results
        if isinstance((usage := result.get("worker_usage")), dict)
        and isinstance(usage.get("max_rss_platform_units"), (int, float))
    ]
    scale = target / len(results)
    return {
        "censored_tasks": summary["tasks"]["censored"],
        "estimated_disk_bytes": round(disk_bytes * scale),
        "estimated_serial_wall_seconds": sum(durations) * scale,
        "max_task_wall_seconds": max(durations),
        "median_task_wall_seconds": statistics.median(durations),
        "observations_per_task": summary["observations"] / len(results),
        "pilot_disk_bytes": disk_bytes,
        "pilot_path": str(run),
        "pilot_tasks": len(results),
        "planned_tasks": target,
        "schema": "sigma-campaign-budget-estimate-v1",
        "worker_max_rss_platform_units": max(rss) if rss else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--planned-tasks", type=int)
    args = parser.parse_args()
    try:
        report = estimate(args.run, args.planned_tasks)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
