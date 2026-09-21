#!/usr/bin/env python3
"""Reduce transient pilot outputs to the sole retained F6 decision record."""

from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime
from pathlib import Path
from typing import Any

from experiments.common import canonical_json, sha256_file


def _seconds(started: str, ended: str) -> float:
    return (datetime.fromisoformat(ended) - datetime.fromisoformat(started)).total_seconds()


def summarize(root: Path) -> dict[str, Any]:
    ledger_path = root / "campaign-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    if ledger.get("schema") != "sigma-campaign-ledger-v2" or ledger.get("campaign") != "pilot":
        raise ValueError("input is not a Sigma v2 pilot campaign ledger")
    runs: dict[str, Any] = {}
    total_disk = 0
    total_observations = 0
    total_task_seconds = 0.0
    peak_rss = 0
    for name, entry in sorted(ledger["runs"].items()):
        directory = root / name
        summary_path = directory / "summary.json"
        manifest_path = directory / "manifest.json"
        if sha256_file(summary_path) != entry["summary_sha256"]:
            raise ValueError(f"summary hash mismatch: {name}")
        if sha256_file(manifest_path) != entry["manifest_sha256"]:
            raise ValueError(f"manifest hash mismatch: {name}")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        task_seconds = 0.0
        run_peak_rss = 0
        attempts = 0
        for result_path in directory.glob("tasks/*/result.json"):
            result = json.loads(result_path.read_text(encoding="utf-8"))
            task_seconds += _seconds(result["started_utc"], result["ended_utc"])
            usage = result.get("worker_usage")
            if isinstance(usage, dict):
                run_peak_rss = max(run_peak_rss, int(usage.get("max_rss_platform_units") or 0))
        attempts = len(list(directory.glob("tasks/*/attempts/*-result.json")))
        disk_bytes = sum(path.stat().st_size for path in directory.rglob("*") if path.is_file())
        total_disk += disk_bytes
        total_observations += int(summary["observations"])
        total_task_seconds += task_seconds
        peak_rss = max(peak_rss, run_peak_rss)
        runs[name] = {
            "config_sha256": entry["config_sha256"],
            "disk_bytes": disk_bytes,
            "failed_attempts_retained": attempts,
            "observations": summary["observations"],
            "passed": summary["passed"],
            "peak_worker_rss_platform_units": run_peak_rss,
            "quality_controls_passed": summary["quality_controls_passed"],
            "task_seconds": round(task_seconds, 6),
            "tasks": summary["tasks"],
        }

    sac = json.loads((root / "exp07r-sac-bic" / "summary.json").read_text(encoding="utf-8"))
    sac_groups = sac["groups"]
    kdf = json.loads((root / "exp12r-mode-budget" / "summary.json").read_text(encoding="utf-8"))
    return {
        "campaign": "pilot-v2-2",
        "decisions": {
            "confirmatory_authorized": False,
            "exp07_required_samples_per_input_bit": {
                "maximum": max(group["required_samples_per_input_bit"] for group in sac_groups),
                "minimum": min(group["required_samples_per_input_bit"] for group in sac_groups),
                "pilot": min(group["samples_per_input_bit"] for group in sac_groups),
            },
            "exp12_identical_argon2_budget": all(
                group["same_argon2_budget"] for group in kdf["groups"]
            ),
            "human_preregistration_freeze_required": True,
            "pilot_data_must_not_enter_article": True,
            "timing_requires_controlled_governor_and_multihost_replication": True,
        },
        "environment": {
            "platform": platform.platform(),
            "rss_units": "resource.getrusage platform units (KiB on this Linux pilot)",
        },
        "runs": runs,
        "schema": "sigma-pilot-decision-record-v1",
        "totals": {
            "disk_bytes": total_disk,
            "observations": total_observations,
            "peak_worker_rss_platform_units": peak_rss,
            "runs": len(runs),
            "task_seconds": round(total_task_seconds, 6),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = summarize(args.root)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    args.output.write_bytes(canonical_json(report) + b"\n")
    print(json.dumps(report["totals"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
