#!/usr/bin/env python3
"""Validate the pre-data R15 publication-scale and data policies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCALE = ROOT / "experiments" / "r15-publication-scale-plan.json"
DATA = ROOT / "experiments" / "r15-data-policy.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def check_r15_plan() -> dict[str, object]:
    scale = _load(SCALE)
    data = _load(DATA)

    if scale.get("schema") != "sigma-v3-r15-publication-scale-plan-v1":
        raise ValueError("unexpected R15 publication-scale schema")
    if data.get("schema") != "sigma-v3-r15-data-policy-v1":
        raise ValueError("unexpected R15 data-policy schema")
    if scale.get("confirmatory_evidence") is not False:
        raise ValueError("publication-scale plan must not contain confirmatory evidence")
    if data.get("confirmatory_evidence") is not False:
        raise ValueError("data policy must not contain confirmatory evidence")

    confidence = scale.get("confidence")
    if not isinstance(confidence, dict):
        raise ValueError("confidence section is missing")
    if float(confidence["primary_ci"]) < 0.95:
        raise ValueError("primary confidence interval target must be at least 95%")
    if float(confidence["rare_event_one_sided_upper"]) < 0.99:
        raise ValueError("rare-event upper bound target must be at least 99%")
    if float(confidence["power_target"]) < 0.95:
        raise ValueError("primary power target must be at least 95%")
    if float(confidence["minimum_exceptional_power"]) < 0.90:
        raise ValueError("exceptional minimum power must be at least 90%")
    if _positive_int(
        confidence["bootstrap_replicates_primary"], "bootstrap_replicates_primary"
    ) < 10_000:
        raise ValueError("primary bootstrap must use at least 10,000 resamples")
    if _positive_int(
        confidence["minimum_estimable_points_per_primary_curve"],
        "minimum_estimable_points_per_primary_curve",
    ) < 6:
        raise ValueError("primary scaling curves require at least six estimable points")

    campaigns = scale.get("campaigns")
    if not isinstance(campaigns, dict) or not campaigns:
        raise ValueError("campaign publication-scale matrix is missing")

    required = {
        "HIST-01A",
        "HIST-01B",
        "HIST-02",
        "HIST-03",
        "HIST-05",
        "HIST-06",
        "LAYOUT-04",
        "RED-02",
        "RED-03",
        "RED-04",
        "RED-05",
        "TMTO",
        "PARAM-01",
        "PARAM-02",
        "PARAM-03",
        "PARAM-04",
        "PARAM-05",
        "PARAM-06",
        "BRANCH-05",
        "BRANCH-06",
        "STAT-01",
    }
    if set(campaigns) != required:
        missing = sorted(required - set(campaigns))
        extra = sorted(set(campaigns) - required)
        raise ValueError(f"R15 campaign scale coverage mismatch: missing={missing}, extra={extra}")

    if (
        _positive_int(campaigns["HIST-01B"]["batches_per_cell"], "HIST-01B batches")
        < 256
    ):
        raise ValueError("HIST-01B requires publication-scale conditional batches")
    if (
        _positive_int(campaigns["HIST-01B"]["trials_per_batch"], "HIST-01B trials")
        < 1024
    ):
        raise ValueError("HIST-01B requires >=1024 trials per batch")
    if (
        _positive_int(campaigns["RED-02"]["replicates_per_cell"], "RED-02 replicates")
        < 512
    ):
        raise ValueError("RED-02 requires >=512 replicates per cell")
    if (
        _positive_int(campaigns["PARAM-01"]["samples_per_replicate"], "PARAM-01 samples")
        < 186_000
    ):
        raise ValueError("PARAM-01 sample volume is below publication scale")
    if (
        _positive_int(campaigns["PARAM-02"]["permutations"], "PARAM-02 permutations")
        < 5000
    ):
        raise ValueError("PARAM-02 requires >=5000 permutations")
    if (
        _positive_int(campaigns["PARAM-04"]["physical_hosts"], "PARAM-04 hosts") < 3
    ):
        raise ValueError("PARAM-04 requires three physical hosts")
    if (
        _positive_int(campaigns["PARAM-05"]["physical_hosts"], "PARAM-05 hosts") < 3
    ):
        raise ValueError("PARAM-05 requires three physical hosts")
    if (
        _positive_int(campaigns["STAT-01"]["streams_per_cell"], "STAT-01 streams") < 64
    ):
        raise ValueError("STAT-01 requires >=64 stream identities per cell")

    if data.get("processed_volume_is_not_retained_volume") is not True:
        raise ValueError("R15 must distinguish processed and retained volume")
    scratch = data.get("scratch_limits")
    if not isinstance(scratch, dict):
        raise ValueError("scratch limits are missing")
    if float(scratch["default_gib"]) > 10:
        raise ValueError("default scratch ceiling exceeds 10 GiB")
    if float(scratch["preferred_stat_gib"]) > 2:
        raise ValueError("preferred STAT scratch ceiling exceeds 2 GiB")

    stream_policy = data.get("stream_policy")
    if not isinstance(stream_policy, dict):
        raise ValueError("stream policy is missing")
    for field in (
        "deterministic_regeneration",
        "full_sha256",
        "chunk_hashes",
        "prefer_pipe_or_callback",
    ):
        if stream_policy.get(field) is not True:
            raise ValueError(f"stream policy must require {field}")
    if stream_policy.get("canonical_large_stream_artifact") is not False:
        raise ValueError("large streams must not be canonical retained artifacts")

    retained = set(data.get("retain", ()))
    for field in (
        "canonical numeric raw records",
        "stream manifest",
        "stream full/chunk hashes",
        "external tool/version manifest",
        "parsed battery results",
    ):
        if field not in retained:
            raise ValueError(f"required retained evidence missing: {field}")

    return {
        "schema": "sigma-v3-r15-plan-gate-v1",
        "passed": True,
        "confirmatory_evidence": False,
        "campaigns": len(campaigns),
        "primary_ci": confidence["primary_ci"],
        "rare_event_upper": confidence["rare_event_one_sided_upper"],
        "power_target": confidence["power_target"],
        "default_scratch_gib": scratch["default_gib"],
        "preferred_stat_scratch_gib": scratch["preferred_stat_gib"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_plan()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.report is not None:
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
