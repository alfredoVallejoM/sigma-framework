import argparse
import csv
import gzip
import io
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .common import canonical_json, environment_manifest, sha256_file
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


def execute(config_path: Path, output: Path, command: list[str]) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("master_seed"), str):
        raise ValueError("config must be an object with a string master_seed")
    experiment = config.get("experiment")
    if experiment not in RUNNERS:
        raise ValueError(f"unsupported experiment: {experiment!r}")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    config_copy = output / "config.json"
    config_copy.write_bytes(canonical_json(config) + b"\n")

    records = RUNNERS[experiment](config)
    if not records:
        raise RuntimeError("experiment produced no observations")
    raw_path = output / "observations.csv.gz"
    fields = sorted({key for record in records for key in record})
    with (
        raw_path.open("wb") as compressed_target,
        gzip.GzipFile(filename="", mode="wb", fileobj=compressed_target, mtime=0) as gzip_target,
        io.TextIOWrapper(gzip_target, encoding="utf-8", newline="") as target,
    ):
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    failures = sum(
        any(value is False for key, value in record.items() if key.endswith("_match"))
        for record in records
    )
    groups = SUMMARIZERS[experiment](records) if experiment in SUMMARIZERS else []
    statistical_failures = sum(
        value is False
        for group in groups
        for key, value in group.items()
        if key.startswith("compatible_")
    )
    failures += statistical_failures
    summary = {
        "experiment": experiment,
        "failures": failures,
        "groups": groups,
        "observations": len(records),
        "passed": failures == 0,
        "schema": "sigma-experiment-summary-v1",
    }
    summary_path = output / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = environment_manifest(config, command)
    manifest["artifacts"] = {
        config_copy.name: sha256_file(config_copy),
        raw_path.name: sha256_file(raw_path),
        summary_path.name: sha256_file(summary_path),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        summary = execute(args.config, args.output, sys.argv)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
