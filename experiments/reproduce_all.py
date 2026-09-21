"""Execute the current pilot or frozen confirmatory campaign as one ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .common import canonical_json, sha256_file
from .freeze import verify_freeze
from .runner import execute
from .schema import validate_config


def _campaign_configs(config_root: Path, campaign: str) -> list[Path]:
    directory = config_root / ("pilots" if campaign == "pilot" else "confirmatory-frozen")
    configs = sorted(directory.glob("*.json"))
    if campaign == "confirmatory":
        freeze_path = directory / "freeze.json"
        freeze = verify_freeze(freeze_path)
        frozen = {str((freeze_path.parent / relative).resolve()) for relative in freeze["configs"]}
        configs = [path for path in configs if path.name != "freeze.json"]
        if {str(path.resolve()) for path in configs} != frozen:
            raise ValueError("confirmatory directory differs from its freeze manifest")
    if not configs:
        raise ValueError(f"no {campaign} configurations found under {directory}")
    for path in configs:
        config = validate_config(json.loads(path.read_text(encoding="utf-8")))
        declared = str(config.get("campaign", ""))
        if campaign == "pilot" and declared and not declared.startswith("pilot"):
            raise ValueError(f"non-pilot config in pilot directory: {path}")
        if campaign == "confirmatory" and not declared.startswith("confirmatory"):
            raise ValueError(f"non-confirmatory config in frozen directory: {path}")
    return configs


def reproduce_all(
    config_root: Path,
    output_root: Path,
    campaign: str = "pilot",
    *,
    resume: bool = False,
) -> dict[str, Any]:
    configs = _campaign_configs(config_root, campaign)
    output_root.mkdir(parents=True, exist_ok=True)
    runs: dict[str, dict[str, Any]] = {}
    for config_path in configs:
        output = output_root / config_path.stem
        summary = execute(
            config_path,
            output,
            [*sys.argv, "--config", str(config_path)],
            resume=resume,
            require_clean_tag=campaign == "confirmatory",
        )
        runs[config_path.stem] = {
            "config": str(config_path),
            "config_sha256": sha256_file(config_path),
            "manifest_sha256": sha256_file(output / "manifest.json"),
            "summary": summary,
            "summary_sha256": sha256_file(output / "summary.json"),
        }
    record: dict[str, Any] = {
        "campaign": campaign,
        "runs": runs,
        "schema": "sigma-campaign-ledger-v2",
    }
    (output_root / "campaign-ledger.json").write_bytes(canonical_json(record) + b"\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-root", type=Path, default=Path("experiments/configs"))
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--campaign", choices=("pilot", "confirmatory"), default="pilot")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    try:
        record = reproduce_all(
            args.config_root,
            args.output_root,
            args.campaign,
            resume=args.resume,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"campaign": record["campaign"], "runs": sorted(record["runs"])}))
    return 0 if all(run["summary"]["passed"] for run in record["runs"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
