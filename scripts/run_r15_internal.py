#!/usr/bin/env python3
"""Execute one sharded R15 internal confirmatory campaign."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.r15_confirmatory_internal import run_internal_shard


def _filters(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--factor must use KEY=VALUE")
        key, item = value.split("=", 1)
        if not key or not item:
            raise ValueError("--factor KEY and VALUE must be non-empty")
        if key in result:
            raise ValueError(f"duplicate factor filter: {key}")
        result[key] = item
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--factor", action="append", default=[])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = run_internal_shard(
            config_path=args.config,
            execution_manifest_path=args.execution_manifest,
            output_root=args.output,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
            factor_filters=_filters(args.factor),
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
