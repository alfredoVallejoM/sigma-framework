import argparse
import json
import sys
from pathlib import Path

from .runner import execute


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate Sigma experiment raw data and summaries"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--task-timeout", type=float)
    parser.add_argument("--require-clean-tag", action="store_true")
    args = parser.parse_args()
    summary = execute(
        args.config,
        args.output,
        ["python", "-m", "experiments.reproduce", *sys.argv[1:]],
        resume=args.resume,
        task_timeout=args.task_timeout,
        require_clean_tag=args.require_clean_tag,
    )
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
