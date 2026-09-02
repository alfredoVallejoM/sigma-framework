import argparse
import json
from pathlib import Path

from .runner import execute


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate Sigma experiment raw data and summaries"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = execute(args.config, args.output, ["python", "-m", "experiments.reproduce"])
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
