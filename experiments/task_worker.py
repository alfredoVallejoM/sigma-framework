"""Isolated worker for one deterministic experiment task."""

from __future__ import annotations

import argparse
import json
import os
import traceback
from pathlib import Path
from typing import Any

from .common import canonical_json
from .runner import RUNNERS


def _atomic_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(canonical_json(value) + b"\n")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    try:
        config: Any = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("task config must be an object")
        experiment = config.get("experiment")
        if experiment not in RUNNERS:
            raise ValueError(f"unsupported experiment: {experiment!r}")
        records = RUNNERS[experiment](config)
        if not records:
            raise RuntimeError("experiment task produced no observations")
        _atomic_json(args.result, {"records": records})
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
