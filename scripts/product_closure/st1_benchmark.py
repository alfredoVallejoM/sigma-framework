"""Local complexity ledger for Sigma Manifest V1."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import tempfile
import time
from pathlib import Path

from sigma.tree import build_directory_manifest

DEFAULT_FILE_COUNTS = (1, 4, 16, 64, 256, 1024)
DEFAULT_BYTE_SIZES = (0, 1, 4096, 65_536, 262_144, 1_048_576)


def _slope(points: list[tuple[int, int]], *, min_x: int = 1) -> float | None:
    usable = [(x, y) for x, y in points if x >= min_x and y > 0]
    if len(usable) < 2:
        return None
    xs = [math.log(x) for x, _ in usable]
    ys = [math.log(y) for _, y in usable]
    xm = statistics.fmean(xs)
    ym = statistics.fmean(ys)
    den = sum((x - xm) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - xm) * (y - ym) for x, y in zip(xs, ys)) / den


def _median_build(root: Path, repeats: int) -> tuple[int, int]:
    observations = []
    encoded_size = 0
    for _ in range(repeats):
        started = time.perf_counter_ns()
        manifest = build_directory_manifest(root)
        encoded = manifest.to_bytes()
        observations.append(time.perf_counter_ns() - started)
        encoded_size = len(encoded)
    return int(statistics.median(observations)), encoded_size


def run_benchmark(*, repeats: int) -> dict[str, object]:
    file_rows = []
    with tempfile.TemporaryDirectory(prefix="sigma-st1-files-") as temp:
        root = Path(temp)
        for count in DEFAULT_FILE_COUNTS:
            case = root / f"f{count}"
            case.mkdir()
            for index in range(count):
                (case / f"{index:05d}.bin").write_bytes(index.to_bytes(4, "big") * 8)
            median_ns, wire_bytes = _median_build(case, repeats)
            file_rows.append(
                {
                    "files": count,
                    "input_bytes": count * 32,
                    "manifest_wire_bytes": wire_bytes,
                    "median_ns": median_ns,
                }
            )

    byte_rows = []
    with tempfile.TemporaryDirectory(prefix="sigma-st1-bytes-") as temp:
        root = Path(temp)
        for size in DEFAULT_BYTE_SIZES:
            case = root / f"b{size}"
            case.mkdir()
            (case / "payload.bin").write_bytes(b"x" * size)
            median_ns, wire_bytes = _median_build(case, repeats)
            byte_rows.append(
                {
                    "files": 1,
                    "input_bytes": size,
                    "manifest_wire_bytes": wire_bytes,
                    "median_ns": median_ns,
                }
            )

    return {
        "schema": "sigma-manifest-st1-complexity-ledger-v1",
        "repeats": repeats,
        "file_count_sweep": file_rows,
        "byte_sweep": byte_rows,
        "empirical_file_count_exponent": _slope(
            [(row["files"], row["median_ns"]) for row in file_rows]
        ),
        "empirical_large_byte_exponent": _slope(
            [(row["input_bytes"], row["median_ns"]) for row in byte_rows],
            min_x=65_536,
        ),
        "derived_contract": {
            "time": "O(m*B + F log F) with bounded canonical path length",
            "manifest_memory": "O(F) plus per-file TreeBuilder O(chunk + m log N_file)",
            "io": "O(B + F)",
        },
        "interpretation": "local exploratory engineering evidence; not a cross-host performance claim",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.repeats <= 0:
        parser.error("repeats must be positive")
    report = run_benchmark(repeats=args.repeats)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
