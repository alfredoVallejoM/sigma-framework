#!/usr/bin/env python3
"""Export EXP-08 observation groups as battery-ready byte streams."""

import argparse
import csv
import gzip
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slug(value: str) -> str:
    if not value or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in value
    ):
        raise ValueError(f"unsafe stream label: {value!r}")
    return value


def export(run_directory: Path, output: Path) -> dict[str, Any]:
    config_path = run_directory / "config.json"
    observations_path = run_directory / "observations.csv.gz"
    if not config_path.is_file() or not observations_path.is_file():
        raise ValueError("input must be an EXP-08 run with config and observations")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("experiment") != "EXP-08":
        raise ValueError("distribution stream export only accepts EXP-08")
    with gzip.open(observations_path, "rt", encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    if not rows:
        raise ValueError("EXP-08 run contains no observations")
    grouped: dict[tuple[str, str, str, int], list[dict[str, str]]] = {}
    for row in rows:
        key = (
            row["construction"],
            row["corpus"],
            row.get("domain") or "digest",
            int(row.get("stream") or 0),
        )
        grouped.setdefault(key, []).append(row)
    output.mkdir(parents=True, exist_ok=False)
    streams = []
    for (construction, corpus, domain, stream), group in sorted(grouped.items()):
        name = (
            "--".join((_slug(construction), _slug(corpus), _slug(domain), f"stream-{stream:04d}"))
            + ".bin"
        )
        ordered = sorted(group, key=lambda row: int(row["index"]))
        expected_indices = list(range(len(ordered)))
        indices = [int(row["index"]) for row in ordered]
        if indices != expected_indices:
            raise ValueError(f"non-contiguous indices in {construction}/{corpus}/{domain}/{stream}")
        data = b"".join(bytes.fromhex(row["output_hex"]) for row in ordered)
        (output / name).write_bytes(data)
        streams.append(
            {
                "bytes": len(data),
                "construction": construction,
                "corpus": corpus,
                "domain": domain,
                "file": name,
                "messages": len(ordered),
                "sha256": _sha256(data),
                "stream": stream,
            }
        )
    tools = {
        "nist-sp-800-22": shutil.which("assess") or shutil.which("niststs"),
        "practrand": shutil.which("RNG_test"),
        "testu01": shutil.which("testu01") or shutil.which("SmallCrush"),
    }
    manifest = {
        "battery_tools": {
            name: {"executable": executable, "status": "available" if executable else "unavailable"}
            for name, executable in tools.items()
        },
        "bit_order": "most-significant-bit first within each byte",
        "byte_transform": "none; canonical output bytes concatenated by message index",
        "source_config_sha256": _sha256(config_path.read_bytes()),
        "source_observations_sha256": _sha256(observations_path.read_bytes()),
        "source_run": str(run_directory.resolve()),
        "schema": "sigma-exp08-battery-export-v1",
        "streams": streams,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        manifest = export(args.run, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
