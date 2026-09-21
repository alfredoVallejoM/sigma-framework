"""Create and verify the human-reviewed confirmatory campaign freeze record."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import canonical_json, sha256_file
from .schema import validate_config

FREEZE_SCHEMA = "sigma-confirmatory-freeze-v1"


def preregistration_is_frozen(text: str) -> bool:
    """Accept only an exact top-level frozen status line, not prose mentioning it."""

    lines = text.splitlines()
    statuses = [(index, line) for index, line in enumerate(lines) if line.startswith("Status:")]
    if len(statuses) != 1:
        return False
    index, status = statuses[0]
    return index < 8 and status == "Status: **frozen**"


def _reviewed_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("reviewed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("reviewed_at must include a timezone")
    return value


def create_freeze(
    preregistration: Path,
    configs: list[Path],
    output: Path,
    *,
    reviewed_by: str,
    reviewed_at: str,
) -> dict[str, Any]:
    """Bind a human-frozen protocol and every confirmatory config by hash."""

    if not reviewed_by.strip():
        raise ValueError("reviewed_by must identify the human reviewer")
    _reviewed_timestamp(reviewed_at)
    preregistration_text = preregistration.read_text(encoding="utf-8")
    if not preregistration_is_frozen(preregistration_text):
        raise ValueError("preregistration must explicitly declare Status: **frozen**")
    if not configs:
        raise ValueError("at least one confirmatory config is required")

    preregistration_hash = sha256_file(preregistration)
    file_hashes: dict[str, str] = {}
    for path in sorted(configs):
        config = validate_config(json.loads(path.read_text(encoding="utf-8")))
        if not str(config.get("campaign", "")).startswith("confirmatory"):
            raise ValueError(f"not a confirmatory config: {path}")
        if (
            not isinstance(config.get("freeze_manifest"), str)
            or Path(config["freeze_manifest"]).resolve() != output.resolve()
        ):
            raise ValueError(f"config does not select this freeze manifest: {path}")
        registration = config.get("preregistration")
        if not isinstance(registration, dict) or registration.get("sha256") != preregistration_hash:
            raise ValueError(f"config does not bind the frozen preregistration: {path}")
        file_hashes[os.path.relpath(path.resolve(), output.parent.resolve())] = sha256_file(path)

    record: dict[str, Any] = {
        "configs": file_hashes,
        "preregistration": {
            "path": os.path.relpath(preregistration.resolve(), output.parent.resolve()),
            "sha256": preregistration_hash,
        },
        "reviewed_at": reviewed_at,
        "reviewed_by": reviewed_by.strip(),
        "schema": FREEZE_SCHEMA,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json(record) + b"\n")
    return record


def verify_freeze(path: Path) -> dict[str, Any]:
    """Verify the record schema and every file bound by the freeze."""

    record = json.loads(path.read_text(encoding="utf-8"))
    required = {"configs", "preregistration", "reviewed_at", "reviewed_by", "schema"}
    if not isinstance(record, dict) or set(record) != required:
        raise ValueError("invalid confirmatory freeze fields")
    if record["schema"] != FREEZE_SCHEMA:
        raise ValueError("unsupported confirmatory freeze schema")
    if not isinstance(record["reviewed_by"], str) or not record["reviewed_by"].strip():
        raise ValueError("freeze record has no human reviewer")
    _reviewed_timestamp(record["reviewed_at"])
    registration = record["preregistration"]
    configs = record["configs"]
    if not isinstance(registration, dict) or set(registration) != {"path", "sha256"}:
        raise ValueError("invalid frozen preregistration entry")
    if not isinstance(configs, dict) or not configs:
        raise ValueError("freeze record has no configurations")
    entries = {registration["path"]: registration["sha256"], **configs}
    for relative, expected in entries.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or len(expected) != 64:
            raise ValueError("invalid freeze file entry")
        candidate = (path.parent / relative).resolve()
        if not candidate.is_file() or sha256_file(candidate) != expected:
            raise ValueError(f"freeze file/hash mismatch: {relative}")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--config", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reviewed-by", required=True)
    parser.add_argument("--reviewed-at", required=True)
    args = parser.parse_args()
    try:
        record = create_freeze(
            args.preregistration,
            args.config,
            args.output,
            reviewed_by=args.reviewed_by,
            reviewed_at=args.reviewed_at,
        )
        verify_freeze(args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
