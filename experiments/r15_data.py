"""R15 append-only data, scratch and provenance primitives."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import canonical_json

LEDGER_GENESIS = hashlib.sha256(b"sigma-v3-r15-ledger-v1").hexdigest()


@dataclass(frozen=True, order=True)
class RunKeyV3:
    freeze_id: str
    attack_id: str
    cell_id: str
    replicate_id: int

    def __post_init__(self) -> None:
        if not self.freeze_id or not self.attack_id or not self.cell_id:
            raise ValueError("RunKey labels must be non-empty")
        if any("/" in value or "\\" in value for value in (self.attack_id, self.cell_id)):
            raise ValueError("RunKey labels must be path-safe")
        if self.replicate_id < 0:
            raise ValueError("replicate_id must be non-negative")

    @property
    def stable_id(self) -> str:
        return f"{self.freeze_id}:{self.attack_id}:{self.cell_id}:{self.replicate_id:08d}"


@dataclass(frozen=True)
class ScratchQuotaV3:
    maximum_bytes: int
    minimum_free_bytes: int

    def __post_init__(self) -> None:
        if self.maximum_bytes <= 0 or self.minimum_free_bytes < 0:
            raise ValueError("scratch quota values are invalid")

    def check(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(root)
        if usage.free < self.minimum_free_bytes:
            raise RuntimeError("insufficient free scratch space")


def record_path_v3(root: Path, key: RunKeyV3) -> Path:
    return root / "raw" / key.attack_id / key.cell_id / f"{key.replicate_id:08d}.json"


def receipt_path_v3(root: Path, key: RunKeyV3) -> Path:
    return root / "receipts" / key.attack_id / key.cell_id / f"{key.replicate_id:08d}.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write_record_v3(
    root: Path,
    key: RunKeyV3,
    record: dict[str, Any],
) -> tuple[Path, str]:
    """Write one canonical record once; existing RunKeys are immutable."""

    path = record_path_v3(root, key)
    if path.exists():
        raise FileExistsError(f"RunKey already has a canonical record: {key.stable_id}")
    data = canonical_json(record) + b"\n"
    digest = _sha256_bytes(data)
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(data)
            writer.flush()
            os.fsync(writer.fileno())
        if path.exists():
            raise FileExistsError(f"RunKey raced with another writer: {key.stable_id}")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

    receipt = {
        "schema": "sigma-v3-r15-run-receipt-v1",
        "run_key": key.stable_id,
        "record_path": str(path.relative_to(root)),
        "record_sha256": digest,
    }
    receipt_path = receipt_path_v3(root, key)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(canonical_json(receipt) + b"\n")
    return path, digest


def verify_record_v3(root: Path, key: RunKeyV3) -> str:
    path = record_path_v3(root, key)
    receipt_path = receipt_path_v3(root, key)
    if not path.is_file() or not receipt_path.is_file():
        raise ValueError("record/receipt pair is incomplete")
    digest = _sha256_bytes(path.read_bytes())
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("run_key") != key.stable_id:
        raise ValueError("receipt RunKey mismatch")
    if receipt.get("record_sha256") != digest:
        raise ValueError("record hash mismatch")
    return digest


def build_ledger_v3(root: Path, keys: list[RunKeyV3]) -> dict[str, object]:
    """Build a deterministic post-hoc hash chain from sorted canonical records."""

    if len(keys) != len(set(keys)):
        raise ValueError("duplicate RunKeys are not allowed")
    chain = LEDGER_GENESIS
    entries: list[dict[str, str]] = []
    for key in sorted(keys):
        digest = verify_record_v3(root, key)
        payload = bytes.fromhex(chain) + key.stable_id.encode("utf-8") + bytes.fromhex(digest)
        chain = hashlib.sha256(payload).hexdigest()
        entries.append(
            {
                "run_key": key.stable_id,
                "record_sha256": digest,
                "chain_sha256": chain,
            }
        )
    return {
        "schema": "sigma-v3-r15-ledger-v1",
        "genesis_sha256": LEDGER_GENESIS,
        "entries": entries,
        "root_sha256": chain,
    }


def directory_size_v3(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def enforce_scratch_usage_v3(root: Path, quota: ScratchQuotaV3) -> int:
    size = directory_size_v3(root) if root.exists() else 0
    if size > quota.maximum_bytes:
        raise RuntimeError("scratch usage exceeds the frozen quota")
    quota.check(root)
    return size


__all__ = [
    "LEDGER_GENESIS",
    "RunKeyV3",
    "ScratchQuotaV3",
    "atomic_write_record_v3",
    "build_ledger_v3",
    "directory_size_v3",
    "enforce_scratch_usage_v3",
    "receipt_path_v3",
    "record_path_v3",
    "verify_record_v3",
]
