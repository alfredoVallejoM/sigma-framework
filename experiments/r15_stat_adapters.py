"""External statistical-battery contracts for R15 STAT-01.

Large streams are never canonical retained artifacts. Adapters consume a
reproducible byte source and archive identities, hashes, commands, logs and
parsed results.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

BatteryId = Literal["nist-sts", "practrand", "testu01-smallcrush", "testu01-crush"]


@dataclass(frozen=True)
class ExternalBatterySpecV3:
    battery_id: BatteryId
    executable: str
    command_template: tuple[str, ...]
    transport: str
    requires_version: bool = True
    requires_binary_sha256: bool = True


@dataclass(frozen=True)
class StreamIdentityV3:
    freeze_id: str
    construction: str
    corpus: str
    stream_id: int
    seed_hex: str
    total_bytes: int
    chunk_bytes: int

    def __post_init__(self) -> None:
        if not self.freeze_id or not self.construction or not self.corpus:
            raise ValueError("stream identity labels must be non-empty")
        if self.stream_id < 0:
            raise ValueError("stream_id must be non-negative")
        if len(self.seed_hex) != 64 or any(
            character not in "0123456789abcdef" for character in self.seed_hex
        ):
            raise ValueError("seed_hex must be lowercase SHA-256 hex")
        if self.total_bytes <= 0 or self.chunk_bytes <= 0:
            raise ValueError("stream sizes must be positive")


BATTERIES_V3 = (
    ExternalBatterySpecV3(
        "nist-sts",
        "assess",
        ("assess", "{bits}"),
        "single-temporary-file-or-adapter",
    ),
    ExternalBatterySpecV3(
        "practrand",
        "RNG_test",
        ("RNG_test", "stdin64", "-tlmin", "1MB", "-tlmax", "{total_bytes}"),
        "stdin-pipe",
    ),
    ExternalBatterySpecV3(
        "testu01-smallcrush",
        "sigma-testu01-smallcrush",
        ("sigma-testu01-smallcrush", "--stdin"),
        "stdin-callback-wrapper",
    ),
    ExternalBatterySpecV3(
        "testu01-crush",
        "sigma-testu01-crush",
        ("sigma-testu01-crush", "--stdin"),
        "stdin-callback-wrapper",
    ),
)


def derive_stream_seed_v3(
    freeze_id: str,
    construction: str,
    corpus: str,
    stream_id: int,
) -> bytes:
    if stream_id < 0:
        raise ValueError("stream_id must be non-negative")
    fields = (
        b"sigma-v3-r15-stat",
        freeze_id.encode("utf-8"),
        construction.encode("utf-8"),
        corpus.encode("utf-8"),
        stream_id.to_bytes(8, "big"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


class StreamHasherV3:
    """Incremental full/chunk hashing without retaining the stream."""

    def __init__(self, *, chunk_bytes: int) -> None:
        if chunk_bytes <= 0:
            raise ValueError("chunk_bytes must be positive")
        self._chunk_bytes = chunk_bytes
        self._full = hashlib.sha256()
        self._pending = bytearray()
        self._chunks: list[str] = []
        self._total = 0

    def update(self, data: bytes) -> None:
        if not isinstance(data, bytes) or not data:
            raise ValueError("stream chunks must be non-empty bytes")
        self._full.update(data)
        self._pending.extend(data)
        self._total += len(data)
        while len(self._pending) >= self._chunk_bytes:
            chunk = bytes(self._pending[: self._chunk_bytes])
            del self._pending[: self._chunk_bytes]
            self._chunks.append(hashlib.sha256(chunk).hexdigest())

    def finish(self) -> dict[str, object]:
        if self._pending:
            self._chunks.append(hashlib.sha256(bytes(self._pending)).hexdigest())
            self._pending.clear()
        return {
            "sha256": self._full.hexdigest(),
            "chunk_sha256": tuple(self._chunks),
            "total_bytes": self._total,
            "chunk_bytes": self._chunk_bytes,
        }


def validate_battery_manifest_entry_v3(entry: dict[str, object]) -> None:
    required = {
        "battery_id",
        "version",
        "binary_sha256",
        "command",
        "transport",
    }
    if set(entry) != required:
        raise ValueError("invalid external battery manifest entry")
    if entry["battery_id"] not in {spec.battery_id for spec in BATTERIES_V3}:
        raise ValueError("unknown battery id")
    version = entry["version"]
    binary = entry["binary_sha256"]
    command = entry["command"]
    transport = entry["transport"]
    if not isinstance(version, str) or not version:
        raise ValueError("external battery version is required")
    if (
        not isinstance(binary, str)
        or len(binary) != 64
        or any(ch not in "0123456789abcdef" for ch in binary)
    ):
        raise ValueError("binary_sha256 must be lowercase SHA-256")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(value, str) for value in command)
    ):
        raise ValueError("command must be a non-empty string list")
    if not isinstance(transport, str) or not transport:
        raise ValueError("transport must be non-empty")


__all__ = [
    "BATTERIES_V3",
    "ExternalBatterySpecV3",
    "StreamHasherV3",
    "StreamIdentityV3",
    "derive_stream_seed_v3",
    "validate_battery_manifest_entry_v3",
]
