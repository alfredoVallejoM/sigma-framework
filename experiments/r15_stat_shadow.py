"""R15-F STAT stream shadow rehearsal without external battery binaries."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r15_stat_adapters import StreamIdentityV3, derive_stream_seed_v3
from .r15_stat_streams import (
    STAT_CONSTRUCTIONS,
    STAT_CORPORA,
    StatStreamGeneratorV3,
    hash_stat_stream_v3,
)
from .r141_protocol import R141_FREEZE_ID

SHADOW_F_NAMESPACE = "sigma-v3-r15-shadow-f-v1"
SHADOW_F_FREEZE_ID = "synthetic-r15f-shadow"
SHADOW_BYTES_PER_CELL = 2048
SHADOW_CHUNK_BYTES = 256


def _identity(construction: str, corpus: str, index: int) -> StreamIdentityV3:
    seed = derive_stream_seed_v3(R141_FREEZE_ID, construction, corpus, index)
    return StreamIdentityV3(
        freeze_id=R141_FREEZE_ID,
        construction=construction,
        corpus=corpus,
        stream_id=index,
        seed_hex=seed.hex(),
        total_bytes=SHADOW_BYTES_PER_CELL,
        chunk_bytes=SHADOW_CHUNK_BYTES,
    )


def run_stat_shadow_suite_v3(root: Path) -> dict[str, object]:
    results: list[dict[str, object]] = []
    keys: list[RunKeyV3] = []
    index = 0
    for construction in STAT_CONSTRUCTIONS:
        for corpus in STAT_CORPORA:
            identity = _identity(construction, corpus, index)
            first = hash_stat_stream_v3(identity, emit_chunk_bytes=333)
            second = hash_stat_stream_v3(identity, emit_chunk_bytes=511)
            if first != second:
                raise RuntimeError("STAT stream regeneration changed with chunking")

            generator = StatStreamGeneratorV3(identity)
            first_block = generator.output_block(0)
            if construction == "broken-control":
                if len(first_block) != 64 or first_block[:32] != first_block[32:]:
                    raise RuntimeError("broken control lost its repeated-half defect")

            key = RunKeyV3(
                SHADOW_F_FREEZE_ID,
                "STAT-01",
                f"stat-shadow-{index:03d}",
                0,
            )
            record: dict[str, Any] = {
                "schema": "sigma-v3-r15-stat-shadow-record-v1",
                "namespace": SHADOW_F_NAMESPACE,
                "confirmatory": False,
                "run_key": key.stable_id,
                "identity": asdict(identity),
                "stream_sha256": first["sha256"],
                "chunk_sha256": list(first["chunk_sha256"]),
            }
            atomic_write_record_v3(root, key, record)
            keys.append(key)
            results.append(
                {
                    "construction": construction,
                    "corpus": corpus,
                    "sha256": first["sha256"],
                    "total_bytes": first["total_bytes"],
                    "chunk_count": len(first["chunk_sha256"]),
                }
            )
            index += 1

    ledger = build_ledger_v3(root, keys)
    return {
        "schema": "sigma-v3-r15-stat-shadow-v1",
        "namespace": SHADOW_F_NAMESPACE,
        "confirmatory": False,
        "cells": len(results),
        "logical_bytes": len(results) * SHADOW_BYTES_PER_CELL,
        "ledger_root": ledger["root_sha256"],
        "results": results,
    }


__all__ = [
    "SHADOW_BYTES_PER_CELL",
    "SHADOW_CHUNK_BYTES",
    "SHADOW_F_FREEZE_ID",
    "SHADOW_F_NAMESPACE",
    "run_stat_shadow_suite_v3",
]
