"""PX0 persistent Tree index size/load/proof resource ledger."""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from sigma.tree import (
    TreeProofIndex,
    build_persistent_index,
    read_persistent_index,
    write_persistent_index_atomic,
)

LEAF_COUNTS = (1, 4, 16, 64, 256, 512)


def _measure(callable_, repeats: int = 1):
    values = []
    peaks = []
    result = None
    for _ in range(repeats):
        tracemalloc.start()
        started = time.perf_counter_ns()
        result = callable_()
        values.append(time.perf_counter_ns() - started)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return result, int(statistics.median(values)), max(peaks)


def run_ledger(*, repeats: int) -> dict[str, object]:
    rows = []
    chunk = 65_536

    with tempfile.TemporaryDirectory(prefix="sigma-px0-bench-") as temp:
        root = Path(temp)
        for leaves in LEAF_COUNTS:
            data = bytes((i * 37 + leaves) % 251 for i in range(chunk)) * leaves

            index, build_ns, build_peak = _measure(
                lambda data=data: build_persistent_index(data),
                1,
            )
            encoded, encode_ns, encode_peak = _measure(index.to_bytes, repeats)
            sidecar = root / f"{leaves}.sigma-index"
            write_persistent_index_atomic(sidecar, index)

            normal, normal_ns, normal_peak = _measure(
                lambda sidecar=sidecar: read_persistent_index(sidecar),
                repeats,
            )
            mapped, mmap_ns, mmap_peak = _measure(
                lambda sidecar=sidecar: read_persistent_index(
                    sidecar,
                    use_mmap=True,
                ),
                repeats,
            )
            if normal != index or mapped != index:
                raise AssertionError("PX0 benchmark reader parity failed")

            target_leaf = leaves // 2
            _, persistent_proof_ns, persistent_proof_peak = _measure(
                lambda index=index, target_leaf=target_leaf: index.prove_leaf(
                    target_leaf
                ),
                repeats,
            )
            ephemeral = TreeProofIndex(data)
            _, ephemeral_proof_ns, ephemeral_proof_peak = _measure(
                lambda ephemeral=ephemeral, target_leaf=target_leaf: ephemeral.prove_leaf(
                    target_leaf
                ),
                repeats,
            )
            _, validate_ns, validate_peak = _measure(
                lambda index=index, data=data: index.validate_source(data),
                1,
            )

            rows.append(
                {
                    "leaf_count": leaves,
                    "source_bytes": len(data),
                    "node_count": index.node_count,
                    "sidecar_bytes": len(encoded),
                    "sidecar_to_source_ratio": len(encoded) / len(data),
                    "sidecar_bytes_per_leaf": len(encoded) / leaves,
                    "build_ns": build_ns,
                    "build_peak_bytes": build_peak,
                    "encode_ns": encode_ns,
                    "encode_peak_bytes": encode_peak,
                    "decode_normal_ns": normal_ns,
                    "decode_normal_peak_bytes": normal_peak,
                    "decode_mmap_ns": mmap_ns,
                    "decode_mmap_peak_bytes": mmap_peak,
                    "persistent_inclusion_ns": persistent_proof_ns,
                    "persistent_inclusion_peak_bytes": persistent_proof_peak,
                    "ephemeral_indexed_inclusion_ns": ephemeral_proof_ns,
                    "ephemeral_indexed_inclusion_peak_bytes": ephemeral_proof_peak,
                    "full_source_validation_ns": validate_ns,
                    "full_source_validation_peak_bytes": validate_peak,
                }
            )

    return {
        "schema": "sigma-px0-persistent-index-ledger-v1",
        "repeats": repeats,
        "rows": rows,
        "derived_contract": {
            "index_build": "O(B)",
            "sidecar_storage": "O(N * TreeNodeSummary)",
            "structural_decode_validation": "O(N) node-composition work",
            "detached_inclusion_generation": "O(log N)",
            "trusted_source_binding": "O(B) full Tree validation once per bound snapshot",
            "delta_after_binding": "ST4 local-update work plus source materialization semantics",
            "mmap_semantics": "byte-identical to normal reader; current parser still materializes TreeNode objects",
        },
        "claim_boundary": {
            "timings": "local engineering evidence only",
            "source_hint_security_evidence": False,
            "sidecar_identity_evidence": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.repeats <= 0:
        parser.error("repeats must be positive")
    report = run_ledger(repeats=args.repeats)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
