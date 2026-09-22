"""Complexity and size ledger for SV0 TrajectoryAuditV3."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import tracemalloc
from pathlib import Path

from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    TrajectoryAuditModeV3,
    TrajectoryAuditV3,
    audit_from_evaluation_v3,
    verify_trajectory_audit_structure_v3,
)
from sigma.v3 import evaluate_v3

SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _measure(callable_, repeats: int) -> tuple[object, int, int]:
    times: list[int] = []
    peaks: list[int] = []
    result: object = None
    for _ in range(repeats):
        tracemalloc.start()
        started = time.perf_counter_ns()
        result = callable_()
        times.append(time.perf_counter_ns() - started)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return result, int(statistics.median(times)), max(peaks)


def run_ledger(*, repeats: int) -> dict[str, object]:
    rows = []
    for suite_id in SUITES:
        message = b"SV0 complexity ledger"
        context = SigmaContextV3.for_suite(
            suite_id,
            salt=b"sv0-ledger",
            challenge=b"trajectory-audit",
            application_context=b"scripts/product_closure/sv0_benchmark",
        )
        evaluation = evaluate_v3(context, BytesSource(message))
        row: dict[str, object] = {
            "suite_id": f"0x{int(suite_id):04x}",
            "round_profile": context.round_profile.name,
            "trajectory_profile": context.trajectory_profile.name,
            "target_round": evaluation.parameters.target_round,
            "state_count": evaluation.parameters.state_count,
            "states": len(evaluation.states),
            "transitions": len(evaluation.states) - 1,
            "state_size": context.state_size,
        }

        compact_wire_bytes = 0
        full_wire_bytes = 0
        for mode in (
            TrajectoryAuditModeV3.COMPACT,
            TrajectoryAuditModeV3.FULL,
        ):
            audit_obj, build_ns, build_peak = _measure(
                lambda evaluation=evaluation, mode=mode: audit_from_evaluation_v3(
                    evaluation, mode=mode
                ),
                repeats,
            )
            if not isinstance(audit_obj, TrajectoryAuditV3):
                raise AssertionError("SV0 benchmark returned wrong audit type")
            wire = audit_obj.to_bytes()
            verified, replay_ns, replay_peak = _measure(
                lambda audit_obj=audit_obj: verify_trajectory_audit_structure_v3(
                    audit_obj
                ),
                repeats,
            )
            if verified is not True:
                raise AssertionError("SV0 benchmark structural replay failed")
            prefix = mode.name.lower()
            row[f"{prefix}_wire_bytes"] = len(wire)
            row[f"{prefix}_build_median_ns"] = build_ns
            row[f"{prefix}_build_peak_bytes"] = build_peak
            row[f"{prefix}_replay_median_ns"] = replay_ns
            row[f"{prefix}_replay_peak_bytes"] = replay_peak
            if mode is TrajectoryAuditModeV3.COMPACT:
                compact_wire_bytes = len(wire)
            else:
                full_wire_bytes = len(wire)

        row["full_over_compact_ratio"] = full_wire_bytes / compact_wire_bytes
        rows.append(row)

    return {
        "schema": "sigma-sv0-complexity-ledger-v1",
        "repeats": repeats,
        "rows": rows,
        "derived_contract": {
            "rounds": "R = t + k - 1",
            "compact_build_from_existing_evaluation": "O(compact audit output size)",
            "full_build_from_existing_evaluation": "O(full audit output size)",
            "structural_replay": "O(R * registered round transition cost)",
            "source_io_for_audit_construction": "0",
            "full_source_verification": "O(evaluate_v3(source) + audit compare)",
        },
        "claim_boundary": {
            "timings": "local engineering evidence only",
            "security_width_claim": False,
            "provenance_claim": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=7)
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
