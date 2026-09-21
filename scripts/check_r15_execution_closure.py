#!/usr/bin/env python3
"""Validate R15-0A execution closure without confirmatory data."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from experiments.history_reduced import ReducedHistoryConfig
from experiments.r14_protocol import confirmatory_attack_ids
from experiments.r15_attack_bindings import R15_EXECUTOR_BINDINGS
from experiments.r15_branch_dependency import profile_deep_vector_dependency_v3
from experiments.r15_history_games import (
    conditional_crossing_trials_v3,
    profile_history_game_v3,
)
from experiments.r15_layout_ablation import profile_layout_ablation_three_way_v3
from experiments.r15_parameter_analysis import parameter_mutual_information_profile_v3
from experiments.r15_endpoint_wrappers import (
    find_first_full_state_collision_v3,
    parameter_grinding_work_ratio_v3,
    parameter_uniformity_profile_v3,
)
from experiments.r15_stat_adapters import BATTERIES_V3, StreamHasherV3
from experiments.reduced_oracle import ReducedOracle

DEVELOPMENT_SEED = b"sigma-v3-r15-0a-execution-closure"


def _resolve_bindings() -> None:
    expected = set(confirmatory_attack_ids())
    actual = set(R15_EXECUTOR_BINDINGS)
    if actual != expected:
        raise RuntimeError(
            f"R15 executor coverage mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    for binding in R15_EXECUTOR_BINDINGS.values():
        module = importlib.import_module(binding.module)
        if not hasattr(module, binding.executor):
            raise RuntimeError(
                f"{binding.attack_id} executor is missing: {binding.module}.{binding.executor}"
            )
        if not binding.primary_metric:
            raise RuntimeError(f"{binding.attack_id} has no primary metric")


def check_r15_execution_closure() -> dict[str, object]:
    _resolve_bindings()

    oracle = ReducedOracle(DEVELOPMENT_SEED)
    config = ReducedHistoryConfig(
        state_bits=4,
        history_bits=4,
        persistent_bits=4,
        target_round=1,
        state_count=1,
    )

    games = {
        game: profile_history_game_v3(
            oracle,
            config,
            persistent=3,
            state=5,
            round_index=0,
            game=game,
            input_budget=16,
        )
        for game in ("collision", "second-preimage", "fixed-point", "cycle")
    }
    crossing = conditional_crossing_trials_v3(
        oracle,
        config,
        round_index=0,
        trials=32,
    )
    full_state = find_first_full_state_collision_v3(
        oracle,
        config,
        round_index=0,
        candidates=32,
    )
    layouts = profile_layout_ablation_three_way_v3(
        oracle,
        history_bits=4,
        field_count=5,
        slots=17,
    )
    uniformity = parameter_uniformity_profile_v3(
        ReducedOracle(DEVELOPMENT_SEED + b"/uniformity"),
        128,
        persistent_bits=8,
    )
    grinding = parameter_grinding_work_ratio_v3(
        ReducedOracle(DEVELOPMENT_SEED + b"/grinding"),
        32,
        persistent_bits=8,
    )
    mi = parameter_mutual_information_profile_v3(
        ReducedOracle(DEVELOPMENT_SEED + b"/mi"),
        128,
        permutations=31,
        seed=DEVELOPMENT_SEED,
        persistent_bits=8,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    branch = profile_deep_vector_dependency_v3(
        ReducedOracle(DEVELOPMENT_SEED + b"/branch"),
        bits=4,
        branch_count=4,
        candidates=16,
    )
    hasher = StreamHasherV3(chunk_bytes=8)
    hasher.update(b"abcdefgh")
    hasher.update(b"ijklmnop")
    stream = hasher.finish()

    if {item.variant for item in layouts} != {"fixed", "values-only", "adaptive"}:
        raise RuntimeError("three-way layout ablation is incomplete")
    if not 0.0 <= crossing.visible_match_rate <= 1.0:
        raise RuntimeError("conditional crossing endpoint is invalid")
    if full_state.queries <= 0:
        raise RuntimeError("full-state first-hit endpoint is invalid")
    if uniformity.max_deviation < 0:
        raise RuntimeError("parameter-uniformity endpoint is invalid")
    if not 0.0 < grinding.net_work_ratio <= 1.0:
        raise RuntimeError("parameter-grinding work ratio is invalid")
    if mi.permutations != 31:
        raise RuntimeError("MI permutation executor did not honor the requested budget")
    if branch.interventions != 64:
        raise RuntimeError("DeepVector dependency intervention count is invalid")
    if stream["total_bytes"] != 16 or len(BATTERIES_V3) != 4:
        raise RuntimeError("STAT adapter/stream closure failed")

    return {
        "schema": "sigma-v3-r15-execution-closure-v1",
        "passed": True,
        "confirmatory": False,
        "executor_bindings": len(R15_EXECUTOR_BINDINGS),
        "history_games": sorted(games),
        "layout_variants": [item.variant for item in layouts],
        "full_state_queries_fixture": full_state.queries,
        "parameter_max_deviation_fixture": uniformity.max_deviation,
        "grinding_work_ratio_fixture": grinding.net_work_ratio,
        "mi_permutations_fixture": mi.permutations,
        "branch_interventions_fixture": branch.interventions,
        "stat_batteries": [item.battery_id for item in BATTERIES_V3],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_execution_closure()
    except (ImportError, RuntimeError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    if args.report is not None:
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
