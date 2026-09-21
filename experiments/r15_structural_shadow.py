"""R15-C structural shadow acquisition over frozen R14.1 cells.

The suite exercises real R14.1 cell factors through production experimental
executors, but derives seeds from a distinct shadow namespace and clamps work
to CI-safe budgets. It produces no confirmatory evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .branch_failures_v3 import BranchFailureConfigV3, profile_branch_failure_v3
from .common import canonical_json
from .history_attackers_v3 import (
    find_same_persistent_crossings_v3,
    profile_crossing_outcome_v3,
    profile_history_truncation_v3,
)
from .history_reduced import ReducedHistoryConfig
from .r15_branch_dependency import profile_deep_vector_dependency_v3
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r15_endpoint_wrappers import (
    find_first_full_state_collision_v3,
    parameter_grinding_work_ratio_v3,
    parameter_uniformity_profile_v3,
)
from .r15_history_games import (
    conditional_crossing_trials_v3,
    profile_history_game_v3,
)
from .r15_layout_ablation import profile_layout_ablation_three_way_v3
from .r15_parameter_analysis import parameter_mutual_information_profile_v3
from .r141_protocol import R141Cell, cells_for_attack_r141
from .reduced_oracle import ReducedOracle

SHADOW_NAMESPACE = "sigma-v3-r15-shadow-c-v1"
SHADOW_FREEZE_ID = "synthetic-r15c-shadow"

STRUCTURAL_ATTACKS = (
    "HIST-01",
    "HIST-02",
    "HIST-03",
    "HIST-05",
    "HIST-06",
    "LAYOUT-04",
    "BRANCH-05",
    "BRANCH-06",
    "PARAM-01",
    "PARAM-02",
    "PARAM-03",
)


@dataclass(frozen=True)
class ShadowExecutionResultV3:
    attack_id: str
    cell_id: str
    primary_metric: str
    primary_value: int | float | str | bool | None
    metrics: dict[str, int | float | str | bool | None]

    def __post_init__(self) -> None:
        if self.attack_id not in STRUCTURAL_ATTACKS:
            raise ValueError("attack is outside the R15-C structural shadow scope")
        if not self.cell_id or not self.primary_metric:
            raise ValueError("shadow result identity/metric must be non-empty")


def derive_shadow_seed_v3(attack_id: str, cell_id: str) -> bytes:
    fields = (
        SHADOW_NAMESPACE.encode("ascii"),
        attack_id.encode("ascii"),
        cell_id.encode("ascii"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


def _factor_sha256(cell: R141Cell) -> str:
    return hashlib.sha256(canonical_json(cell.factors)).hexdigest()


def _history_config(
    *,
    bits: int,
    history_bits: int | None = None,
    target_round: int = 1,
    state_count: int = 1,
) -> ReducedHistoryConfig:
    return ReducedHistoryConfig(
        state_bits=bits,
        history_bits=history_bits if history_bits is not None else bits,
        persistent_bits=bits,
        target_round=target_round,
        state_count=state_count,
    )


def _natural_crossing(cell: R141Cell, seed: bytes) -> ShadowExecutionResultV3:
    factors = cell.factors
    bits = int(factors["state_bits"])
    round_index = int(factors["round_index"])
    config = _history_config(
        bits=bits,
        history_bits=int(factors["history_bits"]),
        target_round=max(1, round_index + 1),
    )
    oracle = ReducedOracle(seed)
    crossings = find_same_persistent_crossings_v3(
        oracle,
        config,
        round_index=round_index,
        candidates=min(int(factors["candidate_budget"]), 512),
        limit=min(int(factors["crossing_target"]), 8),
    )
    outcomes = [
        profile_crossing_outcome_v3(oracle, config, crossing) for crossing in crossings
    ]
    matches = sum(item.r125_successors_equal for item in outcomes)
    rate = matches / len(outcomes) if outcomes else 0.0
    return ShadowExecutionResultV3(
        "HIST-01",
        cell.cell_id,
        "next_state_match_rate",
        rate,
        {
            "mode": "natural-crossing",
            "crossings": len(crossings),
            "next_state_matches": matches,
            "full_state_matches": sum(item.next_full_states_equal for item in outcomes),
        },
    )


def _conditional_crossing(cell: R141Cell, seed: bytes) -> ShadowExecutionResultV3:
    factors = cell.factors
    bits = int(factors["state_bits"])
    round_index = int(factors["round_index"])
    config = _history_config(
        bits=bits,
        history_bits=int(factors["history_bits"]),
        target_round=max(1, round_index + 1),
    )
    result = conditional_crossing_trials_v3(
        ReducedOracle(seed),
        config,
        round_index=round_index,
        trials=min(int(factors["trials_per_batch"]), 128),
    )
    return ShadowExecutionResultV3(
        "HIST-01",
        cell.cell_id,
        "next_state_match_rate",
        result.visible_match_rate,
        {
            "mode": "conditional-crossing",
            "trials": result.trials,
            "visible_successor_matches": result.visible_successor_matches,
            "full_state_matches": result.full_state_matches,
        },
    )


def execute_structural_shadow_cell_v3(
    attack_id: str,
    cell: R141Cell,
) -> ShadowExecutionResultV3:
    seed = derive_shadow_seed_v3(attack_id, cell.cell_id)
    factors = cell.factors
    oracle = ReducedOracle(seed)

    if attack_id == "HIST-01":
        mode = str(factors["mode"])
        if mode == "natural-crossing":
            return _natural_crossing(cell, seed)
        if mode == "conditional-crossing":
            return _conditional_crossing(cell, seed)
        raise ValueError("unknown HIST-01 shadow mode")

    if attack_id == "HIST-02":
        bits = int(factors["state_bits"])
        config = _history_config(
            bits=bits,
            history_bits=int(factors["history_bits"]),
            target_round=max(1, int(factors["round_index"])),
        )
        result = find_first_full_state_collision_v3(
            oracle,
            config,
            round_index=int(factors["round_index"]),
            candidates=min(int(factors["candidate_budget"]), 256),
        )
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "queries_to_first_full_state_collision",
            result.queries,
            {
                "success": result.success,
                "censored": result.censored,
                "collision_pairs_at_stop": result.collision_pairs_at_stop,
            },
        )

    if attack_id == "HIST-03":
        bits = int(factors["history_bits"])
        config = _history_config(bits=bits, history_bits=bits)
        result = profile_history_game_v3(
            oracle,
            config,
            persistent=3,
            state=5,
            round_index=0,
            game=str(factors["game"]),  # type: ignore[arg-type]
            input_budget=min(int(factors["input_budget"]), 1 << min(bits, 8)),
        )
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "queries",
            result.queries,
            {
                "game": result.game,
                "success": result.success,
                "collision_pairs": result.collision_pairs,
                "cycles": result.cycles,
                "max_cycle_length": result.max_cycle_length,
                "max_tail_length": result.max_tail_length,
            },
        )

    if attack_id == "HIST-05":
        bits = int(factors["history_bits"])
        state_bits = int(factors["state_bits"])
        result = profile_history_truncation_v3(
            seed,
            (bits,),
            state_bits=state_bits,
            persistent_bits=state_bits,
            persistent=3,
            state=7,
            round_index=int(factors["round_index"]),
        )[0]
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "full_collision_pairs",
            result.full_collision_pairs,
            {
                "visible_collision_pairs": result.visible_collision_pairs,
                "visible_image_size": result.visible_image_size,
                "full_image_size": result.full_image_size,
            },
        )

    if attack_id in ("HIST-06", "LAYOUT-04"):
        profiles = profile_layout_ablation_three_way_v3(
            oracle,
            history_bits=int(factors["history_bits"]),
            field_count=int(factors["field_count"]),
            slots=int(factors["slots"]),
        )
        adaptive = next(item for item in profiles if item.variant == "adaptive")
        pairs = adaptive.histories * (adaptive.histories - 1) // 2
        rate = adaptive.plan_collision_pairs / pairs if pairs else 0.0
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "plan_collision_rate",
            rate,
            {
                "variants": ",".join(item.variant for item in profiles),
                "adaptive_unique_plans": adaptive.unique_plans,
                "adaptive_plan_collision_pairs": adaptive.plan_collision_pairs,
                "adaptive_frame_collision_pairs": adaptive.frame_collision_pairs,
                "adaptive_tie_count": adaptive.tie_count,
            },
        )

    if attack_id == "BRANCH-05":
        config = BranchFailureConfigV3(
            bits=int(factors["state_bits"]),
            branch_count=int(factors["branch_count"]),
            candidates=min(int(factors["candidates"]), 256),
        )
        result = profile_branch_failure_v3(
            oracle,
            config,
            "deep",
            str(factors["fault"]),  # type: ignore[arg-type]
        )
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "collision_pairs",
            result.collision_pairs,
            {
                "fault": str(factors["fault"]),
                "image_size": result.image_size,
                "conservative_bits": result.conservative_bits,
            },
        )

    if attack_id == "BRANCH-06":
        result = profile_deep_vector_dependency_v3(
            oracle,
            bits=int(factors["state_bits"]),
            branch_count=int(factors["branch_count"]),
            candidates=min(int(factors["candidates"]), 64),
            fault=str(factors["fault"]),  # type: ignore[arg-type]
        )
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "affected_branches",
            result.mean_affected_branches,
            {
                "fault": str(factors["fault"]),
                "interventions": result.interventions,
                "all_branches_affected_rate": result.all_branches_affected_rate,
                "hamming_distance_sum": result.hamming_distance_sum,
            },
        )

    if attack_id == "PARAM-01":
        result = parameter_uniformity_profile_v3(
            oracle,
            min(int(factors["samples"]), 930),
            persistent_bits=12,
        )
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "max_deviation",
            result.max_deviation,
            {
                "samples": result.samples,
                "pair_count": result.pair_count,
                "relative_max_deviation": result.relative_max_deviation,
                "chi_square": result.chi_square,
            },
        )

    if attack_id == "PARAM-02":
        result = parameter_mutual_information_profile_v3(
            oracle,
            min(int(factors["samples"]), 512),
            permutations=min(int(factors["permutations"]), 127),
            seed=seed,
            persistent_bits=12,
            candidate_bucket_bits=int(factors["candidate_bucket_bits"]),
            persistent_bucket_bits=int(factors["persistent_bucket_bits"]),
        )
        primary = max(result.mi_candidate, result.mi_persistent)
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "mutual_information",
            primary,
            {
                "samples": result.samples,
                "mi_candidate": result.mi_candidate,
                "mi_persistent": result.mi_persistent,
                "permutation_p_candidate": result.permutation_p_candidate,
                "permutation_p_persistent": result.permutation_p_persistent,
                "permutations": result.permutations,
            },
        )

    if attack_id == "PARAM-03":
        result = parameter_grinding_work_ratio_v3(
            oracle,
            min(int(factors["candidate_budget"]), 512),
            persistent_bits=12,
        )
        return ShadowExecutionResultV3(
            attack_id,
            cell.cell_id,
            "net_work_ratio",
            result.net_work_ratio,
            {
                "candidate_budget": result.candidate_budget,
                "attempts": result.attempts,
                "selected_cost": result.selected_cost,
                "selected_work": result.selected_work,
                "baseline_work": result.full_evaluation_baseline_work,
            },
        )

    raise ValueError(f"unsupported R15-C structural attack: {attack_id}")


def selected_shadow_cells_v3() -> tuple[tuple[str, R141Cell], ...]:
    selected: list[tuple[str, R141Cell]] = []

    hist01 = cells_for_attack_r141("HIST-01")
    selected.append(("HIST-01", next(cell for cell in hist01 if cell.factors["mode"] == "natural-crossing")))
    selected.append(("HIST-01", next(cell for cell in hist01 if cell.factors["mode"] == "conditional-crossing")))

    selected.append(("HIST-02", cells_for_attack_r141("HIST-02")[0]))

    hist03 = cells_for_attack_r141("HIST-03")
    for game in ("collision", "second-preimage", "fixed-point", "cycle"):
        selected.append(("HIST-03", next(cell for cell in hist03 if cell.factors["game"] == game)))

    selected.append(("HIST-05", cells_for_attack_r141("HIST-05")[0]))
    selected.append(("HIST-06", cells_for_attack_r141("HIST-06")[0]))
    selected.append(("LAYOUT-04", cells_for_attack_r141("LAYOUT-04")[0]))

    selected.extend(("BRANCH-05", cell) for cell in cells_for_attack_r141("BRANCH-05"))
    selected.extend(("BRANCH-06", cell) for cell in cells_for_attack_r141("BRANCH-06"))

    selected.append(("PARAM-01", cells_for_attack_r141("PARAM-01")[0]))
    selected.append(("PARAM-02", cells_for_attack_r141("PARAM-02")[0]))
    selected.extend(("PARAM-03", cell) for cell in cells_for_attack_r141("PARAM-03"))
    return tuple(selected)


def run_structural_shadow_suite_v3(root: Path) -> dict[str, object]:
    results: list[ShadowExecutionResultV3] = []
    keys: list[RunKeyV3] = []
    for attack_id, cell in selected_shadow_cells_v3():
        result = execute_structural_shadow_cell_v3(attack_id, cell)
        result_payload = asdict(result)
        key = RunKeyV3(SHADOW_FREEZE_ID, attack_id, cell.cell_id, 0)
        record: dict[str, Any] = {
            "schema": "sigma-v3-r15-shadow-record-v1",
            "namespace": SHADOW_NAMESPACE,
            "confirmatory": False,
            "run_key": key.stable_id,
            "source_cell_id": cell.cell_id,
            "source_factor_sha256": _factor_sha256(cell),
            "result": result_payload,
        }
        atomic_write_record_v3(root, key, record)
        results.append(result)
        keys.append(key)

    ledger = build_ledger_v3(root, keys)
    return {
        "schema": "sigma-v3-r15-structural-shadow-v1",
        "namespace": SHADOW_NAMESPACE,
        "confirmatory": False,
        "records": len(results),
        "attacks": sorted({result.attack_id for result in results}),
        "ledger_root": ledger["root_sha256"],
        "results": [asdict(result) for result in results],
    }


__all__ = [
    "SHADOW_FREEZE_ID",
    "SHADOW_NAMESPACE",
    "STRUCTURAL_ATTACKS",
    "ShadowExecutionResultV3",
    "derive_shadow_seed_v3",
    "execute_structural_shadow_cell_v3",
    "run_structural_shadow_suite_v3",
    "selected_shadow_cells_v3",
]
