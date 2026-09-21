"""R15 confirmatory runner for internally authorized software campaigns."""

from __future__ import annotations

import argparse
import json
import math
import platform
import signal
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .branch_failures_v3 import BranchFailureConfigV3, profile_branch_failure_v3
from .common import canonical_json, sha256_file
from .history_attackers_v3 import (
    find_same_persistent_crossings_v3,
    profile_crossing_outcome_v3,
    profile_history_truncation_v3,
)
from .history_reduced import ReducedHistoryConfig, evaluate_reduced_history
from .r13_schema import ResourceBudget
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
from .r141_schema import (
    ConfirmatoryRecordR141,
    config_from_dict_r141,
    derive_confirmatory_seed_r141,
)
from .reduced_oracle import ReducedOracle
from .tmto_v3 import TMTOConfigV3, measure_tmto_v3
from .trajectory_attacks_v3 import (
    find_window_collision_v3,
    find_window_preimage_v3,
    find_window_second_preimage_v3,
    multi_target_window_attack_v3,
)

INTERNAL_CAMPAIGN_ID = "confirmatory-v3-r141-internal"


@dataclass(frozen=True)
class InternalOutcome:
    status: str
    construction: str
    metrics: dict[str, int | float | str | bool | None]
    observed: ResourceBudget
    censor_reason: str | None = None
    error_class: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ceil_scale(value: int, numerator: int, denominator: int) -> int:
    if value == 0:
        return 0
    if denominator <= 0:
        raise ValueError("resource scaling denominator must be positive")
    return min(value, math.ceil(value * numerator / denominator))


def _scaled_observed(
    declared: ResourceBudget,
    *,
    used_work: int,
    declared_work: int,
) -> ResourceBudget:
    used = max(0, min(used_work, declared_work))
    return ResourceBudget(
        min(declared.W, used),
        _ceil_scale(declared.Q_A, used, declared_work),
        _ceil_scale(declared.Q_J, used, declared_work),
        _ceil_scale(declared.Q_H, used, declared_work),
        _ceil_scale(declared.Q_R, used, declared_work),
        declared.d if used else 0,
        declared.p,
        declared.mu,
        declared.u,
    )


def _full_observed(declared: ResourceBudget) -> ResourceBudget:
    return declared


@contextmanager
def _timeout(seconds: int) -> Iterator[None]:
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(_signum: int, _frame: object) -> None:
        raise TimeoutError("frozen per-run timeout reached")

    previous = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, float(seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous)


def _history_config(
    factors: dict[str, Any],
    *,
    state_count_default: int = 1,
) -> ReducedHistoryConfig:
    bits = int(factors.get("state_bits", factors.get("history_bits", 8)))
    history_bits = int(factors.get("history_bits", bits))
    target_round = int(factors.get("target_round", max(1, int(factors.get("round_index", 0)) + 1)))
    state_count = int(factors.get("state_count", state_count_default))
    return ReducedHistoryConfig(
        state_bits=bits,
        history_bits=history_bits,
        persistent_bits=bits,
        target_round=target_round,
        state_count=state_count,
    )


def _execute_hist01(
    oracle: ReducedOracle,
    seed: bytes,
    factors: dict[str, Any],
    declared: ResourceBudget,
) -> InternalOutcome:
    mode = str(factors["mode"])
    config = _history_config(factors)
    round_index = int(factors["round_index"])
    if mode == "conditional-crossing":
        trials = int(factors["trials_per_batch"])
        result = conditional_crossing_trials_v3(
            oracle,
            config,
            round_index=round_index,
            trials=trials,
        )
        return InternalOutcome(
            "success",
            "r125-history",
            {
                "next_state_match_rate": result.visible_match_rate,
                "full_state_match_rate": result.full_state_match_rate,
                "trials": result.trials,
                "next_state_matches": result.visible_successor_matches,
                "full_state_matches": result.full_state_matches,
            },
            _full_observed(declared),
        )
    if mode != "natural-crossing":
        raise ValueError("unsupported HIST-01 mode")
    candidate_budget = int(factors["candidate_budget"])
    target = int(factors["crossing_target"])
    crossings = find_same_persistent_crossings_v3(
        oracle,
        config,
        round_index=round_index,
        candidates=candidate_budget,
        limit=target,
    )
    outcomes = [profile_crossing_outcome_v3(oracle, config, crossing) for crossing in crossings]
    state_matches = sum(item.r125_successors_equal for item in outcomes)
    full_matches = sum(item.next_full_states_equal for item in outcomes)
    complete = len(crossings) >= target
    rate = state_matches / len(crossings) if crossings else 0.0
    full_rate = full_matches / len(crossings) if crossings else 0.0
    return InternalOutcome(
        "success" if complete else "censored",
        "r125-history",
        {
            "next_state_match_rate": rate,
            "full_state_match_rate": full_rate,
            "crossings": len(crossings),
            "crossing_target": target,
            "candidate_budget": candidate_budget,
        },
        _full_observed(declared),
        None if complete else "crossing-target-not-reached-at-candidate-budget",
    )


def execute_internal_run(
    attack_id: str,
    factors: dict[str, Any],
    declared: ResourceBudget,
    seed: bytes,
) -> InternalOutcome:
    oracle = ReducedOracle(seed)

    if attack_id == "HIST-01":
        return _execute_hist01(oracle, seed, factors, declared)

    if attack_id == "HIST-02":
        config = _history_config(factors)
        cap = int(factors["candidate_budget"])
        result = find_first_full_state_collision_v3(
            oracle,
            config,
            round_index=int(factors["round_index"]),
            candidates=cap,
        )
        return InternalOutcome(
            "success" if result.success else "censored",
            "r125-history",
            {
                "queries_to_first_full_state_collision": result.queries,
                "collision_pairs": result.collision_pairs_at_stop,
                "censored": result.censored,
            },
            _scaled_observed(declared, used_work=result.queries, declared_work=cap),
            None if result.success else "no-full-state-collision-at-candidate-budget",
        )

    if attack_id == "HIST-03":
        bits = int(factors["history_bits"])
        budget = int(factors["input_budget"])
        result = profile_history_game_v3(
            oracle,
            _history_config(factors),
            persistent=3,
            state=5,
            round_index=0,
            game=str(factors["game"]),  # type: ignore[arg-type]
            input_budget=budget,
        )
        return InternalOutcome(
            "success" if result.success else "no-success",
            "history-step",
            {
                "queries": result.queries,
                "game": result.game,
                "collision_pairs": result.collision_pairs,
                "cycles": result.cycles,
                "max_cycle_length": result.max_cycle_length,
                "max_tail_length": result.max_tail_length,
                "history_bits": bits,
            },
            _full_observed(declared),
        )

    if attack_id == "HIST-05":
        bits = int(factors["history_bits"])
        result = profile_history_truncation_v3(
            seed,
            (bits,),
            state_bits=int(factors["state_bits"]),
            persistent_bits=int(factors["state_bits"]),
            persistent=3,
            state=7,
            round_index=int(factors["round_index"]),
        )[0]
        return InternalOutcome(
            "success",
            "r125-history",
            {
                "full_collision_pairs": result.full_collision_pairs,
                "visible_collision_pairs": result.visible_collision_pairs,
                "visible_image_size": result.visible_image_size,
                "full_image_size": result.full_image_size,
            },
            _full_observed(declared),
        )

    if attack_id in ("HIST-06", "LAYOUT-04"):
        profiles = profile_layout_ablation_three_way_v3(
            oracle,
            history_bits=int(factors["history_bits"]),
            field_count=int(factors["field_count"]),
            slots=int(factors["slots"]),
        )
        adaptive = next(item for item in profiles if item.variant == "adaptive")
        denominator = adaptive.histories * (adaptive.histories - 1) // 2
        rate = adaptive.plan_collision_pairs / denominator if denominator else 0.0
        return InternalOutcome(
            "success",
            "history-layout",
            {
                "plan_collision_rate": rate,
                "frame_collision_pairs": adaptive.frame_collision_pairs,
                "unique_plans": adaptive.unique_plans,
                "tie_count": adaptive.tie_count,
                "fixed_unique_plans": next(
                    item.unique_plans for item in profiles if item.variant == "fixed"
                ),
                "values_only_unique_plans": next(
                    item.unique_plans for item in profiles if item.variant == "values-only"
                ),
            },
            _full_observed(declared),
        )

    if attack_id in ("RED-02", "RED-03", "RED-04", "RED-05"):
        config = _history_config(factors, state_count_default=2)
        construction = str(factors["construction"])
        cap = int(factors["max_candidates"])
        if attack_id == "RED-02":
            found = find_window_collision_v3(
                oracle,
                config,
                construction=construction,  # type: ignore[arg-type]
                candidates=cap,
                persistent_policy="any",
            )
            used = cap if found is None else found.evaluated_candidates
            return InternalOutcome(
                "success" if found is not None else "censored",
                construction,
                {
                    "queries_to_first_window_collision": used,
                    "censored": found is None,
                    "state_count": config.state_count,
                },
                _scaled_observed(declared, used_work=used, declared_work=cap),
                None if found is not None else "no-window-collision-at-candidate-budget",
            )
        if attack_id == "RED-03":
            target_candidate = (1 << 120) + 17
            target = evaluate_reduced_history(
                oracle,
                config,
                target_candidate,
                construction,  # type: ignore[arg-type]
            ).window
            found = find_window_preimage_v3(
                oracle,
                config,
                construction=construction,  # type: ignore[arg-type]
                target_window=target,
                candidates=cap,
            )
            used = cap if found is None else int(found["evaluated_candidates"])
            return InternalOutcome(
                "success" if found is not None else "censored",
                construction,
                {
                    "queries": used,
                    "target_candidate": target_candidate,
                    "censored": found is None,
                },
                _scaled_observed(declared, used_work=used, declared_work=cap),
                None if found is not None else "no-preimage-at-candidate-budget",
            )
        if attack_id == "RED-04":
            policy = "same" if factors["policy"] == "same-persistent" else "any"
            found = find_window_second_preimage_v3(
                oracle,
                config,
                construction=construction,  # type: ignore[arg-type]
                target_candidate=17,
                candidates=cap,
                persistent_policy=policy,  # type: ignore[arg-type]
            )
            used = cap if found is None else found.evaluated_candidates
            return InternalOutcome(
                "success" if found is not None else "censored",
                construction,
                {
                    "queries": used,
                    "policy": str(factors["policy"]),
                    "persistent_equal": False if found is None else found.persistent_equal,
                    "censored": found is None,
                },
                _scaled_observed(declared, used_work=used, declared_work=cap),
                None if found is not None else "no-second-preimage-at-candidate-budget",
            )
        targets = int(factors["targets"])
        result = multi_target_window_attack_v3(
            oracle,
            config,
            construction=construction,  # type: ignore[arg-type]
            targets=targets,
            search_candidates=cap,
        )
        used = int(result["evaluated"])
        success = bool(result["success"])
        return InternalOutcome(
            "success" if success else "censored",
            construction,
            {"queries": used, "targets": targets, "censored": not success},
            _scaled_observed(declared, used_work=used, declared_work=cap),
            None if success else "no-multi-target-hit-at-candidate-budget",
        )

    if attack_id in ("TMTO-01", "TMTO-02"):
        result = measure_tmto_v3(
            oracle,
            TMTOConfigV3(
                bits=int(factors["state_bits"]),
                history_bits=int(factors["history_bits"]),
                entries=int(factors["entries"]),
                chain_length=int(factors["chain_length"]),
                distinguished_bits=int(factors["distinguished_bits"]),
                targets=int(factors["targets"]),
            ),
            str(factors["strategy"]),  # type: ignore[arg-type]
            str(factors["construction"]),  # type: ignore[arg-type]
        )
        work = result.offline_queries + result.online_queries + result.history_queries
        observed = ResourceBudget(
            min(declared.W, work),
            0,
            0,
            min(declared.Q_H, result.history_queries),
            min(declared.Q_R, result.offline_queries + result.online_queries),
            min(declared.d, result.parallel_depth),
            declared.p,
            min(declared.mu, result.memory_entries),
            declared.u,
        )
        return InternalOutcome(
            "success",
            result.construction,
            {
                "online_queries": result.online_queries,
                "offline_queries": result.offline_queries,
                "memory_entries": result.memory_entries,
                "history_queries": result.history_queries,
                "parallel_depth": result.parallel_depth,
                "reuse_rate": result.reuse_rate,
                "strategy": result.strategy,
            },
            observed,
        )

    if attack_id == "PARAM-01":
        result = parameter_uniformity_profile_v3(oracle, int(factors["samples"]))
        return InternalOutcome(
            "success",
            "parameter-derivation",
            {
                "max_deviation": result.max_deviation,
                "relative_max_deviation": result.relative_max_deviation,
                "chi_square": result.chi_square,
                "observed_pairs": result.observed_pairs,
                "samples": result.samples,
            },
            _full_observed(declared),
        )

    if attack_id == "PARAM-02":
        result = parameter_mutual_information_profile_v3(
            oracle,
            int(factors["samples"]),
            permutations=int(factors["permutations"]),
            seed=seed,
            candidate_bucket_bits=int(factors["candidate_bucket_bits"]),
            persistent_bucket_bits=int(factors["persistent_bucket_bits"]),
        )
        return InternalOutcome(
            "success",
            "parameter-derivation",
            {
                "mutual_information": max(result.mi_candidate, result.mi_persistent),
                "mi_candidate": result.mi_candidate,
                "mi_persistent": result.mi_persistent,
                "permutation_p_candidate": result.permutation_p_candidate,
                "permutation_p_persistent": result.permutation_p_persistent,
                "permutations": result.permutations,
                "samples": result.samples,
            },
            _full_observed(declared),
        )

    if attack_id == "PARAM-03":
        budget = int(factors["candidate_budget"])
        result = parameter_grinding_work_ratio_v3(oracle, budget)
        observed = ResourceBudget(
            min(declared.W, result.selected_work),
            min(declared.Q_A, result.attempts),
            min(declared.Q_J, result.attempts),
            0,
            0,
            declared.d,
            declared.p,
            declared.mu,
            declared.u,
        )
        return InternalOutcome(
            "success",
            "parameter-derivation",
            {
                "net_work_ratio": result.net_work_ratio,
                "candidate_budget": result.candidate_budget,
                "attempts": result.attempts,
                "selected_cost": result.selected_cost,
                "selected_work": result.selected_work,
                "full_evaluation_baseline_work": result.full_evaluation_baseline_work,
            },
            observed,
        )

    if attack_id == "BRANCH-05":
        config = BranchFailureConfigV3(
            bits=int(factors["state_bits"]),
            branch_count=int(factors["branch_count"]),
            candidates=int(factors["candidates"]),
        )
        result = profile_branch_failure_v3(
            oracle,
            config,
            "deep",
            str(factors["fault"]),  # type: ignore[arg-type]
        )
        return InternalOutcome(
            "success",
            "deep",
            {
                "collision_pairs": result.collision_pairs,
                "image_size": result.image_size,
                "conservative_bits": result.conservative_bits,
                "physical_bits": result.physical_bits,
                "fault": str(factors["fault"]),
            },
            _full_observed(declared),
        )

    if attack_id == "BRANCH-06":
        result = profile_deep_vector_dependency_v3(
            oracle,
            bits=int(factors["state_bits"]),
            branch_count=int(factors["branch_count"]),
            candidates=int(factors["candidates"]),
            fault=str(factors["fault"]),  # type: ignore[arg-type]
        )
        return InternalOutcome(
            "success",
            "deep-vector",
            {
                "affected_branches": result.mean_affected_branches,
                "all_branches_affected_rate": result.all_branches_affected_rate,
                "hamming_distance_sum": result.hamming_distance_sum,
                "first_divergence_sum": result.first_divergence_sum,
                "interventions": result.interventions,
                "fault": str(factors["fault"]),
            },
            _full_observed(declared),
        )

    raise ValueError(f"attack {attack_id} is not supported by the internal runner")


def _matches_filters(factors: dict[str, Any], filters: dict[str, str]) -> bool:
    return all(str(factors.get(key)) == value for key, value in filters.items())


def run_internal_shard(
    *,
    config_path: Path,
    execution_manifest_path: Path,
    output_root: Path,
    shard_index: int,
    shard_count: int,
    factor_filters: dict[str, str] | None = None,
) -> dict[str, object]:
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ValueError("invalid shard index/count")
    filters = factor_filters or {}
    execution = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    if execution.get("schema") != "sigma-v3-r15-execution-manifest-v2":
        raise ValueError("unexpected R15 execution manifest schema")
    if execution.get("scope") not in ("internal", "full"):
        raise ValueError("execution manifest does not authorize internal campaigns")
    if execution.get("confirmatory_unlocked") is not True:
        raise ValueError("confirmatory execution manifest is not unlocked")

    config = config_from_dict_r141(json.loads(config_path.read_text(encoding="utf-8")))
    authorized = execution.get("authorized_attacks")
    if not isinstance(authorized, list) or config.attack_id not in authorized:
        raise ValueError(f"attack {config.attack_id} is not authorized by execution manifest")

    config_sha256 = sha256_file(config_path)
    execution_sha256 = sha256_file(execution_manifest_path)
    prereg_sha256 = str(execution["preregistration_sha256"])
    dependency_sha256 = str(execution["dependency_lock_sha256"])
    artifact_sha256 = str(execution["artifact_sha256"])
    source_commit = str(execution["source_commit"])

    selected: list[tuple[dict[str, Any], int, int]] = []
    ordinal = 0
    for cell in config.cells:
        if not _matches_filters(cell["factors"], filters):
            continue
        for replicate_id in range(int(cell["replicates"])):
            if ordinal % shard_count == shard_index:
                selected.append((cell, replicate_id, ordinal))
            ordinal += 1

    keys: list[RunKeyV3] = []
    statuses: dict[str, int] = {}
    started_shard = time.monotonic()

    for cell, replicate_id, _ordinal in selected:
        cell_id = str(cell["cell_id"])
        declared = ResourceBudget(**cell["budget"])
        seed = derive_confirmatory_seed_r141(config.attack_id, cell_id, replicate_id)
        started_utc = _utc_now()
        try:
            with _timeout(int(cell["timeout_seconds"])):
                outcome = execute_internal_run(
                    config.attack_id,
                    cell["factors"],
                    declared,
                    seed,
                )
        except TimeoutError:
            outcome = InternalOutcome(
                "timeout",
                "internal-timeout",
                {cell["analysis"]["primary_metric"]: None},
                _full_observed(declared),
            )
        except Exception as exc:  # recorded, never silently dropped
            outcome = InternalOutcome(
                "error",
                "internal-error",
                {
                    cell["analysis"]["primary_metric"]: None,
                    "exception_message": str(exc)[:500],
                },
                _full_observed(declared),
                error_class=type(exc).__name__,
            )
        completed_utc = _utc_now()

        record = ConfirmatoryRecordR141.create(
            campaign_id=INTERNAL_CAMPAIGN_ID,
            attack_id=config.attack_id,
            claim_ids=config.claims,
            construction=outcome.construction,
            cell_id=cell_id,
            replicate_id=replicate_id,
            declared=declared,
            observed=outcome.observed,
            status=outcome.status,  # type: ignore[arg-type]
            metrics=outcome.metrics,
            censor_reason=outcome.censor_reason,
            error_class=outcome.error_class,
            code_commit=source_commit,
            artifact_sha256=artifact_sha256,
            config_sha256=config_sha256,
            preregistration_sha256=prereg_sha256,
            dependency_lock_sha256=dependency_sha256,
            execution_manifest_sha256=execution_sha256,
            host_id="software-internal",
            platform_name=platform.system(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            started_utc=started_utc,
            completed_utc=completed_utc,
        )
        key = RunKeyV3(record.freeze_id, record.attack_id, record.cell_id, record.replicate_id)
        atomic_write_record_v3(output_root, key, asdict(record))
        keys.append(key)
        statuses[record.status] = statuses.get(record.status, 0) + 1

    ledger = build_ledger_v3(output_root, keys)
    ledger_path = (
        output_root / "ledgers" / f"{config.attack_id.lower()}-shard-{shard_index:03d}.json"
    )
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_bytes(canonical_json(ledger) + b"\n")

    return {
        "schema": "sigma-v3-r15-internal-shard-report-v1",
        "attack_id": config.attack_id,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "factor_filters": filters,
        "selected_run_units": len(selected),
        "written_records": len(keys),
        "statuses": statuses,
        "ledger_root": ledger["root_sha256"],
        "elapsed_seconds": time.monotonic() - started_shard,
        "confirmatory": True,
    }


__all__ = [
    "INTERNAL_CAMPAIGN_ID",
    "InternalOutcome",
    "execute_internal_run",
    "main",
    "run_internal_shard",
]


def _parse_factor_filters(values: list[str]) -> dict[str, str]:
    filters: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--factor must use KEY=VALUE")
        key, item = value.split("=", 1)
        if not key or not item:
            raise ValueError("--factor KEY and VALUE must be non-empty")
        if key in filters:
            raise ValueError(f"duplicate factor filter: {key}")
        filters[key] = item
    return filters


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute one sharded R15 internal confirmatory campaign."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--factor", action="append", default=[])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = run_internal_shard(
            config_path=args.config,
            execution_manifest_path=args.execution_manifest,
            output_root=args.output,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
            factor_filters=_parse_factor_filters(args.factor),
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
