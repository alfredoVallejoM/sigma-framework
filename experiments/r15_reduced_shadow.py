"""R15-D reduced-cryptanalysis shadow acquisition over R14.1 cells.

The shadow uses real frozen factor combinations with CI-safe work caps and a
dedicated non-confirmatory seed namespace.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .common import canonical_json
from .history_reduced import ReducedHistoryConfig, evaluate_reduced_history
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r141_protocol import R141Cell, cells_for_attack_r141
from .reduced_oracle import ReducedOracle
from .tmto_v3 import TMTOConfigV3, measure_tmto_v3
from .trajectory_attacks_v3 import (
    find_window_collision_v3,
    find_window_preimage_v3,
    find_window_second_preimage_v3,
    multi_target_window_attack_v3,
)

SHADOW_D_NAMESPACE = "sigma-v3-r15-shadow-d-v1"
SHADOW_D_FREEZE_ID = "synthetic-r15d-shadow"
REDUCED_ATTACKS = ("RED-02", "RED-03", "RED-04", "RED-05", "TMTO-01", "TMTO-02")


@dataclass(frozen=True)
class ReducedShadowResultV3:
    attack_id: str
    cell_id: str
    primary_metric: str
    primary_value: int | float | str | bool | None
    metrics: dict[str, int | float | str | bool | None]


def derive_shadow_d_seed_v3(attack_id: str, cell_id: str) -> bytes:
    fields = (
        SHADOW_D_NAMESPACE.encode("ascii"),
        attack_id.encode("ascii"),
        cell_id.encode("ascii"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


def _factor_sha256(cell: R141Cell) -> str:
    return hashlib.sha256(canonical_json(cell.factors)).hexdigest()


def _config(cell: R141Cell) -> ReducedHistoryConfig:
    factors = cell.factors
    return ReducedHistoryConfig(
        state_bits=int(factors["state_bits"]),
        history_bits=int(factors["history_bits"]),
        persistent_bits=int(factors["state_bits"]),
        target_round=int(factors.get("target_round", 2)),
        state_count=int(factors.get("state_count", 2)),
    )


def execute_reduced_shadow_cell_v3(
    attack_id: str,
    cell: R141Cell,
) -> ReducedShadowResultV3:
    seed = derive_shadow_d_seed_v3(attack_id, cell.cell_id)
    oracle = ReducedOracle(seed)
    factors = cell.factors

    if attack_id == "RED-02":
        config = _config(cell)
        cap = min(int(factors["max_candidates"]), 1024)
        found = find_window_collision_v3(
            oracle,
            config,
            construction=str(factors["construction"]),  # type: ignore[arg-type]
            candidates=cap,
            persistent_policy="any",
        )
        queries = cap if found is None else found.evaluated_candidates
        return ReducedShadowResultV3(
            attack_id,
            cell.cell_id,
            "queries_to_first_window_collision",
            queries,
            {
                "construction": str(factors["construction"]),
                "state_count": int(factors["state_count"]),
                "success": found is not None,
                "censored": found is None,
                "candidate_cap": cap,
            },
        )

    if attack_id == "RED-03":
        config = _config(cell)
        construction = str(factors["construction"])
        target_candidate = (1 << 120) + 17
        target = evaluate_reduced_history(
            oracle,
            config,
            target_candidate,
            construction,  # type: ignore[arg-type]
        ).window
        cap = min(int(factors["max_candidates"]), 1024)
        found = find_window_preimage_v3(
            oracle,
            config,
            construction=construction,  # type: ignore[arg-type]
            target_window=target,
            candidates=cap,
        )
        queries = cap if found is None else int(found["evaluated_candidates"])
        return ReducedShadowResultV3(
            attack_id,
            cell.cell_id,
            "queries",
            queries,
            {
                "construction": construction,
                "region": cell.region,
                "success": found is not None,
                "censored": found is None,
                "candidate_cap": cap,
            },
        )

    if attack_id == "RED-04":
        config = _config(cell)
        construction = str(factors["construction"])
        policy = "same" if factors["policy"] == "same-persistent" else "any"
        cap = min(int(factors["max_candidates"]), 1024)
        found = find_window_second_preimage_v3(
            oracle,
            config,
            construction=construction,  # type: ignore[arg-type]
            target_candidate=17,
            candidates=cap,
            persistent_policy=policy,
        )
        queries = cap if found is None else found.evaluated_candidates
        return ReducedShadowResultV3(
            attack_id,
            cell.cell_id,
            "queries",
            queries,
            {
                "construction": construction,
                "policy": str(factors["policy"]),
                "success": found is not None,
                "censored": found is None,
                "candidate_cap": cap,
            },
        )

    if attack_id == "RED-05":
        config = _config(cell)
        cap = min(int(factors["max_candidates"]), 1024)
        result = multi_target_window_attack_v3(
            oracle,
            config,
            construction=str(factors["construction"]),  # type: ignore[arg-type]
            targets=int(factors["targets"]),
            search_candidates=cap,
        )
        return ReducedShadowResultV3(
            attack_id,
            cell.cell_id,
            "queries",
            int(result["evaluated"]),
            {
                "construction": str(factors["construction"]),
                "targets": int(factors["targets"]),
                "success": bool(result["success"]),
                "candidate_cap": cap,
            },
        )

    if attack_id in ("TMTO-01", "TMTO-02"):
        config = TMTOConfigV3(
            bits=int(factors["state_bits"]),
            history_bits=int(factors["history_bits"]),
            entries=min(int(factors["entries"]), 64),
            chain_length=min(int(factors["chain_length"]), 16),
            distinguished_bits=min(int(factors["distinguished_bits"]), 4),
            targets=min(int(factors["targets"]), 4),
        )
        result = measure_tmto_v3(
            oracle,
            config,
            str(factors["strategy"]),  # type: ignore[arg-type]
            str(factors["construction"]),  # type: ignore[arg-type]
        )
        return ReducedShadowResultV3(
            attack_id,
            cell.cell_id,
            "online_queries",
            result.online_queries,
            {
                "strategy": result.strategy,
                "construction": result.construction,
                "offline_queries": result.offline_queries,
                "history_queries": result.history_queries,
                "memory_entries": result.memory_entries,
                "parallel_depth": result.parallel_depth,
                "reuse_rate": result.reuse_rate,
            },
        )

    raise ValueError(f"unsupported R15-D shadow attack: {attack_id}")


def selected_reduced_shadow_cells_v3() -> tuple[tuple[str, R141Cell], ...]:
    selected: list[tuple[str, R141Cell]] = []

    red02 = cells_for_attack_r141("RED-02")
    for construction in ("r12", "r125"):
        for state_count in (1, 2, 3, 4):
            selected.append(
                (
                    "RED-02",
                    next(
                        cell
                        for cell in red02
                        if cell.factors["construction"] == construction
                        and cell.factors["state_count"] == state_count
                    ),
                )
            )

    red03 = cells_for_attack_r141("RED-03")
    for construction in ("r12", "r125"):
        selected.append(
            (
                "RED-03",
                next(
                    cell
                    for cell in red03
                    if cell.factors["construction"] == construction
                    and cell.region == "estimable"
                ),
            )
        )
        selected.append(
            (
                "RED-03",
                next(
                    cell
                    for cell in red03
                    if cell.factors["construction"] == construction
                    and cell.region == "stress"
                ),
            )
        )

    red04 = cells_for_attack_r141("RED-04")
    for construction in ("r12", "r125"):
        for policy in ("same-persistent", "any-persistent"):
            selected.append(
                (
                    "RED-04",
                    next(
                        cell
                        for cell in red04
                        if cell.factors["construction"] == construction
                        and cell.factors["policy"] == policy
                        and cell.region == "estimable"
                    ),
                )
            )

    red05 = cells_for_attack_r141("RED-05")
    for construction in ("r12", "r125"):
        for targets in (1, 8, 64):
            selected.append(
                (
                    "RED-05",
                    next(
                        cell
                        for cell in red05
                        if cell.factors["construction"] == construction
                        and cell.factors["targets"] == targets
                    ),
                )
            )

    tmto01 = cells_for_attack_r141("TMTO-01")
    for construction in ("r12", "r125"):
        for strategy in ("direct", "distinguished", "rho"):
            selected.append(
                (
                    "TMTO-01",
                    next(
                        cell
                        for cell in tmto01
                        if cell.factors["construction"] == construction
                        and cell.factors["strategy"] == strategy
                    ),
                )
            )

    tmto02 = cells_for_attack_r141("TMTO-02")
    for construction in ("r12", "r125"):
        for strategy in ("hellman", "rainbow"):
            selected.append(
                (
                    "TMTO-02",
                    next(
                        cell
                        for cell in tmto02
                        if cell.factors["construction"] == construction
                        and cell.factors["strategy"] == strategy
                    ),
                )
            )

    return tuple(selected)


def run_reduced_shadow_suite_v3(root: Path) -> dict[str, object]:
    results: list[ReducedShadowResultV3] = []
    keys: list[RunKeyV3] = []
    for attack_id, cell in selected_reduced_shadow_cells_v3():
        result = execute_reduced_shadow_cell_v3(attack_id, cell)
        key = RunKeyV3(SHADOW_D_FREEZE_ID, attack_id, cell.cell_id, 0)
        record: dict[str, Any] = {
            "schema": "sigma-v3-r15-reduced-shadow-record-v1",
            "namespace": SHADOW_D_NAMESPACE,
            "confirmatory": False,
            "run_key": key.stable_id,
            "source_cell_id": cell.cell_id,
            "source_region": cell.region,
            "source_factor_sha256": _factor_sha256(cell),
            "result": asdict(result),
        }
        atomic_write_record_v3(root, key, record)
        results.append(result)
        keys.append(key)

    ledger = build_ledger_v3(root, keys)
    return {
        "schema": "sigma-v3-r15-reduced-shadow-v1",
        "namespace": SHADOW_D_NAMESPACE,
        "confirmatory": False,
        "records": len(results),
        "attacks": sorted({result.attack_id for result in results}),
        "ledger_root": ledger["root_sha256"],
        "results": [asdict(result) for result in results],
    }


__all__ = [
    "REDUCED_ATTACKS",
    "SHADOW_D_FREEZE_ID",
    "SHADOW_D_NAMESPACE",
    "ReducedShadowResultV3",
    "derive_shadow_d_seed_v3",
    "execute_reduced_shadow_cell_v3",
    "run_reduced_shadow_suite_v3",
    "selected_reduced_shadow_cells_v3",
]
