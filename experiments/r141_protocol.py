"""R14.1 publication-scale protocol for the future R15 campaign.

This is a pre-data replacement for the preliminary R14 confirmatory matrix.
It changes experimental scale and executors, not Sigma R12.5 semantics.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from .r13_schema import ResourceBudget
from .r14_protocol import ATTACK_DISPOSITIONS, CLAIMS

R141_FREEZE_ID = "sigma-v3-r14-20260921-v2"
R141_TAG = "sigma-v3-r14-freeze-v1"
R141_CONFIRMATORY_NAMESPACE = "sigma-v3-r15"
R12_5_BASELINE = "5ac306bb23acae0e0a4ef03eb56b3062343c2127"
R13_BASELINE = "8a71de3d350ea8215c481e16c9eadbeed54066ef"
SCALE_PLAN_PATH = Path(__file__).with_name("r15-publication-scale-plan.json")

RegionRole = Literal["estimable", "stress", "paired", "descriptive", "exhaustive"]


@dataclass(frozen=True)
class R141AnalysisPlan:
    estimator: str
    interval: str
    multiplicity_family: str
    correction: str
    primary_metric: str
    secondary_metrics: tuple[str, ...]
    bootstrap_replicates: int
    simultaneous_band: str
    power_target: float | None

    def __post_init__(self) -> None:
        if self.bootstrap_replicates < 0:
            raise ValueError("bootstrap_replicates must be non-negative")
        if self.power_target is not None and not 0.0 < self.power_target < 1.0:
            raise ValueError("power_target must be in (0,1)")


@dataclass(frozen=True)
class R141Cell:
    cell_id: str
    factors: dict[str, int | float | str | bool]
    budget: ResourceBudget
    replicates: int
    timeout_seconds: int
    stopping_rule: str
    censoring_rule: str
    region: RegionRole
    analysis: R141AnalysisPlan

    def __post_init__(self) -> None:
        if not self.cell_id or "/" in self.cell_id or "\\" in self.cell_id:
            raise ValueError("cell_id must be portable")
        if not self.factors:
            raise ValueError("cell factors must be non-empty")
        if self.replicates <= 0 or self.timeout_seconds <= 0:
            raise ValueError("replicates and timeout must be positive")


def publication_scale_plan() -> dict[str, Any]:
    value = json.loads(SCALE_PLAN_PATH.read_text(encoding="utf-8"))
    if value.get("schema") != "sigma-v3-r15-publication-scale-plan-v1":
        raise ValueError("unexpected publication-scale plan schema")
    return value


def confirmatory_attack_ids_r141() -> tuple[str, ...]:
    return tuple(
        item.attack_id for item in ATTACK_DISPOSITIONS if item.disposition == "confirmatory"
    )


def _claims_for(attack_id: str) -> tuple[str, ...]:
    claims = tuple(
        sorted(
            item.claim_id
            for item in CLAIMS
            if item.disposition == "confirmatory" and attack_id in item.attacks
        )
    )
    if claims:
        return claims
    raise ValueError(f"no confirmatory claim bound to {attack_id}")


def _execution_kind(attack_id: str) -> str:
    return next(item.execution for item in ATTACK_DISPOSITIONS if item.attack_id == attack_id)


def _budget(
    work: int,
    *,
    qa: int = 0,
    qj: int = 0,
    qh: int = 0,
    qr: int = 0,
    p: int = 1,
    mu: int = 0,
    u: int = 1,
) -> ResourceBudget:
    return ResourceBudget(work, qa, qj, qh, qr, max(1, qr), p, mu, u)


def _analysis(
    primary: str,
    *,
    estimator: str,
    family: str,
    interval: str = "95% CI",
    correction: str = "Holm",
    secondary: tuple[str, ...] = (),
    bootstrap: int = 10_000,
    simultaneous: str = "95% deterministic bootstrap max-deviation",
    power: float | None = 0.95,
) -> R141AnalysisPlan:
    return R141AnalysisPlan(
        estimator,
        interval,
        family,
        correction,
        primary,
        secondary,
        bootstrap,
        simultaneous,
        power,
    )


def _cell(
    attack_id: str,
    index: int,
    factors: dict[str, int | float | str | bool],
    budget: ResourceBudget,
    replicates: int,
    timeout: int,
    analysis: R141AnalysisPlan,
    *,
    region: RegionRole,
    stopping: str = "first-success-or-budget",
    censoring: str = "right-censor at declared budget; timeout/error separate",
) -> R141Cell:
    return R141Cell(
        f"{attack_id.lower()}-{index:03d}",
        factors,
        budget,
        replicates,
        timeout,
        stopping,
        censoring,
        region,
        analysis,
    )


def _collision_budget(bits: int, state_count: int) -> int:
    return min(1 << 22, math.ceil(4.0 * 2 ** (bits * state_count / 2)))


def _preimage_budget(bits: int, state_count: int) -> int:
    return min(1 << 22, 4 * (1 << (bits * state_count)))


def cells_for_attack_r141(attack_id: str) -> tuple[R141Cell, ...]:
    plan = publication_scale_plan()["campaigns"]
    cells: list[R141Cell] = []
    index = 0

    if attack_id == "HIST-01":
        spec = plan["HIST-01A"]
        analysis = _analysis(
            "next_state_match_rate",
            estimator="exact binomial; 99% one-sided bound on zero events",
            family="history-crossing",
            secondary=("full_state_match_rate", "crossings", "run_length"),
            bootstrap=0,
            simultaneous="Holm across width/round cells",
        )
        for bits in spec["widths"]:
            for round_index in spec["round_indices"]:
                work = 1 << min(21, bits + 3)
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "mode": "natural-crossing",
                            "state_bits": bits,
                            "history_bits": bits,
                            "round_index": round_index,
                            "candidate_budget": work,
                            "crossing_target": spec["crossing_target"],
                        },
                        _budget(
                            work,
                            qa=work,
                            qh=work * 2,
                            qr=work * 4,
                            mu=work,
                        ),
                        spec["replicates_per_cell"],
                        7200,
                        analysis,
                        region="estimable",
                        stopping="collect-crossings-until-target-or-budget",
                    )
                )
                index += 1
        conditional = plan["HIST-01B"]
        for bits in conditional["widths"]:
            for round_index in conditional["round_indices"]:
                trials = conditional["trials_per_batch"]
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "mode": "conditional-crossing",
                            "state_bits": bits,
                            "history_bits": bits,
                            "round_index": round_index,
                            "trials_per_batch": trials,
                        },
                        _budget(
                            trials * 8,
                            qh=trials * 2,
                            qr=trials * 4,
                            mu=trials,
                        ),
                        conditional["batches_per_cell"],
                        3600,
                        analysis,
                        region="estimable",
                        stopping="fixed-conditional-trial-count",
                    )
                )
                index += 1

    elif attack_id == "HIST-02":
        spec = plan["HIST-02"]
        analysis = _analysis(
            "queries_to_first_full_state_collision",
            estimator="Kaplan-Meier median and RMST",
            family="full-state-collision",
            secondary=("collision_pairs", "censored_fraction"),
        )
        for bits in spec["widths"]:
            work = 1 << min(22, bits + 4)
            cells.append(
                _cell(
                    attack_id,
                    index,
                    {
                        "state_bits": bits,
                        "history_bits": bits,
                        "round_index": 1,
                        "candidate_budget": work,
                    },
                    _budget(work, qa=work, qh=work, qr=work, mu=work),
                    spec["replicates_per_cell"],
                    7200,
                    analysis,
                    region="estimable",
                )
            )
            index += 1

    elif attack_id == "HIST-03":
        spec = plan["HIST-03"]
        analysis = _analysis(
            "queries",
            estimator="exact first-hit / exhaustive functional-graph profile",
            family="history-step",
            secondary=("collision_pairs", "cycles", "max_cycle_length", "max_tail_length"),
            bootstrap=0,
            simultaneous="Holm across game/width cells",
        )
        for bits in spec["widths"]:
            for game in spec["games"]:
                work = 1 << bits
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "history_bits": bits,
                            "game": game,
                            "input_budget": work,
                        },
                        _budget(work, qh=work, mu=work),
                        spec["replicates_per_cell"],
                        7200,
                        analysis,
                        region="exhaustive",
                    )
                )
                index += 1

    elif attack_id == "HIST-05":
        spec = plan["HIST-05"]
        analysis = _analysis(
            "full_collision_pairs",
            estimator="width-scaling regression",
            family="history-truncation",
            secondary=("visible_collision_pairs", "image_size"),
        )
        for bits in spec["history_widths"]:
            work = 1 << bits
            cells.append(
                _cell(
                    attack_id,
                    index,
                    {"state_bits": 8, "history_bits": bits, "round_index": 0},
                    _budget(work, qh=work, qr=work, mu=work),
                    spec["replicates_per_cell"],
                    7200,
                    analysis,
                    region="exhaustive",
                    stopping="exhaustive-history-map",
                )
            )
            index += 1

    elif attack_id in ("HIST-06", "LAYOUT-04"):
        spec = plan[attack_id]
        analysis = _analysis(
            "plan_collision_rate",
            estimator="exact occupancy + bootstrap",
            family="layout-history",
            secondary=("frame_collision_pairs", "unique_plans", "tie_count"),
        )
        for bits in spec["history_widths"]:
            for slots in spec["slots"]:
                work = 1 << bits
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "history_bits": bits,
                            "field_count": 5,
                            "slots": slots,
                            "variants": ",".join(spec["variants"]),
                        },
                        _budget(work, qh=work, mu=work),
                        spec["replicates_per_cell"],
                        7200,
                        analysis,
                        region="exhaustive",
                        stopping="exhaustive-history-enumeration",
                    )
                )
                index += 1

    elif attack_id == "RED-02":
        spec = plan["RED-02"]
        analysis = _analysis(
            "queries_to_first_window_collision",
            estimator="Kaplan-Meier Q50/RMST + log2 slope",
            family="collision-scaling",
            secondary=("censored_fraction", "slope"),
        )
        for construction in spec["constructions"]:
            for state_count_text, widths in spec["widths_by_k"].items():
                state_count = int(state_count_text)
                for bits in widths:
                    work = _collision_budget(bits, state_count)
                    region: RegionRole = "stress" if work == 1 << 22 else "estimable"
                    cells.append(
                        _cell(
                            attack_id,
                            index,
                            {
                                "construction": construction,
                                "state_bits": bits,
                                "history_bits": bits,
                                "state_count": state_count,
                                "target_round": 2,
                                "max_candidates": work,
                            },
                            _budget(
                                work,
                                qa=work,
                                qh=work if construction == "r125" else 0,
                                qr=work,
                                mu=work,
                            ),
                            spec["replicates_per_cell"],
                            14_400,
                            analysis,
                            region=region,
                        )
                    )
                    index += 1

    elif attack_id in ("RED-03", "RED-04"):
        spec = plan[attack_id]
        analysis = _analysis(
            "queries",
            estimator="Kaplan-Meier median/RMST",
            family="preimage" if attack_id == "RED-03" else "second-preimage",
            secondary=("success_rate", "censored_fraction"),
        )
        policies = ("fixed-target",) if attack_id == "RED-03" else tuple(spec["policies"])
        for construction in ("r12", "r125"):
            for bits in spec["widths"]:
                region: RegionRole = (
                    "estimable" if bits in spec.get("estimable_widths", [4, 6, 8, 10]) else "stress"
                )
                reps = (
                    spec["replicates_estimable"]
                    if region == "estimable"
                    else spec["replicates_stress"]
                )
                for policy in policies:
                    work = _preimage_budget(bits, 2)
                    cells.append(
                        _cell(
                            attack_id,
                            index,
                            {
                                "construction": construction,
                                "state_bits": bits,
                                "history_bits": bits,
                                "state_count": 2,
                                "target_round": 2,
                                "policy": policy,
                                "max_candidates": work,
                            },
                            _budget(
                                work,
                                qa=work,
                                qh=work if construction == "r125" else 0,
                                qr=work,
                            ),
                            reps,
                            14_400,
                            analysis,
                            region=region,
                        )
                    )
                    index += 1

    elif attack_id == "RED-05":
        spec = plan["RED-05"]
        analysis = _analysis(
            "queries",
            estimator="Kaplan-Meier by target count",
            family="multi-target",
            secondary=("union_factor", "censored_fraction"),
        )
        for construction in spec["constructions"]:
            for bits in spec["widths"]:
                for targets in spec["targets"]:
                    work = min(
                        1 << 22,
                        max(1024, math.ceil(4.0 * 2 ** (2 * bits) / targets)),
                    )
                    cells.append(
                        _cell(
                            attack_id,
                            index,
                            {
                                "construction": construction,
                                "state_bits": bits,
                                "history_bits": bits,
                                "targets": targets,
                                "state_count": 2,
                                "max_candidates": work,
                            },
                            _budget(
                                work,
                                qa=work,
                                qh=work if construction == "r125" else 0,
                                qr=work,
                                u=targets,
                            ),
                            spec["replicates_per_cell"],
                            14_400,
                            analysis,
                            region="stress" if work == 1 << 22 else "estimable",
                        )
                    )
                    index += 1

    elif attack_id in ("TMTO-01", "TMTO-02"):
        spec = plan["TMTO"]
        strategies = (
            ("direct", "distinguished", "rho") if attack_id == "TMTO-01" else ("hellman", "rainbow")
        )
        analysis = _analysis(
            "online_queries",
            estimator="Pareto frontier with exact dominance",
            family="tmto",
            correction="none",
            secondary=("offline_queries", "memory_entries", "reuse_rate"),
        )
        for construction in spec["constructions"]:
            for bits in spec["widths"]:
                for strategy in strategies:
                    work = 1024 * 64 * 9
                    cells.append(
                        _cell(
                            attack_id,
                            index,
                            {
                                "construction": construction,
                                "state_bits": bits,
                                "history_bits": bits,
                                "strategy": strategy,
                                "entries": 1024,
                                "chain_length": 64,
                                "distinguished_bits": 4,
                                "targets": 8,
                            },
                            _budget(
                                work,
                                qh=work if construction == "r125" else 0,
                                qr=work,
                                mu=1024,
                                u=8,
                            ),
                            spec["replicates_per_cell"],
                            14_400,
                            analysis,
                            region="estimable",
                            stopping="fixed-offline-and-online-budget",
                        )
                    )
                    index += 1

    elif attack_id == "PARAM-01":
        spec = plan["PARAM-01"]
        samples = spec["samples_per_replicate"]
        analysis = _analysis(
            "max_deviation",
            estimator="joint GOF with exact Monte-Carlo fallback",
            family="parameter-uniformity",
            bootstrap=0,
            simultaneous="simultaneous multinomial/Monte-Carlo 95%",
        )
        cells.append(
            _cell(
                attack_id,
                0,
                {
                    "samples": samples,
                    "t_min": 2,
                    "t_max": 32,
                    "k_min": 2,
                    "k_max": 4,
                },
                _budget(samples, qa=samples, qj=samples),
                spec["replicates"],
                7200,
                analysis,
                region="estimable",
                stopping="fixed-sample",
            )
        )

    elif attack_id == "PARAM-02":
        spec = plan["PARAM-02"]
        samples = spec["samples_per_replicate"]
        permutations = spec["permutations"]
        analysis = _analysis(
            "mutual_information",
            estimator="discrete MI with deterministic permutation null",
            family="parameter-correlation",
            bootstrap=0,
            simultaneous="Holm over candidate/persistent MI endpoints",
        )
        cells.append(
            _cell(
                attack_id,
                0,
                {
                    "samples": samples,
                    "permutations": permutations,
                    "candidate_bucket_bits": 6,
                    "persistent_bucket_bits": 6,
                },
                _budget(
                    samples * (permutations + 1),
                    qa=samples,
                    qj=samples,
                ),
                spec["replicates"],
                14_400,
                analysis,
                region="estimable",
                stopping="fixed-sample-and-permutation-budget",
            )
        )

    elif attack_id == "PARAM-03":
        spec = plan["PARAM-03"]
        analysis = _analysis(
            "net_work_ratio",
            estimator="paired ratio",
            family="parameter-grinding",
            secondary=("selected_cost", "preparation_work"),
        )
        for candidates in spec["candidate_budgets"]:
            cells.append(
                _cell(
                    attack_id,
                    index,
                    {"candidate_budget": candidates, "cost": "t+k-1"},
                    _budget(candidates * 4, qa=candidates, qj=candidates),
                    spec["replicates_per_cell"],
                    7200,
                    analysis,
                    region="estimable",
                    stopping="minimum-cost-stratum-or-budget",
                )
            )
            index += 1

    elif attack_id == "PARAM-04":
        spec = plan["PARAM-04"]
        guesses = spec["guesses_per_replicate"]
        analysis = _analysis(
            "work_per_guess",
            estimator="paired full-Sigma vs early-reject-Sigma ratio",
            family="kdf",
            secondary=("early_reject_rate", "argon_ns", "sigma_ns"),
        )
        for host_slot in range(spec["physical_hosts"]):
            cells.append(
                _cell(
                    attack_id,
                    index,
                    {
                        "host_slot": host_slot,
                        "guesses": guesses,
                        "argon_memory_kib": 19_456,
                        "argon_time_cost": 2,
                        "modes": "argon2id,full-sigma,early-reject-sigma",
                    },
                    _budget(
                        guesses * 64,
                        qa=guesses,
                        qj=guesses,
                        qr=guesses * 35,
                        mu=19_456 * 1024,
                    ),
                    spec["paired_replicates_per_host"],
                    28_800,
                    analysis,
                    region="paired",
                    stopping="fixed-guess-budget",
                )
            )
            index += 1

    elif attack_id == "PARAM-05":
        spec = plan["PARAM-05"]
        analysis = _analysis(
            "throughput_ratio",
            estimator="paired full-evaluation vs prepare-select-evaluate ratio",
            family="pow",
            secondary=("selected_cost", "mean_cost", "preparation_ns"),
        )
        for host_slot in range(spec["physical_hosts"]):
            for nonces in spec["nonce_budgets"]:
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "host_slot": host_slot,
                            "nonces": nonces,
                            "modes": "full-each,select-cheapest",
                        },
                        _budget(
                            nonces * 64,
                            qa=nonces,
                            qj=nonces,
                            qr=nonces * 35,
                        ),
                        spec["paired_replicates_per_host_per_budget"],
                        28_800,
                        analysis,
                        region="paired",
                        stopping="fixed-nonce-budget",
                    )
                )
                index += 1

    elif attack_id == "PARAM-06":
        spec = plan["PARAM-06"]
        analysis = _analysis(
            "work_ratio",
            estimator="paired mitigation cost comparison",
            family="mitigation",
            secondary=("variance", "minimum", "maximum"),
        )
        for host_slot in range(spec["physical_hosts"]):
            for mode in spec["modes"]:
                samples = 4096
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "host_slot": host_slot,
                            "mode": mode,
                            "samples": samples,
                            "bucket_upper_bounds": "8,16,24,35",
                            "context_fixed_t": 17,
                            "context_fixed_k": 3,
                        },
                        _budget(samples * 64, qa=samples, qj=samples),
                        spec["replicates_per_host_per_mode"],
                        14_400,
                        analysis,
                        region="paired",
                        stopping="fixed-sample",
                    )
                )
                index += 1

    elif attack_id == "BRANCH-05":
        spec = plan["BRANCH-05"]
        faults = (
            "normal",
            "constant-first",
            "copied-first-two",
            "truncated-first",
            "omitted-last",
            "permuted",
            "constant-fold",
            "truncated-fold",
        )
        analysis = _analysis(
            "collision_pairs",
            estimator="image/collision profile",
            family="deep-fold",
            secondary=("image_size", "conservative_bits"),
        )
        for fault in faults:
            cells.append(
                _cell(
                    attack_id,
                    index,
                    {
                        "mode": "deep",
                        "fault": fault,
                        "state_bits": 8,
                        "branch_count": 4,
                        "candidates": 65_536,
                    },
                    _budget(65_536, qr=65_536, mu=65_536),
                    spec["replicates_per_fault"],
                    7200,
                    analysis,
                    region="estimable",
                    stopping="fixed-candidate-budget",
                )
            )
            index += 1

    elif attack_id == "BRANCH-06":
        spec = plan["BRANCH-06"]
        faults = (
            "normal",
            "constant-first",
            "copied-first-two",
            "truncated-first",
            "omitted-last",
            "permuted",
        )
        analysis = _analysis(
            "affected_branches",
            estimator="component-intervention dependency coverage",
            family="deep-vector",
            secondary=("all_branches_affected_rate", "hamming_distance"),
        )
        for fault in faults:
            cells.append(
                _cell(
                    attack_id,
                    index,
                    {
                        "mode": "deep-vector",
                        "fault": fault,
                        "state_bits": 8,
                        "branch_count": 4,
                        "candidates": 65_536,
                    },
                    _budget(65_536 * 4, qr=65_536 * 4, mu=65_536),
                    spec["replicates_per_fault"],
                    7200,
                    analysis,
                    region="estimable",
                    stopping="fixed-intervention-budget",
                )
            )
            index += 1

    elif attack_id == "STAT-01":
        spec = plan["STAT-01"]
        bytes_per_stream = spec["bytes_per_stream"]
        analysis = _analysis(
            "adjusted_anomaly_rate",
            estimator="external calibrated battery family summary",
            family="statistical-controls",
            correction="Holm primary; BH exploratory",
            secondary=("p_value_distribution", "tool_failures"),
            bootstrap=0,
            simultaneous="battery-family calibrated summary",
            power=None,
        )
        for construction in (
            "SHA512",
            "SHA3-512",
            "BLAKE2b-512",
            "SHAKE256-512",
            "R12.5-wide",
            "R12.5-deep",
            "R12.5-vector",
            "broken-control",
        ):
            for corpus in ("counter", "ff-tail", "alternating"):
                cells.append(
                    _cell(
                        attack_id,
                        index,
                        {
                            "construction": construction,
                            "corpus": corpus,
                            "streams": spec["streams_per_cell"],
                            "bytes_per_stream": bytes_per_stream,
                            "aggregate_bytes": bytes_per_stream * spec["streams_per_cell"],
                            "batteries": "nist-sts,practrand,testu01-smallcrush,testu01-crush",
                            "stream_retention": "ephemeral",
                        },
                        _budget(bytes_per_stream, mu=16 * 1024 * 1024),
                        spec["streams_per_cell"],
                        28_800,
                        analysis,
                        region="descriptive",
                        stopping="complete-declared-battery-set",
                        censoring="tool failure/unavailable is explicit, never omitted",
                    )
                )
                index += 1
    else:
        raise ValueError(f"no R14.1 publication-scale design for {attack_id}")

    return tuple(cells)


def protocol_summary_r141() -> dict[str, object]:
    attacks = confirmatory_attack_ids_r141()
    return {
        "schema": "sigma-v3-r14-1-protocol-v1",
        "freeze_id": R141_FREEZE_ID,
        "tag": R141_TAG,
        "r12_5_baseline": R12_5_BASELINE,
        "r13_baseline": R13_BASELINE,
        "seed_namespace": R141_CONFIRMATORY_NAMESPACE,
        "confirmatory_executed": False,
        "attacks": {
            attack_id: {
                "execution_kind": _execution_kind(attack_id),
                "claims": _claims_for(attack_id),
                "cells": [asdict(cell) for cell in cells_for_attack_r141(attack_id)],
            }
            for attack_id in attacks
        },
    }


__all__ = [
    "R141_CONFIRMATORY_NAMESPACE",
    "R141_FREEZE_ID",
    "R141_TAG",
    "R141AnalysisPlan",
    "R141Cell",
    "cells_for_attack_r141",
    "confirmatory_attack_ids_r141",
    "protocol_summary_r141",
    "publication_scale_plan",
]
