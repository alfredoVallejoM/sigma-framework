"""Predeclared R14 analysis and figure schemas.

The functions operate on synthetic or future R15 records. R14 uses only
synthetic fixtures so no confirmatory result is observed before freeze.
"""

from __future__ import annotations

from dataclasses import dataclass

from .r13_schema import ResourceBudget
from .r14_protocol import CLAIMS, FREEZE_ID, confirmatory_attack_ids, confirmatory_cells
from .r14_schema import ConfirmatoryRecordV3, derive_confirmatory_seed


@dataclass(frozen=True)
class FigureSpecV3:
    figure_id: str
    title: str
    attack_ids: tuple[str, ...]
    fields: tuple[str, ...]
    transform: str
    uncertainty: str


# fmt: off
FIGURES_V3 = (
    FigureSpecV3("F01", "Sigma-IAP causal architecture", ("HIST-01",), ("state_bits",), "schematic-only", "none"),
    FigureSpecV3("F02", "Visible crossing without historical coalescence", ("HIST-01",), ("next_state_match_rate",), "group by width/round", "exact 95%"),
    FigureSpecV3("F03", "Visible versus full-state collision scaling", ("HIST-02", "HIST-05"), ("queries_to_first_full_state_collision", "full_collision_pairs"), "log2 work vs width", "bootstrap 95%"),
    FigureSpecV3("F04", "Multi-state collision scaling", ("RED-02",), ("queries_to_first_window_collision",), "Kaplan-Meier Q50 by k", "bootstrap 95%"),
    FigureSpecV3("F05", "Reduced second-preimage work", ("RED-04",), ("queries",), "KM/RMST by policy", "bootstrap 95%"),
    FigureSpecV3("F06", "Time-memory trade-off frontier", ("TMTO-01", "TMTO-02"), ("online_queries", "offline_queries", "memory_entries"), "Pareto frontier", "bootstrap 95%"),
    FigureSpecV3("F07", "Derived parameter distribution and grinding", ("PARAM-01", "PARAM-03"), ("max_deviation", "net_work_ratio"), "joint distribution + paired ratio", "simultaneous/paired 95%"),
    FigureSpecV3("F08", "History-aware layout ablation", ("HIST-06", "LAYOUT-04"), ("plan_collision_rate",), "variant comparison", "bootstrap 95%"),
    FigureSpecV3("F09", "Deep and DeepVector fault controls", ("BRANCH-05", "BRANCH-06"), ("collision_pairs", "affected_branches"), "fault-profile comparison", "bootstrap/simultaneous 95%"),
    FigureSpecV3("F10", "Cost decomposition", ("PARAM-04", "PARAM-05"), ("work_per_guess", "throughput_ratio"), "paired component cost", "bootstrap 95%"),
    FigureSpecV3("F11", "TMTO memory/work frontier", ("TMTO-01", "TMTO-02"), ("memory_entries", "online_queries"), "Pareto projection", "bootstrap 95%"),
    FigureSpecV3("F12", "KDF early rejection", ("PARAM-04",), ("work_per_guess",), "paired fixed-vs-derived", "paired bootstrap 95%"),
    FigureSpecV3("F13", "PoW nonce-cost grinding", ("PARAM-05", "PARAM-06"), ("throughput_ratio", "work_ratio"), "paired cost ratio", "paired bootstrap 95%"),
    FigureSpecV3("F14", "Statistical controls", ("STAT-01",), ("adjusted_anomaly_rate",), "external battery calibrated summary", "descriptive"),
    FigureSpecV3("F15", "Cross-platform conformance", ("HIST-01",), ("status",), "engineering summary from frozen gates", "none"),
)

# fmt: on

TABLES_V3 = (
    "suite-domain-registry",
    "claims-evidence",
    "theorem-assumption-status",
    "attacker-budgets",
    "kat-corpus",
    "negative-results",
    "performance",
    "host-reproduction",
    "limitations",
)


def synthetic_fixture_records() -> list[ConfirmatoryRecordV3]:
    """Create schema-valid synthetic records; never use them as evidence."""

    records: list[ConfirmatoryRecordV3] = []
    claims_by_attack = {
        attack_id: tuple(
            claim.claim_id
            for claim in CLAIMS
            if attack_id in claim.attacks and claim.disposition == "confirmatory"
        )
        for attack_id in confirmatory_attack_ids()
    }
    for attack_id in confirmatory_attack_ids():
        cell = confirmatory_cells(attack_id)[0]
        metrics: dict[str, int | float | str | bool | None] = {
            cell.analysis.primary_metric: 0.0,
            "synthetic": True,
        }
        records.append(
            ConfirmatoryRecordV3.create(
                campaign_id="synthetic-r14",
                attack_id=attack_id,
                claim_ids=claims_by_attack[attack_id] or ("C12",),
                construction="synthetic",
                cell_id=cell.cell_id,
                replicate_id=0,
                declared=cell.budget,
                observed=ResourceBudget(0, 0, 0, 0, 0, 0, 1, 0, 1),
                status="no-success",
                metrics=metrics,
                censor_reason=None,
                error_class=None,
                code_commit="0" * 40,
                artifact_sha256="0" * 64,
                config_sha256="0" * 64,
                preregistration_sha256="0" * 64,
                dependency_lock_sha256="0" * 64,
                host_id="synthetic",
                platform_name="synthetic",
                architecture="synthetic",
                python_version="synthetic",
                started_utc="2026-09-20T00:00:00+00:00",
                completed_utc="2026-09-20T00:00:00+00:00",
            )
        )
    return records


def figure_payloads(records: list[ConfirmatoryRecordV3]) -> dict[str, dict[str, object]]:
    """Freeze filtering/grouping inputs without choosing presentation from results."""

    by_attack: dict[str, list[ConfirmatoryRecordV3]] = {}
    for record in records:
        by_attack.setdefault(record.attack_id, []).append(record)
    payloads: dict[str, dict[str, object]] = {}
    for figure in FIGURES_V3:
        selected = [
            record
            for attack_id in figure.attack_ids
            for record in by_attack.get(attack_id, ())
        ]
        payloads[figure.figure_id] = {
            "title": figure.title,
            "attack_ids": list(figure.attack_ids),
            "fields": list(figure.fields),
            "transform": figure.transform,
            "uncertainty": figure.uncertainty,
            "records": len(selected),
        }
    return payloads


def validate_synthetic_analysis() -> dict[str, object]:
    records = synthetic_fixture_records()
    payloads = figure_payloads(records)
    if set(payloads) != {item.figure_id for item in FIGURES_V3}:
        raise RuntimeError("synthetic figure coverage is incomplete")
    missing = [
        figure.figure_id
        for figure in FIGURES_V3
        if not figure.attack_ids or any(attack not in confirmatory_attack_ids() for attack in figure.attack_ids)
    ]
    if missing:
        raise RuntimeError(f"figure schemas reference non-confirmatory attacks: {missing}")
    return {
        "schema": "sigma-v3-r14-analysis-gate-v1",
        "synthetic_only": True,
        "records": len(records),
        "figures": len(payloads),
        "tables": len(TABLES_V3),
        "passed": True,
    }


__all__ = [
    "FIGURES_V3",
    "TABLES_V3",
    "FigureSpecV3",
    "figure_payloads",
    "synthetic_fixture_records",
    "validate_synthetic_analysis",
]
