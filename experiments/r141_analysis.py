"""R14.1 synthetic analysis closure over the publication-scale protocol."""

from __future__ import annotations

from experiments.r14_analysis import FIGURES_V3, TABLES_V3
from experiments.r15_estimators import BOOTSTRAP_REPLICATES
from experiments.r141_protocol import confirmatory_attack_ids_r141


def validate_r141_analysis() -> dict[str, object]:
    attacks = set(confirmatory_attack_ids_r141())
    invalid = [
        figure.figure_id
        for figure in FIGURES_V3
        if any(attack not in attacks for attack in figure.attack_ids)
    ]
    if invalid:
        raise RuntimeError(f"R14.1 figures reference non-confirmatory attacks: {invalid}")
    if BOOTSTRAP_REPLICATES != 10_000:
        raise RuntimeError("R14.1 bootstrap constant drifted")
    return {
        "schema": "sigma-v3-r14-1-analysis-gate-v1",
        "passed": True,
        "synthetic_only": True,
        "figures": len(FIGURES_V3),
        "tables": len(TABLES_V3),
        "attacks": len(attacks),
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
    }


__all__ = ["validate_r141_analysis"]
