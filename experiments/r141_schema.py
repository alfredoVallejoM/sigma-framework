"""R14.1/R15 v2 config and deterministic seed schema."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

from .r13_schema import RESOURCE_FIELDS, ResourceBudget
from .r141_protocol import (
    R141_CONFIRMATORY_NAMESPACE,
    R141_FREEZE_ID,
    confirmatory_attack_ids_r141,
)


@dataclass(frozen=True)
class ConfirmatoryConfigR141:
    schema: str
    campaign: str
    freeze_id: str
    attack_id: str
    seed_namespace: str
    execution_kind: str
    claims: tuple[str, ...]
    cells: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        if self.schema != "sigma-v3-r15-config-v2":
            raise ValueError("unexpected R14.1 config schema")
        if self.campaign != "confirmatory-v3-r141":
            raise ValueError("unexpected R14.1 campaign")
        if self.freeze_id != R141_FREEZE_ID:
            raise ValueError("R14.1 freeze id mismatch")
        if self.attack_id not in confirmatory_attack_ids_r141():
            raise ValueError("attack is not confirmatory")
        if self.seed_namespace != R141_CONFIRMATORY_NAMESPACE:
            raise ValueError("seed namespace mismatch")
        if self.execution_kind not in ("internal", "external"):
            raise ValueError("invalid execution kind")
        if not self.claims or not self.cells:
            raise ValueError("claims/cells must be non-empty")
        ids: list[str] = []
        for cell in self.cells:
            validate_r141_cell(cell)
            ids.append(cell["cell_id"])
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate cell ids")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_r141_cell(cell: dict[str, Any]) -> None:
    required = {
        "cell_id",
        "factors",
        "budget",
        "replicates",
        "timeout_seconds",
        "stopping_rule",
        "censoring_rule",
        "region",
        "analysis",
    }
    if set(cell) != required:
        raise ValueError("invalid R14.1 cell fields")
    if cell["region"] not in ("estimable", "stress", "paired", "descriptive", "exhaustive"):
        raise ValueError("invalid cell region")
    budget = cell["budget"]
    if not isinstance(budget, dict) or set(budget) != set(RESOURCE_FIELDS):
        raise ValueError("invalid ResourceBudget")
    ResourceBudget(**budget)
    if not isinstance(cell["replicates"], int) or cell["replicates"] <= 0:
        raise ValueError("replicates must be positive")
    if not isinstance(cell["timeout_seconds"], int) or cell["timeout_seconds"] <= 0:
        raise ValueError("timeout must be positive")
    analysis = cell["analysis"]
    required_analysis = {
        "estimator",
        "interval",
        "multiplicity_family",
        "correction",
        "primary_metric",
        "secondary_metrics",
        "bootstrap_replicates",
        "simultaneous_band",
        "power_target",
    }
    if not isinstance(analysis, dict) or set(analysis) != required_analysis:
        raise ValueError("invalid R14.1 analysis fields")
    if analysis["bootstrap_replicates"] < 0:
        raise ValueError("bootstrap_replicates must be non-negative")


def config_from_dict_r141(data: dict[str, Any]) -> ConfirmatoryConfigR141:
    required = {
        "schema",
        "campaign",
        "freeze_id",
        "attack_id",
        "seed_namespace",
        "execution_kind",
        "claims",
        "cells",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("invalid R14.1 config fields")
    return ConfirmatoryConfigR141(
        schema=data["schema"],
        campaign=data["campaign"],
        freeze_id=data["freeze_id"],
        attack_id=data["attack_id"],
        seed_namespace=data["seed_namespace"],
        execution_kind=data["execution_kind"],
        claims=tuple(data["claims"]),
        cells=tuple(data["cells"]),
    )


def derive_confirmatory_seed_r141(
    attack_id: str,
    cell_id: str,
    replicate_id: int,
) -> bytes:
    if attack_id not in confirmatory_attack_ids_r141():
        raise ValueError("attack is not confirmatory")
    if not cell_id:
        raise ValueError("cell_id must be non-empty")
    if isinstance(replicate_id, bool) or not isinstance(replicate_id, int) or replicate_id < 0:
        raise ValueError("replicate_id must be non-negative int")
    fields = (
        R141_CONFIRMATORY_NAMESPACE.encode("ascii"),
        R141_FREEZE_ID.encode("ascii"),
        attack_id.encode("ascii"),
        cell_id.encode("ascii"),
        replicate_id.to_bytes(8, "big"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


__all__ = [
    "ConfirmatoryConfigR141",
    "config_from_dict_r141",
    "derive_confirmatory_seed_r141",
    "validate_r141_cell",
]
