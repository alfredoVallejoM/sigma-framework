"""R14.1/R15 v2 config and deterministic seed schema."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal

from .r13_schema import RESOURCE_FIELDS, ResourceBudget
from .r141_protocol import (
    R141_CONFIRMATORY_NAMESPACE,
    R141_FREEZE_ID,
    confirmatory_attack_ids_r141,
)

TerminalStatusR141 = Literal["success", "no-success", "censored", "timeout", "error"]


def _is_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be non-empty")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def _record_hash(data: dict[str, Any]) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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


@dataclass(frozen=True)
class ConfirmatoryRecordR141:
    schema: str
    campaign_id: str
    freeze_id: str
    attack_id: str
    claim_ids: tuple[str, ...]
    construction: str
    cell_id: str
    replicate_id: int
    seed_hex: str
    phase: str
    declared: ResourceBudget
    observed: ResourceBudget
    status: TerminalStatusR141
    metrics: dict[str, int | float | str | bool | None]
    censor_reason: str | None
    error_class: str | None
    code_commit: str
    artifact_sha256: str
    config_sha256: str
    preregistration_sha256: str
    dependency_lock_sha256: str
    execution_manifest_sha256: str
    host_id: str
    platform_name: str
    architecture: str
    python_version: str
    started_utc: str
    completed_utc: str
    record_sha256: str

    @classmethod
    def create(
        cls,
        *,
        campaign_id: str,
        attack_id: str,
        claim_ids: tuple[str, ...],
        construction: str,
        cell_id: str,
        replicate_id: int,
        declared: ResourceBudget,
        observed: ResourceBudget,
        status: TerminalStatusR141,
        metrics: dict[str, int | float | str | bool | None],
        censor_reason: str | None,
        error_class: str | None,
        code_commit: str,
        artifact_sha256: str,
        config_sha256: str,
        preregistration_sha256: str,
        dependency_lock_sha256: str,
        execution_manifest_sha256: str,
        host_id: str,
        platform_name: str,
        architecture: str,
        python_version: str,
        started_utc: str,
        completed_utc: str,
    ) -> "ConfirmatoryRecordR141":
        seed_hex = derive_confirmatory_seed_r141(attack_id, cell_id, replicate_id).hex()
        base: dict[str, Any] = {
            "schema": "sigma-v3-r15-record-v2",
            "campaign_id": campaign_id,
            "freeze_id": R141_FREEZE_ID,
            "attack_id": attack_id,
            "claim_ids": list(claim_ids),
            "construction": construction,
            "cell_id": cell_id,
            "replicate_id": replicate_id,
            "seed_hex": seed_hex,
            "phase": "confirmatory",
            "declared": asdict(declared),
            "observed": asdict(observed),
            "status": status,
            "metrics": metrics,
            "censor_reason": censor_reason,
            "error_class": error_class,
            "code_commit": code_commit,
            "artifact_sha256": artifact_sha256,
            "config_sha256": config_sha256,
            "preregistration_sha256": preregistration_sha256,
            "dependency_lock_sha256": dependency_lock_sha256,
            "execution_manifest_sha256": execution_manifest_sha256,
            "host_id": host_id,
            "platform_name": platform_name,
            "architecture": architecture,
            "python_version": python_version,
            "started_utc": started_utc,
            "completed_utc": completed_utc,
        }
        return cls(
            schema="sigma-v3-r15-record-v2",
            campaign_id=campaign_id,
            freeze_id=R141_FREEZE_ID,
            attack_id=attack_id,
            claim_ids=claim_ids,
            construction=construction,
            cell_id=cell_id,
            replicate_id=replicate_id,
            seed_hex=seed_hex,
            phase="confirmatory",
            declared=declared,
            observed=observed,
            status=status,
            metrics=metrics,
            censor_reason=censor_reason,
            error_class=error_class,
            code_commit=code_commit,
            artifact_sha256=artifact_sha256,
            config_sha256=config_sha256,
            preregistration_sha256=preregistration_sha256,
            dependency_lock_sha256=dependency_lock_sha256,
            execution_manifest_sha256=execution_manifest_sha256,
            host_id=host_id,
            platform_name=platform_name,
            architecture=architecture,
            python_version=python_version,
            started_utc=started_utc,
            completed_utc=completed_utc,
            record_sha256=_record_hash(base),
        )

    def __post_init__(self) -> None:
        if self.schema != "sigma-v3-r15-record-v2":
            raise ValueError("unexpected R14.1 confirmatory record schema")
        if self.freeze_id != R141_FREEZE_ID:
            raise ValueError("record freeze_id mismatch")
        if self.attack_id not in confirmatory_attack_ids_r141():
            raise ValueError("record attack is not confirmatory")
        if self.phase != "confirmatory":
            raise ValueError("R15 record phase must be confirmatory")
        if self.status not in ("success", "no-success", "censored", "timeout", "error"):
            raise ValueError("invalid terminal status")
        if not self.campaign_id or not self.construction or not self.cell_id:
            raise ValueError("campaign/construction/cell identity must be non-empty")
        if not self.claim_ids or any(
            not isinstance(claim, str) or not claim.startswith("C") for claim in self.claim_ids
        ):
            raise ValueError("record must bind claim ids")
        if isinstance(self.replicate_id, bool) or not isinstance(self.replicate_id, int):
            raise TypeError("replicate_id must be int")
        if self.replicate_id < 0:
            raise ValueError("replicate_id must be non-negative")
        for field in RESOURCE_FIELDS:
            if getattr(self.observed, field) > getattr(self.declared, field):
                raise ValueError("observed resources exceed declared budget")
        expected_seed = derive_confirmatory_seed_r141(
            self.attack_id, self.cell_id, self.replicate_id
        ).hex()
        if self.seed_hex != expected_seed:
            raise ValueError("record seed differs from frozen derivation")
        if self.status == "censored" and not self.censor_reason:
            raise ValueError("censored result requires a reason")
        if self.status == "error" and not self.error_class:
            raise ValueError("error result requires error_class")
        if self.status not in ("censored", "error") and (
            self.censor_reason is not None or self.error_class is not None
        ):
            raise ValueError("terminal annotations do not match status")
        if len(self.code_commit) not in (40, 64) or any(
            character not in "0123456789abcdef" for character in self.code_commit
        ):
            raise ValueError("code_commit must be a lowercase Git object id")
        for value in (
            self.artifact_sha256,
            self.config_sha256,
            self.preregistration_sha256,
            self.dependency_lock_sha256,
            self.execution_manifest_sha256,
        ):
            if not _is_sha256(value):
                raise ValueError("integrity identifiers must be SHA-256 hex")
        for value in (
            self.host_id,
            self.platform_name,
            self.architecture,
            self.python_version,
        ):
            if not isinstance(value, str) or not value:
                raise ValueError("environment identity fields must be non-empty")
        started = _timestamp(self.started_utc)
        completed = _timestamp(self.completed_utc)
        if completed < started:
            raise ValueError("completed_utc precedes started_utc")

        payload = asdict(self)
        provided = payload.pop("record_sha256")
        if not _is_sha256(provided) or provided != _record_hash(payload):
            raise ValueError("record integrity hash mismatch")


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
    "ConfirmatoryRecordR141",
    "TerminalStatusR141",
    "config_from_dict_r141",
    "derive_confirmatory_seed_r141",
    "validate_r141_cell",
]
