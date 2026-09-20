from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from experiments.freeze import preregistration_is_frozen
from experiments.r13_attack_registry import ATTACK_REGISTRY
from experiments.r13_schema import ResourceBudget
from experiments.r14_analysis import FIGURES_V3, TABLES_V3, validate_synthetic_analysis
from experiments.r14_protocol import (
    ATTACK_DISPOSITIONS,
    CLAIMS,
    CONFIRMATORY_NAMESPACE,
    FREEZE_ID,
    confirmatory_attack_ids,
    confirmatory_cells,
)
from experiments.r14_schema import (
    ConfirmatoryConfigV3,
    ConfirmatoryRecordV3,
    derive_confirmatory_seed,
)
from scripts.prepare_v3_confirmatory import DEFAULT_OUTPUT, render_configs


def test_r14_covers_every_claim_and_r13_attack_once() -> None:
    assert {item.claim_id for item in CLAIMS} == {f"C{index:02d}" for index in range(1, 21)}
    assert len({item.claim_id for item in CLAIMS}) == len(CLAIMS)
    assert {item.attack_id for item in ATTACK_DISPOSITIONS} == set(ATTACK_REGISTRY)
    assert len({item.attack_id for item in ATTACK_DISPOSITIONS}) == len(ATTACK_DISPOSITIONS)


def test_confirmatory_cells_are_closed_and_budgeted() -> None:
    assert len(confirmatory_attack_ids()) == 21
    all_ids: set[str] = set()
    for attack_id in confirmatory_attack_ids():
        cells = confirmatory_cells(attack_id)
        assert cells
        for cell in cells:
            assert cell.cell_id not in all_ids
            all_ids.add(cell.cell_id)
            assert cell.replicates > 0
            assert cell.timeout_seconds > 0
            assert cell.budget.p >= 1
            assert cell.budget.u >= 1
            assert cell.analysis.primary_metric
            assert "p-value" not in cell.stopping_rule.lower()


def test_frozen_configs_are_exactly_regenerable() -> None:
    rendered = render_configs()
    actual = {
        path.name: path.read_bytes()
        for path in DEFAULT_OUTPUT.glob("*.json")
        if path.name != "protocol-freeze.json"
    }
    assert actual == rendered


def test_preregistration_is_explicitly_frozen() -> None:
    text = Path("experiments/preregistration-v3.md").read_text(encoding="utf-8")
    assert preregistration_is_frozen(text)
    assert FREEZE_ID in text


def test_confirmatory_seed_is_deterministic_and_domain_separated() -> None:
    left = derive_confirmatory_seed("HIST-01", "hist-01-000", 0)
    assert left == derive_confirmatory_seed("HIST-01", "hist-01-000", 0)
    assert left != derive_confirmatory_seed("HIST-01", "hist-01-000", 1)
    assert left != derive_confirmatory_seed("HIST-02", "hist-02-000", 0)
    assert len(left) == 32


def test_confirmatory_record_rejects_seed_and_resource_tampering() -> None:
    cell = confirmatory_cells("HIST-01")[0]
    zero = ResourceBudget(0, 0, 0, 0, 0, 0, 1, 0, 1)
    valid = ConfirmatoryRecordV3.create(
        campaign_id="test",
        attack_id="HIST-01",
        claim_ids=("C04",),
        construction="r125",
        cell_id=cell.cell_id,
        replicate_id=0,
        declared=cell.budget,
        observed=zero,
        status="no-success",
        metrics={},
        censor_reason=None,
        error_class=None,
        code_commit="0" * 40,
        artifact_sha256="0" * 64,
        config_sha256="0" * 64,
        preregistration_sha256="0" * 64,
        dependency_lock_sha256="0" * 64,
        host_id="test",
        platform_name="test-os",
        architecture="test-arch",
        python_version="3.13",
        started_utc="2026-09-20T00:00:00+00:00",
        completed_utc="2026-09-20T00:00:01+00:00",
    )
    assert valid.phase == "confirmatory"

    with pytest.raises(ValueError, match="seed"):
        ConfirmatoryRecordV3(
            **{**valid.__dict__, "seed_hex": "00" * 32}
        )

    excessive = ResourceBudget(
        cell.budget.W + 1,
        cell.budget.Q_A,
        cell.budget.Q_J,
        cell.budget.Q_H,
        cell.budget.Q_R,
        cell.budget.d,
        cell.budget.p,
        cell.budget.mu,
        cell.budget.u,
    )
    with pytest.raises(ValueError, match="exceed"):
        ConfirmatoryRecordV3(
            **{**valid.__dict__, "observed": excessive}
        )

    with pytest.raises(ValueError, match="integrity"):
        ConfirmatoryRecordV3(
            **{**valid.__dict__, "metrics": {"tampered": True}}
        )


def test_config_schema_rejects_wrong_namespace() -> None:
    cell = confirmatory_cells("PARAM-01")[0]
    with pytest.raises(ValueError, match="namespace"):
        ConfirmatoryConfigV3(
            "sigma-v3-r15-config-v1",
            "confirmatory-v3",
            FREEZE_ID,
            "PARAM-01",
            "pilot",
            "internal",
            ("C13",),
            (asdict(cell),),
        )
    assert CONFIRMATORY_NAMESPACE == "sigma-v3-r15"


def test_synthetic_analysis_covers_all_predeclared_surfaces() -> None:
    result = validate_synthetic_analysis()
    assert result["passed"] is True
    assert result["synthetic_only"] is True
    assert result["figures"] == len(FIGURES_V3) == 15
    assert result["tables"] == len(TABLES_V3) == 9


def test_campaign_index_declares_no_confirmatory_execution() -> None:
    index = json.loads((DEFAULT_OUTPUT / "campaign-index.json").read_text(encoding="utf-8"))
    assert index["freeze_id"] == FREEZE_ID
    assert index["confirmatory_executed"] is False
    assert {item["attack_id"] for item in index["attacks"]} == set(confirmatory_attack_ids())
