from __future__ import annotations

from experiments.r13_schema import ResourceBudget
from experiments.r15_estimators import (
    ScalingCellV3,
    bootstrap_scaling_slope_interval_v3,
    bootstrap_survival_statistic_v3,
    holm_adjust_v3,
    kaplan_meier_v3,
    km_q50_v3,
    km_rmst_v3,
    pareto_frontier_v3,
    scaling_slope_v3,
    simultaneous_mean_band_v3,
    zero_event_upper_bound_v3,
)
from experiments.r141_protocol import (
    R141_FREEZE_ID,
    cells_for_attack_r141,
    confirmatory_attack_ids_r141,
)
from experiments.r141_schema import ConfirmatoryRecordR141, derive_confirmatory_seed_r141
from scripts.check_r141_protocol import check_r141_protocol
from scripts.prepare_r141_confirmatory import render_r141_configs


def test_r141_protocol_gate_is_predata_and_publication_scale() -> None:
    report = check_r141_protocol()
    assert report["passed"] is True
    assert report["confirmatory_executed"] is False
    assert report["attacks"] == 21
    assert int(report["run_units"]) >= 150_000


def test_r141_attack_cells_are_nonempty_and_unique() -> None:
    ids: set[tuple[str, str]] = set()
    for attack_id in confirmatory_attack_ids_r141():
        cells = cells_for_attack_r141(attack_id)
        assert cells
        for cell in cells:
            key = (attack_id, cell.cell_id)
            assert key not in ids
            ids.add(key)
            assert cell.replicates > 0
            assert cell.analysis.primary_metric
            assert cell.region in {
                "estimable",
                "stress",
                "paired",
                "descriptive",
                "exhaustive",
            }


def test_r141_generated_configs_include_manifest_and_index() -> None:
    rendered = render_r141_configs()
    assert len(rendered) == 23
    assert "campaign-index.json" in rendered
    assert "config-manifest.json" in rendered
    assert all(data.endswith(b"\n") for data in rendered.values())


def test_r141_seed_derivation_is_domain_separated() -> None:
    left = derive_confirmatory_seed_r141("HIST-01", "hist-01-000", 0)
    assert len(left) == 32
    assert left == derive_confirmatory_seed_r141("HIST-01", "hist-01-000", 0)
    assert left != derive_confirmatory_seed_r141("HIST-01", "hist-01-000", 1)
    assert left != derive_confirmatory_seed_r141("HIST-02", "hist-02-000", 0)
    assert R141_FREEZE_ID.encode() not in left


def test_survival_estimators_preserve_censoring() -> None:
    points = kaplan_meier_v3([2, 3, 3, 5], [True, True, False, True])
    assert points
    assert km_q50_v3(points) in (3, 5)
    assert km_rmst_v3(points, tau=5) > 0


def test_zero_event_99_percent_bound_is_stricter_than_95() -> None:
    bound95 = zero_event_upper_bound_v3(1000, level=0.95)
    bound99 = zero_event_upper_bound_v3(1000, level=0.99)
    assert 0 < bound95 < bound99 < 1


def test_holm_and_pareto_are_deterministic() -> None:
    adjusted = holm_adjust_v3([0.01, 0.03, 0.2])
    assert len(adjusted) == 3
    frontier = pareto_frontier_v3([(1, 5, 5), (2, 2, 2), (5, 1, 5), (3, 3, 3)])
    assert (3, 3, 3) not in frontier
    assert (2, 2, 2) in frontier


def test_r141_confirmatory_record_binds_new_freeze_and_execution_manifest() -> None:
    budget = ResourceBudget(10, 2, 2, 2, 2, 2, 1, 4, 1)
    observed = ResourceBudget(5, 1, 1, 1, 1, 1, 1, 2, 1)
    record = ConfirmatoryRecordR141.create(
        campaign_id="fixture",
        attack_id="HIST-01",
        claim_ids=("C04",),
        construction="fixture-r125",
        cell_id="hist-01-000",
        replicate_id=0,
        declared=budget,
        observed=observed,
        status="no-success",
        metrics={"next_state_match_rate": 0.0},
        censor_reason=None,
        error_class=None,
        code_commit="1" * 40,
        artifact_sha256="2" * 64,
        config_sha256="3" * 64,
        preregistration_sha256="4" * 64,
        dependency_lock_sha256="5" * 64,
        execution_manifest_sha256="6" * 64,
        host_id="fixture-host",
        platform_name="linux",
        architecture="x86_64",
        python_version="3.13",
        started_utc="2026-09-21T00:00:00+00:00",
        completed_utc="2026-09-21T00:00:01+00:00",
    )
    assert record.freeze_id == R141_FREEZE_ID
    assert record.phase == "confirmatory"
    assert len(record.record_sha256) == 64


def test_frozen_scaling_estimators_are_deterministic() -> None:
    assert scaling_slope_v3([4, 6, 8], [4, 8, 16]) == 0.5
    times = [2, 3, 4, 5, 6, 7, 8, 9]
    events = [True, True, True, True, True, False, False, False]
    interval = bootstrap_survival_statistic_v3(
        times,
        events,
        statistic="rmst",
        tau=9,
        label="fixture-rmst",
        replicates=200,
    )
    assert interval.lower <= interval.upper

    cells = (
        ScalingCellV3(4, (2, 3, 4, 5, 6, 7, 8, 9), (True,) * 8),
        ScalingCellV3(6, (4, 5, 6, 7, 8, 9, 10, 11), (True,) * 8),
        ScalingCellV3(8, (8, 9, 10, 11, 12, 13, 14, 15), (True,) * 8),
    )
    slope = bootstrap_scaling_slope_interval_v3(
        cells,
        label="fixture-slope",
        replicates=200,
    )
    assert slope.lower <= slope.upper

    band = simultaneous_mean_band_v3(
        ((4.0, (1.0, 2.0, 3.0)), (6.0, (2.0, 3.0, 4.0))),
        label="fixture-band",
        replicates=200,
    )
    assert len(band) == 2
    assert all(point.lower <= point.estimate <= point.upper for point in band)
