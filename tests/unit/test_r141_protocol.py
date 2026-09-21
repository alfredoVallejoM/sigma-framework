from __future__ import annotations

from experiments.r141_protocol import (
    R141_FREEZE_ID,
    cells_for_attack_r141,
    confirmatory_attack_ids_r141,
)
from experiments.r141_schema import derive_confirmatory_seed_r141
from experiments.r15_estimators import (
    holm_adjust_v3,
    kaplan_meier_v3,
    km_q50_v3,
    km_rmst_v3,
    pareto_frontier_v3,
    zero_event_upper_bound_v3,
)
from scripts.check_r141_protocol import check_r141_protocol
from scripts.prepare_r141_confirmatory import render_r141_configs


def test_r141_protocol_gate_is_predata_and_publication_scale() -> None:
    report = check_r141_protocol()
    assert report["passed"] is True
    assert report["confirmatory_executed"] is False
    assert report["attacks"] == 21
    assert report["run_units"] >= 150_000


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
