from __future__ import annotations

import json

from scripts.check_r15_plan import DATA, SCALE, check_r15_plan


def test_r15_plan_gate_passes_current_predata_plan() -> None:
    result = check_r15_plan()
    assert result["passed"] is True
    assert result["confirmatory_evidence"] is False
    assert result["campaigns"] == 21
    primary_ci = result["primary_ci"]
    rare_event_upper = result["rare_event_upper"]
    power_target = result["power_target"]
    assert isinstance(primary_ci, (int, float)) and primary_ci >= 0.95
    assert isinstance(rare_event_upper, (int, float)) and rare_event_upper >= 0.99
    assert isinstance(power_target, (int, float)) and power_target >= 0.95


def test_r15_scale_plan_is_predata_only() -> None:
    scale = json.loads(SCALE.read_text(encoding="utf-8"))
    assert scale["status"] == "r14.1-freeze-candidate"
    assert scale["confirmatory_evidence"] is False


def test_r15_data_policy_forbids_retained_large_streams() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    policy = data["stream_policy"]
    assert policy["canonical_large_stream_artifact"] is False
    assert policy["deterministic_regeneration"] is True
    assert policy["full_sha256"] is True
    assert data["scratch_limits"]["default_gib"] <= 10
    assert data["scratch_limits"]["preferred_stat_gib"] <= 2


def test_publication_scale_has_dense_collision_grid() -> None:
    scale = json.loads(SCALE.read_text(encoding="utf-8"))
    grid = scale["campaigns"]["RED-02"]["widths_by_k"]
    assert len(grid["1"]) >= 8
    assert len(grid["2"]) >= 7
    assert scale["campaigns"]["RED-02"]["replicates_per_cell"] >= 512


def test_publication_scale_uses_large_rare_event_exposure() -> None:
    scale = json.loads(SCALE.read_text(encoding="utf-8"))
    hist = scale["campaigns"]["HIST-01B"]
    assert hist["batches_per_cell"] * hist["trials_per_batch"] >= 262_144


def test_plan_json_files_contain_no_result_payloads() -> None:
    for path in (SCALE, DATA):
        text = path.read_text(encoding="utf-8")
        forbidden = (
            '"observed"',
            '"p_value"',
            '"result"',
            '"effect_estimate"',
            '"confirmatory_records"',
        )
        assert not any(token in text for token in forbidden), path
