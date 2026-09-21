from __future__ import annotations

from experiments.r15_analysis_shadow import ANALYSIS_SHADOW_NAMESPACE, run_analysis_shadow_v3
from experiments.r15_audit_shadow import AUDIT_SHADOW_NAMESPACE, run_audit_shadow_v3
from scripts.check_r15_analysis_shadow import check_r15_analysis_shadow
from scripts.check_r15_audit_shadow import check_r15_audit_shadow


def test_r15_g_locked_analysis_shadow_is_deterministic() -> None:
    left = check_r15_analysis_shadow()
    right = check_r15_analysis_shadow()
    assert left == right
    assert left["namespace"] == ANALYSIS_SHADOW_NAMESPACE
    assert left["confirmatory"] is False
    assert left["figures"] == 15
    assert left["tables"] == 9


def test_r15_h_audit_shadow_detects_all_fixture_tampering() -> None:
    report = check_r15_audit_shadow()
    assert report["namespace"] == AUDIT_SHADOW_NAMESPACE
    assert report["confirmatory"] is False
    checks = report["checks"]
    assert isinstance(checks, dict)
    assert all(checks.values())
    check_count = report["check_count"]
    assert isinstance(check_count, int) and check_count >= 6


def test_analysis_shadow_hash_is_repeatable() -> None:
    assert (
        run_analysis_shadow_v3()["analysis_sha256"] == run_analysis_shadow_v3()["analysis_sha256"]
    )


def test_audit_shadow_ledger_root_is_repeatable() -> None:
    assert (
        run_audit_shadow_v3()["baseline_ledger_root"]
        == run_audit_shadow_v3()["baseline_ledger_root"]
    )
