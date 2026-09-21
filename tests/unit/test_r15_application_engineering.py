from __future__ import annotations

import json
from pathlib import Path

import experiments.r15_application_engineering as engineering
from experiments.r15_application_engineering import (
    ENGINEERING_CLASSIFICATION,
    ENGINEERING_NAMESPACE,
    EXPECTED_RECORDS,
    EngineeringResult,
    audit_engineering_dataset,
    expected_engineering_runkeys,
    run_engineering_shard,
)


def test_engineering_runkeys_are_exact_and_nonconfirmatory() -> None:
    keys = expected_engineering_runkeys()
    assert len(keys) == EXPECTED_RECORDS == 64
    assert len(keys) == len(set(keys))
    assert {key.attack_id for key in keys} == {"PARAM-04", "PARAM-05", "PARAM-06"}
    assert all(key.freeze_id == ENGINEERING_NAMESPACE for key in keys)
    assert ENGINEERING_NAMESPACE != "sigma-v3-r15"


def test_engineering_shard_writes_exploratory_records(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_execute(
        attack_id: str,
        replicate_id: int,
        factors: dict[str, int],
    ) -> EngineeringResult:
        del factors
        return EngineeringResult(
            attack_id,
            "param-04-engineering",
            replicate_id,
            {"fixture_metric": 1.0},
        )

    monkeypatch.setattr(engineering, "_execute", fake_execute)
    report = run_engineering_shard(
        attack_id="PARAM-04",
        shard_index=0,
        shard_count=8,
        output_root=tmp_path,
        controller_commit="1" * 40,
    )
    assert report["confirmatory"] is False
    assert report["classification"] == ENGINEERING_CLASSIFICATION
    assert report["written_records"] == 2

    records = list((tmp_path / "raw" / "PARAM-04").rglob("*.json"))
    assert len(records) == 2
    for path in records:
        value = json.loads(path.read_text(encoding="utf-8"))
        assert value["confirmatory"] is False
        assert value["counts_toward_r15_pass"] is False
        assert value["counts_toward_core_security_claims"] is False
        assert value["namespace"] == ENGINEERING_NAMESPACE


def test_engineering_audit_accepts_exact_64_record_fixture(tmp_path: Path) -> None:
    shards = tmp_path / "shards"
    for key in expected_engineering_runkeys():
        record = {
            "schema": "sigma-v3-r15-exploratory-engineering-record-v1",
            "namespace": ENGINEERING_NAMESPACE,
            "classification": ENGINEERING_CLASSIFICATION,
            "confirmatory": False,
            "counts_toward_r15_pass": False,
            "counts_toward_core_security_claims": False,
            "run_key": key.stable_id,
            "attack_id": key.attack_id,
            "cell_id": key.cell_id,
            "replicate_id": key.replicate_id,
            "controller_commit": "2" * 40,
            "platform_name": "fixture",
            "architecture": "fixture",
            "python_version": "3.13",
            "runner_note": "fixture",
            "started_utc": "2026-09-21T00:00:00+00:00",
            "completed_utc": "2026-09-21T00:00:01+00:00",
            "metrics": {"fixture": 1},
        }
        engineering.atomic_write_record_v3(shards, key, record)

    output = tmp_path / "merged"
    report = audit_engineering_dataset(
        shards_root=shards,
        output_root=output,
    )
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["counts_toward_r15_pass"] is False
    assert report["expected_records"] == report["observed_records"] == 64
    assert len(report["ledger_root"]) == 64
