import os

import pytest

from experiments.exp09_performance import run, summarize


def test_performance_experiment_separates_operations_and_reports_intervals() -> None:
    records = run(
        {
            "constructions": ["sha256", "sigma-wide"],
            "master_seed": "test",
            "operations": ["full-hash", "anchor", "rounds", "serialization", "verification"],
            "processes": 1,
            "repetitions": 2,
            "sizes": [0, 8],
            "warmups": 1,
        }
    )
    assert {record["operation"] for record in records} == {
        "full-hash",
        "anchor",
        "rounds",
        "serialization",
        "verification",
    }
    groups = summarize(records)
    assert all(group["bootstrap_median_low_ns"] <= group["median_ns"] for group in groups)
    assert all(group["median_ns"] <= group["bootstrap_median_high_ns"] for group in groups)
    assert all(record["repetition"] in {0, 1} for record in records)
    assert all(record["operations_per_s"] > 0 for record in records)
    assert all(
        record["throughput_bytes_s"] is None
        for record in records
        if record["operation"] in {"rounds", "serialization"}
    )


def test_revised_performance_covers_deep_vector_and_local_verification() -> None:
    records = run(
        {
            "constructions": ["sigma-deep-vector"],
            "master_seed": "revised",
            "operations": ["full-hash", "rounds", "local-verification"],
            "processes": 1,
            "repetitions": 1,
            "sizes": [8],
            "suite_family": "v2-2",
            "warmups": 0,
        }
    )
    assert {record["operation"] for record in records} == {
        "full-hash",
        "local-verification",
        "rounds",
    }
    assert all(record["construction"] == "sigma-deep-vector" for record in records)


def test_file_cold_records_the_required_cache_control() -> None:
    if not hasattr(os, "posix_fadvise") or not hasattr(os, "POSIX_FADV_DONTNEED"):
        pytest.skip("POSIX_FADV_DONTNEED is unavailable")
    records = run(
        {
            "constructions": ["sha512"],
            "master_seed": "cold-file",
            "operations": ["file-cold"],
            "processes": 1,
            "repetitions": 1,
            "sizes": [8],
            "warmups": 0,
        }
    )
    assert records[0]["cache_state"] == "posix-fadvise-dontneed-before-each-read"
