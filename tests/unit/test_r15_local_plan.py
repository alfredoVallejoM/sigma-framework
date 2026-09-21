from __future__ import annotations

import json
from pathlib import Path

from scripts.r15_local_plan import tasks


ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "experiments" / "r15-local-campaigns.json"


def test_local_r15_campaign_matrix_is_frozen() -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    expected = plan["expected_run_units"]
    assert (
        expected["wave1"]
        + expected["wave2"]
        + expected["wave3a"]
        + expected["amendment"]
        + expected["stat"]
        == expected["mandatory_total"]
        == 145_088
    )
    assert plan["total_shard_jobs"] == 1_760
    assert plan["campaigns"]["wave3a"]["phases"] == [
        ["red03"],
        ["tmto01", "tmto02"],
        ["red02"],
        ["red05"],
    ]
    assert plan["campaigns"]["amendment"]["phases"] == [["red04"], ["param02"]]


def test_local_r15_task_queue_has_exact_cardinality() -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    queue = tasks(plan)
    assert len(queue) == 1_760
    by_campaign: dict[str, int] = {}
    for item in queue:
        by_campaign[item["campaign"]] = by_campaign.get(item["campaign"], 0) + 1
    assert by_campaign == {
        "wave1": 24,
        "wave2": 576,
        "wave3a": 240,
        "amendment": 384,
        "stat": 512,
        "engineering": 24,
    }
