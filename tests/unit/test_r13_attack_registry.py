from __future__ import annotations

import pytest

from experiments.r13_attack_registry import (
    ATTACKS,
    ATTACK_REGISTRY,
    RESOURCE_FIELDS,
    AttackSpec,
    get_attack,
)


def test_r13_attack_ids_are_unique_and_registry_is_total() -> None:
    assert len(ATTACK_REGISTRY) == len(ATTACKS)
    assert set(ATTACK_REGISTRY) == {attack.attack_id for attack in ATTACKS}


def test_every_attack_publishes_complete_resource_vector() -> None:
    for attack in ATTACKS:
        assert set(attack.resources) == set(RESOURCE_FIELDS)
        assert attack.success_event
        assert attack.metrics
        assert attack.baselines
        assert attack.claims


def test_statistical_batteries_are_not_theorem_evidence() -> None:
    for attack in ATTACKS:
        if attack.family == "STAT":
            assert attack.evidence_class != "E1"


def test_core_paper_attacks_are_registered() -> None:
    required = {
        "HIST-01",
        "HIST-02",
        "HIST-05",
        "RED-04",
        "TMTO-01",
        "PARAM-03",
        "PARAM-04",
        "PARAM-05",
        "BRANCH-05",
        "FAULT-01",
        "APP-SIG-01",
        "STAT-01",
    }
    assert required <= set(ATTACK_REGISTRY)


def test_attack_lookup_rejects_unknown_id() -> None:
    assert get_attack("HIST-01").family == "HIST"
    with pytest.raises(ValueError, match="unknown"):
        get_attack("NOT-AN-ATTACK")


def test_attack_spec_rejects_incomplete_or_misclassified_entries() -> None:
    with pytest.raises(ValueError, match="attack_id"):
        AttackSpec("", "X", "pilot", ("C01",), "E3", "success", ("m",), ("b",))
    with pytest.raises(ValueError, match="full R13 resource"):
        AttackSpec(
            "X-01",
            "X",
            "pilot",
            ("C01",),
            "E3",
            "success",
            ("m",),
            ("b",),
            resources=("W",),
        )
    with pytest.raises(ValueError, match="statistical"):
        AttackSpec(
            "STAT-99",
            "STAT",
            "confirmatory",
            ("C01",),
            "E1",
            "success",
            ("p",),
            ("control",),
        )
