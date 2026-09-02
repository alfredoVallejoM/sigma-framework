from experiments.exp02_collisions import run as run_collisions
from experiments.exp02_collisions import summarize as summarize_collisions
from experiments.exp03_persistence import run as run_persistence
from experiments.exp03_persistence import summarize as summarize_persistence
from experiments.exp04_anchor_robustness import run as run_anchors
from experiments.reduced_oracle import ReducedOracle, trajectory


def test_reduced_oracle_is_deterministic_and_domain_separated() -> None:
    oracle = ReducedOracle(b"seed")
    assert oracle.query("a", 12, b"x") == oracle.query("a", 12, b"x")
    assert oracle.query("a", 12, b"x") != oracle.query("b", 12, b"x")
    anchor, states = trajectory(oracle, 7, 8, 16, 2, 3, True)
    assert 0 <= anchor < 2**16
    assert len(states) == 3
    assert all(0 <= state < 2**8 for state in states)


def test_reduced_experiments_emit_individual_observations() -> None:
    common = {"master_seed": "test"}
    collisions = run_collisions(
        {
            **common,
            "widths": [4],
            "state_counts": [1, 2],
            "target_rounds": [1],
            "anchor_multipliers": [1],
            "repetitions": 2,
            "max_candidates": 1000,
        }
    )
    persistence = run_persistence({**common, "widths": [4], "segments": [1, 2], "trials": 20})
    assert len(collisions) == 16
    assert all(not record["censored"] for record in collisions)
    assert len(persistence) == 80
    assert all(record["persisted"] for record in persistence if record["construction"] == "simple")


def test_reduced_anchor_experiment_covers_all_constructions_and_faults() -> None:
    records = run_anchors(
        {
            "branch_counts": [2],
            "faults": ["normal", "constant-first", "correlated-first-two"],
            "master_seed": "test",
            "max_candidates": 10000,
            "repetitions": 1,
            "widths": [4],
        }
    )
    assert len(records) == 18
    assert {
        record["construction"] for record in records if record["attack"] == "generic-birthday"
    } == {
        "psi-compressed",
        "concat-wide",
        "cross-wide",
        "cross-only",
    }
    assert all(
        record["anchor_collision"] for record in records if record["attack"] == "generic-birthday"
    )
    controls = {
        record["construction"]: record["anchor_collision"]
        for record in records
        if record["attack"] == "framing-ambiguity-control"
    }
    assert controls == {"unframed-concat-control": True, "canonical-framing-control": False}


def test_revised_collision_controls_and_survival_are_reported() -> None:
    records = run_collisions(
        {
            "anchor_multipliers": [1],
            "constructions": [
                "stationary-consecutive",
                "indexed-consecutive",
                "anchored-consecutive",
                "anchored-indexed-consecutive",
            ],
            "master_seed": "controls",
            "max_candidates": 1000,
            "repetitions": 4,
            "state_counts": [2],
            "target_rounds": [1],
            "widths": [4, 6],
        }
    )
    assert {record["construction"] for record in records} == {
        "stationary-consecutive",
        "indexed-consecutive",
        "anchored-consecutive",
        "anchored-indexed-consecutive",
    }
    summaries = summarize_collisions(records)
    assert all(group["survival"] for group in summaries)
    assert all(group["slope_bootstrap_replicates"] > 0 for group in summaries)
    assert all(
        set(group["model_rmse"])
        == {"min-anchor-segment", "state-only", "anchor-only", "segment-only"}
        for group in summaries
    )


def test_revised_persistence_separates_anchor_relation_and_transition_controls() -> None:
    records = run_persistence(
        {
            "anchor_relations": ["same", "different"],
            "constructions": ["stationary", "indexed", "anchored", "anchored-indexed"],
            "master_seed": "controls",
            "segments": [2],
            "trials": 32,
            "widths": [4],
        }
    )
    assert len(records) == 256
    always = [
        record
        for record in records
        if record["anchor_relation"] == "same"
        or record["construction"] in {"stationary", "indexed"}
    ]
    assert all(record["persisted"] for record in always)
    groups = summarize_persistence(records)
    assert {group["anchor_relation"] for group in groups} == {"same", "different"}
    assert all("compatible_holm_5pct" in group for group in groups)
    assert all("interpretation" in group for group in groups)
    assert all(group["quality_control_passed"] for group in groups)
    assert all(
        group["exact_95_low"] <= group["observed_probability"] <= group["exact_95_high"]
        for group in groups
    )
    assert all("saturated_deviance" in group for group in groups)


def test_revised_anchor_fault_matrix_keeps_width_claims_separate() -> None:
    records = run_anchors(
        {
            "branch_counts": [3],
            "constructions": [
                "single-branch",
                "concat-wide",
                "cross-wide",
                "cross-only",
                "single-fold",
                "narrow-fold",
                "constant-fold",
                "deep-vector",
            ],
            "faults": [
                "normal",
                "constant-first",
                "collidable-first",
                "truncated-first",
                "correlated-first-two",
                "permuted",
                "omitted-last",
            ],
            "master_seed": "fault-matrix",
            "max_candidates": 512,
            "repetitions": 1,
            "widths": [4],
        }
    )
    generic = [record for record in records if record["attack"] == "generic-birthday"]
    assert {record["fault"] for record in generic} == {
        "normal",
        "constant-first",
        "collidable-first",
        "truncated-first",
        "correlated-first-two",
        "permuted",
        "omitted-last",
    }
    constant = [record for record in generic if record["construction"] == "constant-fold"]
    assert all(record["conservative_bits"] == 0 for record in constant)
    vector = next(record for record in generic if record["construction"] == "deep-vector")
    assert vector["physical_bits"] > vector["conservative_bits"]
