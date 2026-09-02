from experiments.exp02_collisions import run as run_collisions
from experiments.exp03_persistence import run as run_persistence
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
