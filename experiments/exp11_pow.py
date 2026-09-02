import math
import statistics
import time
from typing import Any

from sigma.applications.pow import PowParameters, PowPredicate, solve, verify

from .common import derived_random


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    trials = int(config.get("trials", 128))
    total_bits = int(config.get("total_difficulty_bits", 4))
    if total_bits % 2:
        raise ValueError("total_difficulty_bits must be even for the dual comparison")
    predicates = (
        (PowPredicate.SINGLE_STATE, total_bits),
        (PowPredicate.DUAL_STATE, total_bits // 2),
        (PowPredicate.CONCATENATED, total_bits),
    )
    for predicate, per_state_bits in predicates:
        rng = derived_random(str(config["master_seed"]), f"EXP-11/{predicate.name}")
        for trial in range(trials):
            parameters = PowParameters(
                challenge=rng.randbytes(16),
                target_round=int(config.get("target_round", 1)),
                state_count=2,
                predicate=predicate,
                difficulty_bits=per_state_bits,
            )
            payload = rng.randbytes(24)
            started = time.perf_counter_ns()
            proof, attempts = solve(
                payload,
                parameters,
                start_nonce=rng.randrange(0, 1 << 32),
                max_attempts=int(config.get("max_attempts", 100_000)),
            )
            mining_ns = time.perf_counter_ns() - started
            started = time.perf_counter_ns()
            verified = verify(payload, proof, parameters)
            verification_ns = time.perf_counter_ns() - started
            records.append(
                {
                    "attempts": attempts,
                    "expected_probability": 2.0**-total_bits,
                    "mining_ns": mining_ns,
                    "nonce": proof.nonce,
                    "predicate": predicate.name.lower(),
                    "target_round": parameters.target_round,
                    "trial": trial,
                    "verification_match": verified,
                    "verification_ns": verification_ns,
                }
            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        groups.setdefault(str(record["predicate"]), []).append(record)
    summaries = []
    for predicate, group in sorted(groups.items()):
        probability = float(group[0]["expected_probability"])
        attempts = [int(row["attempts"]) for row in group]
        expected = 1.0 / probability
        standard_error = math.sqrt(1.0 - probability) / probability / math.sqrt(len(group))
        mean = statistics.mean(attempts)
        summaries.append(
            {
                "compatible_geometric_4se": abs(mean - expected) <= 4 * standard_error,
                "expected_mean_attempts": expected,
                "mean_attempts": mean,
                "median_attempts": statistics.median(attempts),
                "median_mining_ns": statistics.median(int(row["mining_ns"]) for row in group),
                "median_verification_ns": statistics.median(
                    int(row["verification_ns"]) for row in group
                ),
                "predicate": predicate,
                "trials": len(group),
            }
        )
    return summaries
