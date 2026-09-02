import math
import statistics
import time
from typing import Any

from sigma.applications.pow import (
    PowParameters,
    PowPredicate,
    PowProof,
    solve,
    solve_parallel,
    verify,
)
from sigma.outputs import SigmaDigestV2
from sigma.policy import PolicyViolation, ResourcePolicy

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
    target_rounds = [
        int(value) for value in config.get("target_rounds", [config.get("target_round", 1)])
    ]
    state_counts = [int(value) for value in config.get("state_counts", [2])]
    challenge_modes = [str(value) for value in config.get("challenge_modes", ["unique"])]
    max_attempts = int(config.get("max_attempts", 100_000))
    for predicate, per_state_bits in predicates:
        for target_round in target_rounds:
            for state_count in state_counts:
                if predicate is PowPredicate.DUAL_STATE and state_count < 2:
                    continue
                for challenge_mode in challenge_modes:
                    if challenge_mode not in {"unique", "reused"}:
                        raise ValueError(f"unsupported challenge mode: {challenge_mode}")
                    rng = derived_random(
                        str(config["master_seed"]),
                        f"EXP-11/{predicate.name}/{target_round}/{state_count}/{challenge_mode}",
                    )
                    shared_challenge = rng.randbytes(16)
                    for trial in range(trials):
                        challenge = (
                            shared_challenge if challenge_mode == "reused" else rng.randbytes(16)
                        )
                        parameters = PowParameters(
                            challenge=challenge,
                            target_round=target_round,
                            state_count=state_count,
                            predicate=predicate,
                            difficulty_bits=per_state_bits,
                        )
                        payload = rng.randbytes(24)
                        started = time.perf_counter_ns()
                        try:
                            proof, attempts = solve(
                                payload,
                                parameters,
                                start_nonce=rng.randrange(0, 1 << 32),
                                max_attempts=max_attempts,
                            )
                        except RuntimeError:
                            proof = None
                            attempts = max_attempts
                        mining_ns = time.perf_counter_ns() - started
                        verified = None
                        verification_ns = None
                        replay_rejected = None
                        challenge_substitution_rejected = None
                        difficulty_downgrade_rejected = None
                        tampered_digest_rejected = None
                        if proof is not None:
                            started = time.perf_counter_ns()
                            verified = verify(payload, proof, parameters)
                            verification_ns = time.perf_counter_ns() - started
                            replay_rejected = not verify(payload + b"replay", proof, parameters)
                            altered_challenge = bytes((challenge[0] ^ 1,)) + challenge[1:]
                            substituted = PowParameters(
                                altered_challenge,
                                target_round,
                                state_count,
                                predicate,
                                per_state_bits,
                            )
                            challenge_substitution_rejected = not verify(
                                payload, proof, substituted
                            )
                            downgraded = PowParameters(
                                challenge,
                                target_round,
                                state_count,
                                predicate,
                                max(0, per_state_bits - 1),
                            )
                            difficulty_downgrade_rejected = not verify(payload, proof, downgraded)
                            states = list(proof.digest.states)
                            states[0] = bytes((states[0][0] ^ 1,)) + states[0][1:]
                            tampered = PowProof(
                                proof.nonce, SigmaDigestV2(proof.digest.context, tuple(states))
                            )
                            tampered_digest_rejected = not verify(payload, tampered, parameters)
                        restrictive = ResourcePolicy(
                            name="exp11-attempt-cap",
                            max_pow_difficulty_bits=max(512, per_state_bits),
                            max_pow_attempts=max(0, max_attempts - 1),
                        )
                        try:
                            solve(
                                payload,
                                parameters,
                                max_attempts=max_attempts,
                                policy=restrictive,
                            )
                        except PolicyViolation:
                            resource_exhaustion_rejected = True
                        else:
                            resource_exhaustion_rejected = False
                        records.append(
                            {
                                "attempts": attempts,
                                "censored": proof is None,
                                "challenge_mode": challenge_mode,
                                "challenge_substitution_rejected": challenge_substitution_rejected,
                                "difficulty_downgrade_rejected": difficulty_downgrade_rejected,
                                "expected_probability": 2.0**-total_bits,
                                "mining_ns": mining_ns,
                                "nonce": proof.nonce if proof is not None else None,
                                "predicate": predicate.name.lower(),
                                "replay_rejected": replay_rejected,
                                "resource_exhaustion_rejected": resource_exhaustion_rejected,
                                "state_count": state_count,
                                "tampered_digest_rejected": tampered_digest_rejected,
                                "target_round": parameters.target_round,
                                "trial": trial,
                                "verification_match": verified,
                                "verification_ns": verification_ns,
                                "workers": 1,
                            }
                        )
    worker_counts = [int(value) for value in config.get("nonce_worker_counts", [])]
    for trial in range(int(config.get("parallel_trials", 0))):
        rng = derived_random(str(config["master_seed"]), f"EXP-11/parallel/{trial}")
        parameters = PowParameters(
            challenge=rng.randbytes(16),
            target_round=int(config.get("parallel_target_round", 1)),
            state_count=2,
            predicate=PowPredicate.SINGLE_STATE,
            difficulty_bits=total_bits,
        )
        payload = rng.randbytes(24)
        start_nonce = rng.randrange(0, 1 << 32)
        for workers in worker_counts:
            started = time.perf_counter_ns()
            try:
                proof, attempts = solve_parallel(
                    payload,
                    parameters,
                    workers=workers,
                    start_nonce=start_nonce,
                    max_attempts=max_attempts,
                )
            except RuntimeError:
                proof = None
                attempts = max_attempts
            mining_ns = time.perf_counter_ns() - started
            verified = proof is not None and verify(payload, proof, parameters)
            records.append(
                {
                    "attempts": attempts,
                    "censored": proof is None,
                    "challenge_mode": "parallel-scaling",
                    "challenge_substitution_rejected": None,
                    "difficulty_downgrade_rejected": None,
                    "expected_probability": 2.0**-total_bits,
                    "mining_ns": mining_ns,
                    "nonce": proof.nonce if proof is not None else None,
                    "predicate": "single_state_parallel",
                    "replay_rejected": None,
                    "resource_exhaustion_rejected": None,
                    "state_count": 2,
                    "tampered_digest_rejected": None,
                    "target_round": parameters.target_round,
                    "trial": trial,
                    "verification_match": verified,
                    "verification_ns": None,
                    "workers": workers,
                }
            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int, int, str, int], list[dict[str, Any]]] = {}
    for record in records:
        key = (
            str(record["predicate"]),
            int(record["target_round"]),
            int(record.get("state_count", 2)),
            str(record.get("challenge_mode", "unique")),
            int(record.get("workers", 1)),
        )
        groups.setdefault(key, []).append(record)
    summaries: list[dict[str, Any]] = []
    for (predicate, target_round, state_count, challenge_mode, workers), group in sorted(
        groups.items()
    ):
        probability = float(group[0]["expected_probability"])
        attempts = [int(row["attempts"]) for row in group]
        successes = sum(not bool(row.get("censored", False)) for row in group)
        total_attempts = sum(attempts)
        observed_probability = successes / total_attempts
        probability_se = math.sqrt(probability * (1 - probability) / total_attempts)
        expected = 1.0 / probability
        standard_error = math.sqrt(1.0 - probability) / probability / math.sqrt(len(group))
        mean = statistics.mean(attempts)
        attack_fields = (
            "challenge_substitution_rejected",
            "difficulty_downgrade_rejected",
            "replay_rejected",
            "resource_exhaustion_rejected",
            "tampered_digest_rejected",
        )
        quality_control_passed = all(
            row[field] is not False for row in group for field in attack_fields
        ) and all(row["verification_match"] is not False for row in group)
        summaries.append(
            {
                "challenge_mode": challenge_mode,
                "censored_trials": len(group) - successes,
                "compatible_geometric_4se": (
                    abs(mean - expected) <= 4 * standard_error
                    if successes == len(group)
                    else abs(observed_probability - probability) <= 4 * probability_se
                ),
                "expected_mean_attempts": expected,
                "mean_attempts": mean,
                "median_attempts": statistics.median(
                    int(row["attempts"]) for row in group if not row.get("censored", False)
                )
                if successes
                else None,
                "median_mining_ns": statistics.median(int(row["mining_ns"]) for row in group),
                "median_verification_ns": statistics.median(
                    int(row["verification_ns"])
                    for row in group
                    if row["verification_ns"] is not None
                )
                if any(row["verification_ns"] is not None for row in group)
                else None,
                "observed_acceptance_probability": observed_probability,
                "predicate": predicate,
                "quality_control_passed": quality_control_passed,
                "state_count": state_count,
                "target_round": target_round,
                "trials": len(group),
                "workers": workers,
            }
        )
    baselines = {
        (
            item["predicate"],
            item["target_round"],
            item["state_count"],
            item["challenge_mode"],
        ): item
        for item in summaries
        if item["workers"] == 1
    }
    for item in summaries:
        baseline = baselines.get(
            (
                item["predicate"],
                item["target_round"],
                item["state_count"],
                item["challenge_mode"],
            )
        )
        speedup = (
            float(baseline["median_mining_ns"]) / float(item["median_mining_ns"])
            if baseline is not None
            else None
        )
        item["mining_speedup_vs_worker1"] = speedup
        item["mining_parallel_efficiency"] = (
            speedup / int(item["workers"]) if speedup is not None else None
        )
    return summaries
