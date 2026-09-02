import hmac
import statistics
import time
from typing import Any

from sigma.applications.kdf_argon2id import (
    Argon2idParameters,
    derive_argon2id,
    derive_argon2id_sigma,
)
from sigma.policy import ResourcePolicy

from .common import derived_random


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    rng = derived_random(str(config["master_seed"]), "EXP-12/password-corpus")
    candidates = [rng.randbytes(12) for _ in range(int(config.get("candidates", 16)))]
    salt = rng.randbytes(16)
    policy = ResourcePolicy(
        name="exp12-explicit-test-profile",
        min_argon2_memory_kib=min(int(value) for value in config["memory_kib"]),
        max_argon2_memory_kib=max(int(value) for value in config["memory_kib"]),
        min_argon2_time_cost=min(int(value) for value in config["time_cost"]),
        max_argon2_time_cost=max(int(value) for value in config["time_cost"]),
    )
    for memory_kib in config["memory_kib"]:
        for time_cost in config["time_cost"]:
            parameters = Argon2idParameters(
                int(memory_kib), int(time_cost), int(config.get("parallelism", 1))
            )
            targets = {
                "argon2id": derive_argon2id(candidates[-1], salt, parameters, policy=policy),
                "argon2id+sigma": derive_argon2id_sigma(
                    candidates[-1], salt, parameters, policy=policy
                ).final_key,
            }
            for repetition in range(int(config.get("repetitions", 3))):
                for mode in ("argon2id", "argon2id+sigma"):
                    started = time.perf_counter_ns()
                    found = -1
                    for index, password in enumerate(candidates):
                        if mode == "argon2id":
                            candidate = derive_argon2id(
                                password, salt, parameters, policy=policy
                            )
                        else:
                            candidate = derive_argon2id_sigma(
                                password, salt, parameters, policy=policy
                            ).final_key
                        if hmac.compare_digest(candidate, targets[mode]):
                            found = index
                            break
                    elapsed_ns = time.perf_counter_ns() - started
                    records.append(
                        {
                            "candidates": len(candidates),
                            "elapsed_ns": elapsed_ns,
                            "found_match": found == len(candidates) - 1,
                            "guesses_per_second": len(candidates) * 1e9 / elapsed_ns,
                            "memory_kib": parameters.memory_kib,
                            "mode": mode,
                            "parallelism": parameters.parallelism,
                            "repetition": repetition,
                            "time_cost": parameters.time_cost,
                        }
                    )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, int], dict[str, list[dict[str, Any]]]] = {}
    for record in records:
        key = (int(record["memory_kib"]), int(record["time_cost"]))
        grouped.setdefault(key, {}).setdefault(str(record["mode"]), []).append(record)
    summaries = []
    for (memory_kib, time_cost), modes in sorted(grouped.items()):
        base = statistics.median(float(row["guesses_per_second"]) for row in modes["argon2id"])
        composed = statistics.median(
            float(row["guesses_per_second"]) for row in modes["argon2id+sigma"]
        )
        summaries.append(
            {
                "all_matches_found": all(
                    bool(row["found_match"]) for rows in modes.values() for row in rows
                ),
                "argon2id_guesses_per_second": base,
                "composed_guesses_per_second": composed,
                "memory_kib": memory_kib,
                "overhead_ratio": base / composed,
                "time_cost": time_cost,
            }
        )
    return summaries
