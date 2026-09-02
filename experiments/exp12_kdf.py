import hmac
import statistics
import time
from typing import Any

from sigma.applications.kdf_argon2id import (
    KDF_FINAL_DOMAIN,
    Argon2idParameters,
    SigmaKdfResult,
    derive_argon2id,
    derive_argon2id_sigma,
)
from sigma.policy import ResourcePolicy
from sigma.presets import get_preset
from sigma.v2 import hash_bytes

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
            modes = [str(value) for value in config.get("modes", ["argon2id", "argon2id+wide"])]
            presets = {
                "argon2id+wide": "lightweight-v2-2",
                "argon2id+cross-wide": "paranoid-wide-v2-2",
                "argon2id+deep": "paranoid-deep-v2-2",
                "argon2id+deep-vector": "paranoid-deep-vector-v2-2",
            }
            unknown = set(modes) - {"argon2id", *presets}
            if unknown:
                raise ValueError(f"unsupported EXP-12 modes: {sorted(unknown)}")
            targets = {"argon2id": derive_argon2id(candidates[-1], salt, parameters, policy=policy)}
            targets.update(
                {
                    mode: derive_argon2id_sigma(
                        candidates[-1], salt, parameters, policy=policy, preset=presets[mode]
                    ).final_key
                    for mode in modes
                    if mode != "argon2id"
                }
            )
            for repetition in range(int(config.get("repetitions", 3))):
                for mode in modes:
                    started = time.perf_counter_ns()
                    found = -1
                    argon2_ns = 0
                    postprocess_ns = 0
                    for index, password in enumerate(candidates):
                        argon_started = time.perf_counter_ns()
                        base_key = derive_argon2id(password, salt, parameters, policy=policy)
                        argon2_ns += time.perf_counter_ns() - argon_started
                        if mode == "argon2id":
                            candidate = base_key
                        else:
                            post_started = time.perf_counter_ns()
                            context = get_preset(
                                presets[mode],
                                salt=salt,
                                application_context=KDF_FINAL_DOMAIN + parameters.to_bytes(),
                            )
                            digest = hash_bytes(base_key, context, policy=policy)
                            candidate = SigmaKdfResult.bind(parameters, salt, digest).final_key
                            postprocess_ns += time.perf_counter_ns() - post_started
                        if hmac.compare_digest(candidate, targets[mode]):
                            found = index
                            break
                    elapsed_ns = time.perf_counter_ns() - started
                    records.append(
                        {
                            "candidates": len(candidates),
                            "elapsed_ns": elapsed_ns,
                            "argon2_component_ns": argon2_ns,
                            "found_match": found == len(candidates) - 1,
                            "guesses_per_second": len(candidates) * 1e9 / elapsed_ns,
                            "memory_kib": parameters.memory_kib,
                            "mode": mode,
                            "parallelism": parameters.parallelism,
                            "postprocess_component_ns": postprocess_ns,
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
        for mode, rows in sorted(modes.items()):
            if mode == "argon2id":
                continue
            composed = statistics.median(float(row["guesses_per_second"]) for row in rows)
            summaries.append(
                {
                    "all_matches_found": all(
                        bool(row["found_match"])
                        for selected in (modes["argon2id"], rows)
                        for row in selected
                    ),
                    "argon2id_guesses_per_second": base,
                    "composed_guesses_per_second": composed,
                    "memory_kib": memory_kib,
                    "mode": mode,
                    "median_argon2_component_ns": statistics.median(
                        int(row["argon2_component_ns"]) for row in rows
                    ),
                    "median_postprocess_component_ns": statistics.median(
                        int(row["postprocess_component_ns"]) for row in rows
                    ),
                    "overhead_ratio": base / composed,
                    "same_argon2_budget": True,
                    "time_cost": time_cost,
                }
            )
    return summaries
