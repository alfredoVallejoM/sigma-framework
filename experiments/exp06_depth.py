import hashlib
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

from sigma.presets import lightweight_v2, paranoid_deep_v2
from sigma.v2 import _anchor_engine, _round_engine

from .common import derived_random


def _evaluate(payload: bytes, context) -> bytes:
    anchor_engine = _anchor_engine(context)
    anchor_engine.update(payload)
    anchor = anchor_engine.finalize()
    digest, _ = _round_engine(context).evaluate(anchor)
    return digest.to_bytes()


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    repetitions = int(config.get("repetitions", 5))
    message_bytes = int(config.get("message_bytes", 64))
    master_seed = str(config["master_seed"])
    for profile in config["profiles"]:
        if profile == "wide-once":
            constructor = lightweight_v2
        elif profile == "deep":
            constructor = paranoid_deep_v2
        else:
            raise ValueError(f"unsupported round profile: {profile}")
        branch_count = 2 if profile == "wide-once" else 4
        per_level_queries = 1 if profile == "wide-once" else branch_count + 1
        for target_value in config["target_rounds"]:
            target = int(target_value)
            for state_count_value in config["state_counts"]:
                state_count = int(state_count_value)
                context = constructor(target_round=target, state_count=state_count)
                levels = target + state_count - 1
                for candidate_value in config["candidate_counts"]:
                    candidates = int(candidate_value)
                    for worker_value in config["candidate_workers"]:
                        workers = int(worker_value)
                        if workers > candidates:
                            continue
                        for repetition in range(repetitions):
                            label = (
                                f"EXP-06/{profile}/{target}/{state_count}/"
                                f"{candidates}/{workers}/{repetition}"
                            )
                            rng = derived_random(master_seed, label)
                            payloads = [rng.randbytes(message_bytes) for _ in range(candidates)]
                            started = time.perf_counter_ns()
                            if workers == 1:
                                outputs = [_evaluate(payload, context) for payload in payloads]
                            else:
                                with ThreadPoolExecutor(max_workers=workers) as executor:
                                    outputs = list(
                                        executor.map(partial(_evaluate, context=context), payloads)
                                    )
                            elapsed = time.perf_counter_ns() - started
                            records.append(
                                {
                                    "candidate_workers": workers,
                                    "candidates": candidates,
                                    "critical_levels": levels,
                                    "digests_sha256": hashlib.sha256(b"".join(outputs)).hexdigest(),
                                    "elapsed_ns": elapsed,
                                    "implementation_round_span_queries": levels * per_level_queries,
                                    "model_parallel_round_span_queries": levels
                                    if profile == "wide-once"
                                    else levels * 2,
                                    "profile": profile,
                                    "repetition": repetition,
                                    "round_queries": candidates * levels * per_level_queries,
                                    "state_count": state_count,
                                    "target_round": target,
                                    "throughput_candidates_s": candidates * 1_000_000_000 / elapsed,
                                }
                            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "profile",
        "target_round",
        "state_count",
        "candidates",
        "candidate_workers",
    )
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        elapsed = [int(item["elapsed_ns"]) for item in group]
        throughput = [float(item["throughput_candidates_s"]) for item in group]
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                "critical_levels": group[0]["critical_levels"],
                "median_elapsed_ns": int(statistics.median(elapsed)),
                "median_throughput_candidates_s": statistics.median(throughput),
                "observations": len(group),
                "round_queries": group[0]["round_queries"],
            }
        )
    return summaries
