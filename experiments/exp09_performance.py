import hashlib
import os
import random
import statistics
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
)
from sigma.v2 import (
    _anchor_engine,
    _round_engine,
    hash_bytes,
    hash_file,
    verify_adjacent_only,
    verify_full,
)

from .common import derived_random

try:
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]


def _context_switches() -> tuple[int | None, int | None]:
    if resource is None:
        return None, None
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return int(usage.ru_nvcsw), int(usage.ru_nivcsw)


def _branches(message: bytes) -> bytes:
    return b"".join(
        (
            hashlib.sha512(message).digest(),
            hashlib.sha3_512(message).digest(),
            hashlib.blake2b(message, digest_size=64).digest(),
            hashlib.shake_256(message).digest(64),
        )
    )


def _preset(construction: str):
    if construction == "sigma-wide":
        return lightweight_v2_2()
    if construction == "sigma-cross":
        return paranoid_wide_v2_2()
    if construction == "sigma-deep":
        return paranoid_deep_v2_2()
    if construction == "sigma-deep-vector":
        return paranoid_deep_vector_v2_2()
    raise ValueError(f"operation requires a Sigma construction: {construction}")


def _memory_full(construction: str, message: bytes) -> bytes:
    if construction == "sha256":
        return hashlib.sha256(message).digest()
    if construction == "sha512":
        return hashlib.sha512(message).digest()
    if construction == "sha3-256":
        return hashlib.sha3_256(message).digest()
    if construction == "sha3-512":
        return hashlib.sha3_512(message).digest()
    if construction == "blake2b-512":
        return hashlib.blake2b(message, digest_size=64).digest()
    if construction == "concat-branches":
        return _branches(message)
    return hash_bytes(message, _preset(construction)).to_bytes()


def _file_full(construction: str, path: Path) -> bytes:
    if construction.startswith("sigma-"):
        return hash_file(path, _preset(construction)).to_bytes()
    with path.open("rb") as source:
        message = source.read()
    return _memory_full(construction, message)


def _prepared_operation(construction: str, operation: str, message: bytes):
    if operation == "full-hash":
        return lambda: _memory_full(construction, message), "memory"
    if operation in {"file-hash", "file-hot", "file-cold"}:
        temporary = tempfile.TemporaryDirectory(prefix="sigma-exp09-")
        path = Path(temporary.name) / "message.bin"
        path.write_bytes(message)

        def file_call() -> bytes:
            if operation == "file-cold":
                if not hasattr(os, "posix_fadvise") or not hasattr(os, "POSIX_FADV_DONTNEED"):
                    raise RuntimeError("file-cold requires POSIX_FADV_DONTNEED")
                with path.open("rb") as source:
                    os.posix_fadvise(source.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            result = _file_full(construction, path)
            if not path.exists():
                raise RuntimeError("benchmark input unexpectedly disappeared")
            return result

        file_call._temporary = temporary  # type: ignore[attr-defined]
        cache_state = {
            "file-cold": "posix-fadvise-dontneed-before-each-read",
            "file-hash": "uncontrolled-page-cache",
            "file-hot": "warm-page-cache-after-warmup",
        }[operation]
        return file_call, cache_state
    context = _preset(construction)
    anchor_engine = _anchor_engine(context)
    anchor_engine.update(message)
    anchor = anchor_engine.finalize()
    digest = _round_engine(context).evaluate_digest(anchor)
    if operation == "anchor":
        return (
            lambda: _anchor_engine(context).compute(context, (message,)).to_bytes(),
            "memory",
        )
    if operation == "rounds":
        return lambda: _round_engine(context).evaluate_digest(anchor).to_bytes(), "memory"
    if operation == "serialization":
        return digest.to_bytes, "memory"
    if operation == "verification":
        return lambda: bytes((verify_full(message, digest),)), "memory"
    if operation == "local-verification":
        if len(digest.states) < 2:
            raise ValueError("local verification requires at least two published states")
        return (
            lambda: bytes(
                (
                    verify_adjacent_only(
                        context,
                        anchor,
                        context.target_round,
                        digest.states[0],
                        digest.states[1],
                    ),
                )
            ),
            "memory",
        )
    raise ValueError(f"unsupported operation: {operation}")


def _measure(task: tuple[str, str, int, int, int, int]) -> dict[str, Any]:
    construction, operation, size, seed, warmups, repetition = task
    message = random.Random(seed).randbytes(size)
    function, cache_state = _prepared_operation(construction, operation, message)
    for _ in range(warmups):
        function()
    voluntary_before, involuntary_before = _context_switches()
    cpu_started = time.process_time_ns()
    started = time.perf_counter_ns()
    output = function()
    elapsed = time.perf_counter_ns() - started
    cpu_elapsed = time.process_time_ns() - cpu_started
    voluntary_after, involuntary_after = _context_switches()
    byte_operations = {
        "anchor",
        "file-hash",
        "file-hot",
        "file-cold",
        "full-hash",
        "verification",
    }
    return {
        "bytes": size,
        "cache_state": cache_state,
        "construction": construction,
        "cycles_per_byte": None,
        "cpu_elapsed_ns": cpu_elapsed,
        "cpu_percent_single_core": cpu_elapsed / elapsed * 100,
        "elapsed_ns": elapsed,
        "involuntary_context_switches": (
            involuntary_after - involuntary_before
            if involuntary_after is not None and involuntary_before is not None
            else None
        ),
        "operation": operation,
        "operations_per_s": 1_000_000_000 / elapsed,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "pid": os.getpid(),
        "repetition": repetition,
        "throughput_bytes_s": (
            size * 1_000_000_000 / elapsed if size and operation in byte_operations else None
        ),
        "voluntary_context_switches": (
            voluntary_after - voluntary_before
            if voluntary_after is not None and voluntary_before is not None
            else None
        ),
        "warmups": warmups,
    }


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    tasks = []
    repetitions = int(config.get("repetitions", 5))
    warmups = int(config.get("warmups", 2))
    master_seed = str(config["master_seed"])
    sigma = {"sigma-wide", "sigma-cross", "sigma-deep", "sigma-deep-vector"}
    for construction in config["constructions"]:
        for operation in config["operations"]:
            if (
                operation
                not in (
                    "full-hash",
                    "file-hash",
                    "file-hot",
                    "file-cold",
                )
                and construction not in sigma
            ):
                continue
            for size_value in config["sizes"]:
                size = int(size_value)
                for repetition in range(repetitions):
                    label = f"EXP-09/{construction}/{operation}/{size}/{repetition}"
                    seed = derived_random(master_seed, label).getrandbits(128)
                    tasks.append(
                        (
                            str(construction),
                            str(operation),
                            size,
                            seed,
                            warmups,
                            repetition,
                        )
                    )
    order_rng = derived_random(master_seed, "EXP-09/task-order")
    order_rng.shuffle(tasks)
    processes = int(config.get("processes", 1))
    if processes == 1:
        records = [_measure(task) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=processes) as executor:
            records = list(executor.map(_measure, tasks, chunksize=1))
    for order, record in enumerate(records):
        record["randomized_order"] = order
    return records


def _percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("construction", "operation", "bytes", "cache_state")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        values = [float(item["elapsed_ns"]) for item in group]
        rng = derived_random("sigma-exp09-bootstrap-v1", repr(key))
        bootstraps = [statistics.median(rng.choice(values) for _ in values) for _ in range(1000)]
        median = statistics.median(values)
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                "bootstrap_median_high_ns": _percentile(bootstraps, 0.975),
                "bootstrap_median_low_ns": _percentile(bootstraps, 0.025),
                "mad_ns": statistics.median(abs(value - median) for value in values),
                "median_ns": median,
                "median_cpu_percent_single_core": statistics.median(
                    float(item["cpu_percent_single_core"]) for item in group
                ),
                "median_involuntary_context_switches": statistics.median(
                    int(item["involuntary_context_switches"])
                    for item in group
                    if item["involuntary_context_switches"] is not None
                )
                if any(item["involuntary_context_switches"] is not None for item in group)
                else None,
                "median_operations_per_s": statistics.median(
                    float(item["operations_per_s"]) for item in group
                ),
                "median_throughput_bytes_s": (
                    statistics.median(
                        float(item["throughput_bytes_s"])
                        for item in group
                        if item["throughput_bytes_s"] is not None
                    )
                    if any(item["throughput_bytes_s"] is not None for item in group)
                    else None
                ),
                "median_voluntary_context_switches": statistics.median(
                    int(item["voluntary_context_switches"])
                    for item in group
                    if item["voluntary_context_switches"] is not None
                )
                if any(item["voluntary_context_switches"] is not None for item in group)
                else None,
                "observations": len(group),
                "p05_ns": _percentile(values, 0.05),
                "p95_ns": _percentile(values, 0.95),
            }
        )
    return summaries
