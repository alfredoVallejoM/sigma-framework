import contextlib
import hashlib
import math
import multiprocessing
import os
import platform
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path
from queue import Empty
from typing import Any, Optional

from sigma.anchors import TreeWide
from sigma.backends import MultiprocessingTreeBackend
from sigma.presets import get_preset, lightweight_v2, simultaneous_v2
from sigma.rounds import TraceConfig, TracePolicy
from sigma.v2 import _anchor_engine, _round_engine


def _rss_bytes() -> Optional[int]:
    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if platform.system() == "Darwin" else value * 1024)
    except (ImportError, OSError):
        return None


def _proc_rss_bytes(pid: int) -> Optional[int]:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (FileNotFoundError, OSError, ValueError):
        return None
    return None


def _aggregate_rss_monitor(parent: int, stop, queue) -> None:
    peak = 0
    samples = 0
    while not stop.is_set():
        pids = [parent]
        try:
            children = Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
            pids.extend(int(value) for value in children if int(value) != os.getpid())
        except (FileNotFoundError, OSError, ValueError):
            pass
        values = [_proc_rss_bytes(pid) for pid in pids]
        measured = [value for value in values if value is not None]
        if len(measured) == len(values):
            peak = max(peak, sum(measured))
            samples += 1
        time.sleep(0.001)
    queue.put((peak if samples else None, samples))


def _feed(engine, size: int, io_chunk: int) -> int:
    block = bytes((offset * 131 + 17) & 0xFF for offset in range(io_chunk))
    remaining = size
    frontier_peak = 0
    while remaining:
        portion = block[: min(remaining, len(block))]
        engine.update(portion)
        remaining -= len(portion)
        frontier_peak = max(frontier_peak, getattr(engine, "frontier_node_count", 0))
    return frontier_peak


def _worker(task: tuple[str, int, int, int, int, int, str]) -> dict[str, Any]:
    profile, size, io_chunk, workers, target_round, state_count, trace_name = task
    revised_presets = {
        "wide-v2-2": "lightweight-v2-2",
        "cross-wide-v2-2": "paranoid-wide-v2-2",
        "deep-v2-2": "paranoid-deep-v2-2",
        "deep-vector-v2-2": "paranoid-deep-vector-v2-2",
        "tree-wide-v2-2": "simultaneous-v2-2",
        "parallel-tree-v2-2": "simultaneous-v2-2",
    }
    if profile in revised_presets:
        context = get_preset(
            revised_presets[profile], target_round=target_round, state_count=state_count
        )
    else:
        context = (
            lightweight_v2(target_round=target_round, state_count=state_count)
            if profile == "stream-wide"
            else simultaneous_v2(target_round=target_round, state_count=state_count)
        )
    temporary: Optional[tempfile.TemporaryDirectory[str]] = None
    path: Optional[Path] = None
    parallel = profile in {"parallel-tree", "parallel-tree-v2-2"}
    tree_profile = profile in {"tree-wide", "tree-wide-v2-2"}
    if parallel:
        temporary = tempfile.TemporaryDirectory(prefix="sigma-exp10-")
        path = Path(temporary.name) / "message.bin"
        block = bytes((offset * 131 + 17) & 0xFF for offset in range(io_chunk))
        with path.open("wb") as target:
            remaining = size
            while remaining:
                portion = block[: min(remaining, len(block))]
                target.write(portion)
                remaining -= len(portion)
    rss_before = _rss_bytes()
    monitor_context = multiprocessing.get_context("spawn")
    monitor_stop = monitor_context.Event()
    monitor_queue = monitor_context.Queue()
    monitor = None
    if parallel and Path("/proc/self/status").is_file():
        monitor = monitor_context.Process(
            target=_aggregate_rss_monitor,
            args=(multiprocessing.current_process().pid, monitor_stop, monitor_queue),
        )
        monitor.start()
    tracemalloc.start()
    frontier_peak = 0
    if not tree_profile and not parallel:
        engine = _anchor_engine(context)
        frontier_peak = _feed(engine, size, io_chunk)
        evidence = engine.finalize()
        rss_scope = "current-process"
    elif tree_profile:
        tree = TreeWide(context)
        frontier_peak = _feed(tree, size, io_chunk)
        evidence = tree.finalize()
        rss_scope = "current-process"
    elif parallel:
        if path is None:
            raise RuntimeError("parallel memory task has no input file")
        evidence = MultiprocessingTreeBackend(workers).compute_anchor_file(path, context)
        rss_scope = "aggregate-parent-children-sampled" if monitor is not None else "parent-only"
    else:
        raise ValueError(f"unsupported memory profile: {profile}")
    round_engine = _round_engine(context)
    trace_policy = TracePolicy(trace_name)
    if trace_policy is TracePolicy.NONE:
        digest = round_engine.evaluate_digest(evidence)
        trace_entries = 0
    else:
        last_index = target_round + state_count - 1
        digest, transcript = round_engine.evaluate_trace(
            evidence,
            TraceConfig(
                policy=trace_policy,
                every_n=max(1, int(math.sqrt(max(1, last_index)))),
                max_entries=last_index + 1,
            ),
        )
        trace_entries = len(transcript.states)
    _, peak_allocated = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = _rss_bytes()
    aggregate_rss_peak = None
    aggregate_rss_samples = 0
    if monitor is not None:
        monitor_stop.set()
        monitor.join(5)
        if monitor.is_alive():
            monitor.terminate()
            monitor.join()
        with contextlib.suppress(Empty):
            aggregate_rss_peak, aggregate_rss_samples = monitor_queue.get(timeout=1)
    monitor_queue.close()
    disk_temporary_bytes = path.stat().st_size if path is not None else 0
    if temporary is not None:
        temporary.cleanup()
    return {
        "anchor_sha256": hashlib.sha256(evidence.to_bytes()).hexdigest(),
        "bytes": size,
        "frontier_nodes_peak": frontier_peak,
        "io_chunk": io_chunk,
        "digest_sha256": hashlib.sha256(digest.to_bytes()).hexdigest(),
        "disk_temporary_bytes": disk_temporary_bytes,
        "peak_allocated_bytes": peak_allocated,
        "profile": profile,
        "rss_aggregate_peak_bytes": aggregate_rss_peak,
        "rss_aggregate_samples": aggregate_rss_samples,
        "rss_before_bytes": rss_before,
        "rss_peak_bytes": rss_after,
        "rss_scope": rss_scope,
        "state_count": state_count,
        "target_round": target_round,
        "trace_entries": trace_entries,
        "trace_policy": trace_name,
        "workers": workers,
    }


def _worker_entry(task, queue) -> None:
    try:
        queue.put((True, _worker(task)))
    except BaseException as exc:
        queue.put((False, f"{type(exc).__name__}: {exc}"))


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    context = multiprocessing.get_context("spawn")
    records = []
    repetitions = int(config.get("repetitions", 2))
    timeout = float(config.get("timeout_seconds", 120))
    target_rounds = config.get("target_rounds", [1])
    state_counts = config.get("state_counts", [2])
    trace_policies = config.get("trace_policies", ["none"])
    for profile in config["profiles"]:
        worker_values = (
            config.get("workers", [1])
            if profile in {"parallel-tree", "parallel-tree-v2-2"}
            else [1]
        )
        for workers_value in worker_values:
            for io_chunk_value in config["io_chunks"]:
                for size_value in config["sizes"]:
                    for target_round_value in target_rounds:
                        for state_count_value in state_counts:
                            for trace_policy in trace_policies:
                                for repetition in range(repetitions):
                                    task = (
                                        str(profile),
                                        int(size_value),
                                        int(io_chunk_value),
                                        int(workers_value),
                                        int(target_round_value),
                                        int(state_count_value),
                                        str(trace_policy),
                                    )
                                    queue = context.Queue()
                                    process = context.Process(
                                        target=_worker_entry, args=(task, queue)
                                    )
                                    process.start()
                                    process.join(timeout)
                                    if process.is_alive():
                                        process.terminate()
                                        process.join(5)
                                        raise RuntimeError(f"memory worker timed out for {task}")
                                    try:
                                        succeeded, value = queue.get(timeout=5)
                                    except Empty as exc:
                                        raise RuntimeError(
                                            f"memory worker exited {process.exitcode} without a result for {task}"
                                        ) from exc
                                    finally:
                                        queue.close()
                                    if not succeeded:
                                        raise RuntimeError(str(value))
                                    value["repetition"] = repetition
                                    records.append(value)
    return records


def _linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    variance = sum((value - mean_x) ** 2 for value in xs)
    slope = (
        sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / variance
        if variance
        else 0.0
    )
    intercept = mean_y - slope * mean_x
    residual = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys, strict=True))
    return intercept, slope, residual


def _fit_models(sizes: list[float], values: list[float]) -> dict[str, Any]:
    candidates = {}
    for name, xs in (
        ("constant", [0.0] * len(sizes)),
        ("logarithmic", [math.log2(max(1.0, value)) for value in sizes]),
        ("linear", sizes),
    ):
        intercept, slope, residual = _linear_fit(xs, values)
        parameters = 1 if name == "constant" else 2
        aic = len(values) * math.log(max(residual / len(values), 1e-300)) + 2 * parameters
        candidates[name] = {
            "aic": aic,
            "intercept": intercept,
            "residual_sum_squares": residual,
            "slope": slope,
        }
    selected = min(candidates, key=lambda name: candidates[name]["aic"])
    return {"models": candidates, "selected_model": selected}


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "profile",
        "workers",
        "io_chunk",
        "target_round",
        "state_count",
        "trace_policy",
    )
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        by_size: dict[int, list[int]] = {}
        for item in group:
            by_size.setdefault(int(item["bytes"]), []).append(int(item["peak_allocated_bytes"]))
        sizes = [float(size) for size in sorted(by_size)]
        peaks = [float(statistics.median(by_size[int(size)])) for size in sizes]
        memory_models = {"tracemalloc_peak": _fit_models(sizes, peaks)}
        for metric in ("rss_peak_bytes", "rss_aggregate_peak_bytes"):
            values_by_size: dict[int, list[int]] = {}
            for item in group:
                value = item.get(metric)
                if value is not None:
                    values_by_size.setdefault(int(item["bytes"]), []).append(int(value))
            if set(values_by_size) == {int(size) for size in sizes}:
                medians = [
                    float(statistics.median(values_by_size[int(size)])) for size in sizes
                ]
                memory_models[metric] = _fit_models(sizes, medians)
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                **_fit_models(sizes, peaks),
                "dimension": "message_bytes",
                "memory_models": memory_models,
                "observations": len(group),
                "sizes": [int(value) for value in sizes],
            }
        )
    depth_fields = ("profile", "workers", "io_chunk", "bytes", "state_count", "trace_policy")
    depth_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        depth_groups.setdefault(tuple(record[field] for field in depth_fields), []).append(record)
    for key, group in sorted(depth_groups.items()):
        by_depth: dict[int, list[int]] = {}
        for item in group:
            by_depth.setdefault(int(item["target_round"]), []).append(
                int(item["peak_allocated_bytes"])
            )
        depths = [float(depth) for depth in sorted(by_depth)]
        peaks = [float(statistics.median(by_depth[int(depth)])) for depth in depths]
        memory_models = {"tracemalloc_peak": _fit_models(depths, peaks)}
        for metric in ("rss_peak_bytes", "rss_aggregate_peak_bytes"):
            values_by_depth: dict[int, list[int]] = {}
            for item in group:
                value = item.get(metric)
                if value is not None:
                    values_by_depth.setdefault(int(item["target_round"]), []).append(int(value))
            if set(values_by_depth) == {int(depth) for depth in depths}:
                medians = [
                    float(statistics.median(values_by_depth[int(depth)])) for depth in depths
                ]
                memory_models[metric] = _fit_models(depths, medians)
        summaries.append(
            {
                **dict(zip(depth_fields, key, strict=False)),
                **_fit_models(depths, peaks),
                "dimension": "target_round",
                "memory_models": memory_models,
                "observations": len(group),
                "target_rounds": [int(value) for value in depths],
            }
        )
    return summaries
