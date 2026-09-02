import hashlib
import math
import multiprocessing
import platform
import statistics
import tempfile
import tracemalloc
from pathlib import Path
from queue import Empty
from typing import Any, Optional

from sigma.anchors import StreamWide, TreeWide
from sigma.backends import MultiprocessingTreeBackend
from sigma.presets import lightweight_v2, simultaneous_v2


def _rss_bytes() -> Optional[int]:
    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if platform.system() == "Darwin" else value * 1024)
    except (ImportError, OSError):
        return None


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


def _worker(task: tuple[str, int, int, int]) -> dict[str, Any]:
    profile, size, io_chunk, workers = task
    temporary: Optional[tempfile.TemporaryDirectory[str]] = None
    path: Optional[Path] = None
    if profile == "parallel-tree":
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
    tracemalloc.start()
    frontier_peak = 0
    if profile == "stream-wide":
        engine = StreamWide(lightweight_v2())
        frontier_peak = _feed(engine, size, io_chunk)
        evidence = engine.finalize()
        rss_scope = "current-process"
    elif profile == "tree-wide":
        tree = TreeWide(simultaneous_v2())
        frontier_peak = _feed(tree, size, io_chunk)
        evidence = tree.finalize()
        rss_scope = "current-process"
    elif profile == "parallel-tree":
        if path is None:
            raise RuntimeError("parallel memory task has no input file")
        evidence = MultiprocessingTreeBackend(workers).compute_anchor_file(path, simultaneous_v2())
        rss_scope = "parent-only"
    else:
        raise ValueError(f"unsupported memory profile: {profile}")
    _, peak_allocated = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = _rss_bytes()
    if temporary is not None:
        temporary.cleanup()
    return {
        "anchor_sha256": hashlib.sha256(evidence.to_bytes()).hexdigest(),
        "bytes": size,
        "frontier_nodes_peak": frontier_peak,
        "io_chunk": io_chunk,
        "peak_allocated_bytes": peak_allocated,
        "profile": profile,
        "rss_before_bytes": rss_before,
        "rss_peak_bytes": rss_after,
        "rss_scope": rss_scope,
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
    for profile in config["profiles"]:
        worker_values = config.get("workers", [1]) if profile == "parallel-tree" else [1]
        for workers_value in worker_values:
            for io_chunk_value in config["io_chunks"]:
                for size_value in config["sizes"]:
                    for repetition in range(repetitions):
                        task = (
                            str(profile),
                            int(size_value),
                            int(io_chunk_value),
                            int(workers_value),
                        )
                        queue = context.Queue()
                        process = context.Process(target=_worker_entry, args=(task, queue))
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
    fields = ("profile", "workers", "io_chunk")
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
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                **_fit_models(sizes, peaks),
                "observations": len(group),
                "sizes": [int(value) for value in sizes],
            }
        )
    return summaries
