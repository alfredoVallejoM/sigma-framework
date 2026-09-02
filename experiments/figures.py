import argparse
import csv
import gzip
import json
import statistics
from pathlib import Path
from typing import Any

from .common import sha256_file

SELECTED_RUNS = {
    "EXP-01": "exp01-analysis-v2-20260902",
    "EXP-02": "exp02-analysis-20260902",
    "EXP-03": "exp03-analysis-20260902",
    "EXP-04": "exp04-analysis-v2-20260902",
    "EXP-05": "exp05-analysis-v2-20260902",
    "EXP-06": "exp06-smoke-20260902",
    "EXP-07": "exp07-analysis-v2-20260902",
    "EXP-08": "exp08-smoke-20260902",
    "EXP-09": "exp09-smoke-20260902",
    "EXP-10": "exp10-smoke-20260902",
    "EXP-11": "exp11-smoke-20260902",
    "EXP-12": "exp12-smoke-20260902",
    "EXP-14": "exp14-smoke-20260902",
    "EXP-15": "exp15-smoke-20260902",
}


def _summary(results: Path, experiment: str, selected_runs: dict[str, str]) -> dict[str, Any]:
    path = results / selected_runs[experiment] / "summary.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _raw(results: Path, experiment: str, selected_runs: dict[str, str]) -> list[dict[str, str]]:
    path = results / selected_runs[experiment] / "observations.csv.gz"
    with gzip.open(path, "rt", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def _save(figure, output: Path, name: str) -> Path:
    path = output / f"{name}.svg"
    figure.tight_layout()
    figure.savefig(path, format="svg", metadata={"Date": None})
    figure.savefig(output / f"{name}.png", format="png", dpi=180, metadata={"Date": None})
    return path


def generate(
    results: Path, output: Path, selected_runs: dict[str, str] | None = None
) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    matplotlib.rcParams["svg.hashsalt"] = "sigma-v2-figures-v1"
    selected_runs = selected_runs or SELECTED_RUNS
    output.mkdir(parents=True, exist_ok=True)
    created = []

    exp01 = _summary(results, "EXP-01", selected_runs)
    figure, axis = plt.subplots(figsize=(5.2, 3.0))
    axis.bar(["matching", "divergent"], [exp01["observations"], exp01["failures"]])
    axis.set_ylabel("observations")
    axis.set_title("EXP-01 exact determinism smoke")
    created.append(_save(figure, output, "exp01-determinism"))
    plt.close(figure)

    exp02 = _summary(results, "EXP-02", selected_runs)["groups"]
    selected02 = [
        group
        for group in exp02
        if group["target_round"] == 1
        and group["construction"] in ("simple-consecutive", "reinjected-consecutive")
    ]
    figure, axis = plt.subplots(figsize=(5.2, 3.4))
    for construction in ("simple-consecutive", "reinjected-consecutive"):
        subset = [group for group in selected02 if group["construction"] == construction]
        axis.scatter(
            [group["predicted_log2"] for group in subset],
            [group["median_log2_candidates"] for group in subset],
            label=construction,
            alpha=0.75,
        )
    axis.plot([0, 13], [0, 13], linestyle="--", color="black", linewidth=1, label="prediction")
    axis.set(xlabel="predicted log2 work", ylabel="observed median log2 candidates")
    axis.legend(fontsize=8)
    axis.set_title("EXP-02 reduced collision work")
    created.append(_save(figure, output, "exp02-collision-scaling"))
    plt.close(figure)

    exp03 = _summary(results, "EXP-03", selected_runs)["groups"]
    reinjected = [group for group in exp03 if group["construction"] == "reinjected"]
    figure, axis = plt.subplots(figsize=(5.2, 3.4))
    axis.scatter(
        [group["expected_probability"] for group in reinjected],
        [max(group["observed_probability"], 1 / group["trials"] / 2) for group in reinjected],
    )
    axis.plot([1e-8, 1e-1], [1e-8, 1e-1], linestyle="--", color="black", linewidth=1)
    axis.set(
        xscale="log",
        yscale="log",
        xlabel="expected probability",
        ylabel="observed (zero shown at 1/(2N))",
    )
    axis.set_title("EXP-03 conditional persistence")
    created.append(_save(figure, output, "exp03-persistence"))
    plt.close(figure)

    exp04 = _summary(results, "EXP-04", selected_runs)["groups"]
    selected04 = [
        group
        for group in exp04
        if group["attack"] == "generic-birthday"
        and group["fault"] == "normal"
        and group["state_bits"] == 8
        and group["branches"] == 3
    ]
    figure, axis = plt.subplots(figsize=(5.2, 3.2))
    axis.bar(
        [group["construction"] for group in selected04],
        [group["median_log2_candidates"] for group in selected04],
    )
    axis.tick_params(axis="x", rotation=20)
    axis.set_ylabel("median log2 candidates")
    axis.set_title("EXP-04 narrow versus retained-root anchors")
    created.append(_save(figure, output, "exp04-anchor-bottleneck"))
    plt.close(figure)

    exp05 = _summary(results, "EXP-05", selected_runs)["groups"]
    figure, axis = plt.subplots(figsize=(6.4, 3.6))
    coverage_by_family: dict[str, list[float]] = {}
    for group in exp05:
        perturbation = str(group["perturbation"])
        family = perturbation.split("-")[0]
        coverage_by_family.setdefault(family, []).append(float(group["coverage"]))
    labels = sorted(coverage_by_family)
    axis.barh(
        labels,
        [statistics.mean(coverage_by_family[label]) for label in labels],
    )
    axis.set(xlim=(0, 1.02), xlabel="observed output-bit coverage")
    axis.set_title("EXP-05 structural dependency smoke")
    created.append(_save(figure, output, "exp05-dependencies"))
    plt.close(figure)

    exp06 = _summary(results, "EXP-06", selected_runs)["groups"]
    figure, axis = plt.subplots(figsize=(5.2, 3.4))
    for profile in ("wide-once", "deep"):
        subset = sorted(
            (
                group
                for group in exp06
                if group["profile"] == profile
                and group["candidates"] == 1
                and group["candidate_workers"] == 1
                and group["state_count"] == 1
            ),
            key=lambda group: group["critical_levels"],
        )
        axis.plot(
            [group["critical_levels"] for group in subset],
            [group["median_elapsed_ns"] for group in subset],
            marker="o",
            label=profile,
        )
    axis.set(xlabel="adaptive levels", ylabel="median ns")
    axis.legend()
    axis.set_title("EXP-06 per-candidate depth and time")
    created.append(_save(figure, output, "exp06-depth"))
    plt.close(figure)

    exp07 = _summary(results, "EXP-07", selected_runs)["groups"]
    selected07 = [group for group in exp07 if group["layer"] != "anchor-framed"]
    figure, axis = plt.subplots(figsize=(7.2, 3.8))
    axis.barh(
        [group["layer"] for group in selected07],
        [group["mean_flip_probability"] for group in selected07],
    )
    axis.axvline(0.5, linestyle="--", color="black", linewidth=1)
    axis.set_xlabel("mean flip probability")
    axis.set_title("EXP-07 layer-separated diffusion smoke")
    created.append(_save(figure, output, "exp07-diffusion"))
    plt.close(figure)

    exp08 = _summary(results, "EXP-08", selected_runs)["groups"]
    constructions = sorted({str(group["construction"]) for group in exp08})
    minimum_p = [
        min(
            float(value)
            for group in exp08
            if group["construction"] == construction
            for value in group["p_values"].values()
        )
        for construction in constructions
    ]
    figure, axis = plt.subplots(figsize=(6.2, 3.4))
    axis.bar(constructions, minimum_p)
    axis.axhline(exp08[0]["bonferroni_alpha"], linestyle="--", color="black", linewidth=1)
    axis.set(yscale="log", ylabel="minimum published p-value")
    axis.tick_params(axis="x", rotation=25)
    axis.set_title("EXP-08 distribution smoke (descriptive only)")
    created.append(_save(figure, output, "exp08-distribution"))
    plt.close(figure)

    exp09 = _summary(results, "EXP-09", selected_runs)["groups"]
    figure, axis = plt.subplots(figsize=(5.4, 3.5))
    for construction in ("sha256", "concat-branches", "sigma-wide", "sigma-cross", "sigma-deep"):
        subset = sorted(
            (
                group
                for group in exp09
                if group["construction"] == construction
                and group["operation"] == "full-hash"
                and group["bytes"] > 0
            ),
            key=lambda group: group["bytes"],
        )
        axis.plot(
            [group["bytes"] for group in subset],
            [group["median_ns"] for group in subset],
            marker=".",
            label=construction,
        )
    axis.set(xscale="log", yscale="log", xlabel="message bytes", ylabel="median ns")
    axis.legend(fontsize=7)
    axis.set_title("EXP-09 in-memory performance smoke")
    created.append(_save(figure, output, "exp09-performance"))
    plt.close(figure)

    exp10 = _raw(results, "EXP-10", selected_runs)
    figure, axis = plt.subplots(figsize=(5.4, 3.5))
    for profile in ("stream-wide", "tree-wide", "parallel-tree"):
        subset = [
            row
            for row in exp10
            if row["profile"] == profile and row["io_chunk"] == "65536" and row["workers"] == "1"
        ]
        sizes = sorted({int(row["bytes"]) for row in subset if int(row["bytes"]) > 0})
        medians = [
            statistics.median(
                int(row["peak_allocated_bytes"]) for row in subset if int(row["bytes"]) == size
            )
            for size in sizes
        ]
        axis.plot(sizes, medians, marker="o", label=profile)
    axis.set(
        xscale="log", yscale="log", xlabel="message bytes", ylabel="peak Python allocations (bytes)"
    )
    axis.legend(fontsize=8)
    axis.set_title("EXP-10 allocation growth")
    created.append(_save(figure, output, "exp10-memory"))
    plt.close(figure)

    if "EXP-11" in selected_runs:
        exp11 = _summary(results, "EXP-11", selected_runs)["groups"]
        figure, axis = plt.subplots(figsize=(5.4, 3.3))
        axis.bar(
            [str(group["predicate"]).replace("_", " ") for group in exp11],
            [group["mean_attempts"] for group in exp11],
        )
        axis.axhline(exp11[0]["expected_mean_attempts"], linestyle="--", color="black", linewidth=1)
        axis.set(ylabel="mean attempts")
        axis.tick_params(axis="x", rotation=20)
        axis.set_title("EXP-11 equal-probability PoW predicates")
        created.append(_save(figure, output, "exp11-pow"))
        plt.close(figure)

    if "EXP-12" in selected_runs:
        exp12 = _summary(results, "EXP-12", selected_runs)["groups"]
        figure, axis = plt.subplots(figsize=(5.4, 3.3))
        axis.bar(
            [f"{group['memory_kib']} KiB / t={group['time_cost']}" for group in exp12],
            [group["overhead_ratio"] for group in exp12],
        )
        axis.axhline(1, linestyle="--", color="black", linewidth=1)
        axis.set(ylabel="Argon2id rate / composed rate")
        axis.tick_params(axis="x", rotation=20)
        axis.set_title("EXP-12 measured Sigma post-processing overhead")
        created.append(_save(figure, output, "exp12-kdf-overhead"))
        plt.close(figure)

    if "EXP-14" in selected_runs:
        exp14 = _summary(results, "EXP-14", selected_runs)["groups"]
        figure, axis = plt.subplots(figsize=(5.4, 3.3))
        axis.bar(
            [group["fault_site"] for group in exp14], [group["detection_rate"] for group in exp14]
        )
        axis.set(ylim=(0, 1.05), ylabel="detection rate")
        axis.set_title("EXP-14 full-recomputation fault detection")
        created.append(_save(figure, output, "exp14-fault-detection"))
        plt.close(figure)

    if "EXP-15" in selected_runs:
        exp15 = _summary(results, "EXP-15", selected_runs)["groups"]
        diffusion = [group for group in exp15 if group["kind"].endswith("differential")]
        figure, axis = plt.subplots(figsize=(5.2, 3.2))
        axis.bar(
            [group["kind"] for group in diffusion], [group["mean_metric"] for group in diffusion]
        )
        axis.axhline(256, linestyle="--", color="black", linewidth=1)
        axis.set(ylabel="mean changed output bits")
        axis.set_title("EXP-15 Psi diffusion baseline")
        created.append(_save(figure, output, "exp15-psi-diffusion"))
        plt.close(figure)

    source_paths = {
        experiment: results
        / run
        / ("observations.csv.gz" if experiment == "EXP-10" else "summary.json")
        for experiment, run in selected_runs.items()
        if experiment
        in {
            "EXP-01",
            "EXP-02",
            "EXP-03",
            "EXP-04",
            "EXP-05",
            "EXP-06",
            "EXP-07",
            "EXP-08",
            "EXP-09",
            "EXP-10",
            "EXP-11",
            "EXP-12",
            "EXP-14",
            "EXP-15",
        }
    }
    figure_paths = sorted(output.glob("*.svg")) + sorted(output.glob("*.png"))
    manifest = {
        "figures": {path.name: sha256_file(path) for path in figure_paths},
        "schema": "sigma-figure-manifest-v1",
        "sources": {name: sha256_file(path) for name, path in source_paths.items()},
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return [*figure_paths, manifest_path]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("experiments/results"))
    parser.add_argument("--output", type=Path, default=Path("paper/figures"))
    args = parser.parse_args()
    for path in generate(args.results, args.output):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
