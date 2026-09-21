"""Final R15 mandatory dataset closure and locked analysis surfaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .common import canonical_json
from .r13_schema import ResourceBudget
from .r14_analysis import FIGURES_V3, TABLES_V3
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r15_estimators import (
    BOOTSTRAP_REPLICATES,
    clopper_pearson_interval_v3,
    kaplan_meier_v3,
    km_q50_v3,
    km_rmst_v3,
    pareto_frontier_v3,
    zero_event_upper_bound_v3,
)
from .r141_schema import ConfirmatoryRecordR141

ENGINEERING_ATTACKS = {"PARAM-04", "PARAM-05", "PARAM-06"}
MANDATORY_EXPECTED_RUN_UNITS = 145_088
MANDATORY_EXPECTED_ATTACKS = 18
EXPLORATORY_FIGURES = {"F10", "F12", "F13"}


def _expected_runkeys(config_root: Path) -> tuple[RunKeyV3, ...]:
    keys: list[RunKeyV3] = []
    for path in sorted(config_root.glob("*.json")):
        if path.name in {"campaign-index.json", "config-manifest.json"}:
            continue
        config = json.loads(path.read_text(encoding="utf-8"))
        attack_id = str(config["attack_id"])
        if attack_id in ENGINEERING_ATTACKS:
            continue
        freeze_id = str(config["freeze_id"])
        for cell in config["cells"]:
            for replicate_id in range(int(cell["replicates"])):
                keys.append(
                    RunKeyV3(
                        freeze_id,
                        attack_id,
                        str(cell["cell_id"]),
                        replicate_id,
                    )
                )
    if len(keys) != MANDATORY_EXPECTED_RUN_UNITS:
        raise RuntimeError(
            f"mandatory R15 cardinality drifted: {len(keys)} != {MANDATORY_EXPECTED_RUN_UNITS}"
        )
    if len(keys) != len(set(keys)):
        raise RuntimeError("mandatory R15 expected RunKeys contain duplicates")
    if len({key.attack_id for key in keys}) != MANDATORY_EXPECTED_ATTACKS:
        raise RuntimeError("mandatory R15 attack cardinality drifted")
    return tuple(sorted(keys))


def _receipt_for_record(record_path: Path) -> Path:
    parts = record_path.parts
    try:
        raw_index = parts.index("raw")
    except ValueError as exc:
        raise ValueError("R15 record path is not below raw/") from exc
    root = Path(*parts[:raw_index])
    relative = Path(*parts[raw_index + 1 :])
    return root / "receipts" / relative


def _construct_record(value: dict[str, Any]) -> ConfirmatoryRecordR141:
    return ConfirmatoryRecordR141(
        schema=str(value["schema"]),
        campaign_id=str(value["campaign_id"]),
        freeze_id=str(value["freeze_id"]),
        attack_id=str(value["attack_id"]),
        claim_ids=tuple(str(item) for item in value["claim_ids"]),
        construction=str(value["construction"]),
        cell_id=str(value["cell_id"]),
        replicate_id=int(value["replicate_id"]),
        seed_hex=str(value["seed_hex"]),
        phase=str(value["phase"]),
        declared=ResourceBudget(**value["declared"]),
        observed=ResourceBudget(**value["observed"]),
        status=value["status"],  # type: ignore[arg-type]
        metrics=dict(value["metrics"]),
        censor_reason=value["censor_reason"],
        error_class=value["error_class"],
        code_commit=str(value["code_commit"]),
        artifact_sha256=str(value["artifact_sha256"]),
        config_sha256=str(value["config_sha256"]),
        preregistration_sha256=str(value["preregistration_sha256"]),
        dependency_lock_sha256=str(value["dependency_lock_sha256"]),
        execution_manifest_sha256=str(value["execution_manifest_sha256"]),
        host_id=str(value["host_id"]),
        platform_name=str(value["platform_name"]),
        architecture=str(value["architecture"]),
        python_version=str(value["python_version"]),
        started_utc=str(value["started_utc"]),
        completed_utc=str(value["completed_utc"]),
        record_sha256=str(value["record_sha256"]),
    )


def _load_verified_record(record_path: Path) -> tuple[dict[str, Any], RunKeyV3]:
    data = record_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("R15 confirmatory record must be an object")

    record = _construct_record(value)
    key = RunKeyV3(
        record.freeze_id,
        record.attack_id,
        record.cell_id,
        record.replicate_id,
    )
    receipt_path = _receipt_for_record(record_path)
    if not receipt_path.is_file():
        raise ValueError(f"missing receipt for {record_path}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("record_sha256") != digest:
        raise ValueError(f"receipt digest mismatch for {record_path}")
    if receipt.get("run_key") != key.stable_id:
        raise ValueError(f"receipt RunKey mismatch for {record_path}")
    return value, key


def _config_cells(config_root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(config_root.glob("*.json")):
        if path.name in {"campaign-index.json", "config-manifest.json"}:
            continue
        config = json.loads(path.read_text(encoding="utf-8"))
        attack_id = str(config["attack_id"])
        if attack_id in ENGINEERING_ATTACKS:
            continue
        for cell in config["cells"]:
            result[(attack_id, str(cell["cell_id"]))] = cell
    return result


def _numeric(values: list[object]) -> list[float]:
    return [
        float(value)
        for value in values
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]


def _cell_analysis(
    attack_id: str,
    cell_id: str,
    cell: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, object]:
    analysis = cell["analysis"]
    primary = str(analysis["primary_metric"])
    statuses = Counter(str(record["status"]) for record in records)
    metric_values = _numeric([record["metrics"].get(primary) for record in records])
    summary: dict[str, object] = {
        "attack_id": attack_id,
        "cell_id": cell_id,
        "factors": cell["factors"],
        "region": cell["region"],
        "primary_metric": primary,
        "estimator": analysis["estimator"],
        "interval": analysis["interval"],
        "records": len(records),
        "statuses": dict(sorted(statuses.items())),
        "numeric_primary_records": len(metric_values),
    }
    if metric_values:
        summary["mean"] = statistics.fmean(metric_values)
        summary["median"] = statistics.median(metric_values)
        summary["minimum"] = min(metric_values)
        summary["maximum"] = max(metric_values)

    if attack_id == "HIST-01":
        trials = sum(
            int(record["metrics"].get("trials", 0))
            for record in records
            if isinstance(record["metrics"].get("trials"), int)
        )
        successes = sum(
            int(record["metrics"].get("next_state_matches", 0))
            for record in records
            if isinstance(record["metrics"].get("next_state_matches"), int)
        )
        if trials > 0:
            interval = clopper_pearson_interval_v3(successes, trials)
            summary["aggregate_trials"] = trials
            summary["aggregate_successes"] = successes
            summary["exact_rate"] = successes / trials
            summary["ci95"] = asdict(interval)
            if successes == 0:
                summary["zero_event_upper_99"] = zero_event_upper_bound_v3(trials)

    if primary in {
        "queries",
        "queries_to_first_full_state_collision",
        "queries_to_first_window_collision",
    }:
        times: list[int] = []
        events: list[bool] = []
        for record in records:
            value = record["metrics"].get(primary)
            if isinstance(value, int) and not isinstance(value, bool):
                times.append(value)
                events.append(record["status"] == "success")
        if times:
            curve = kaplan_meier_v3(times, events)
            summary["km_q50"] = km_q50_v3(curve)
            summary["km_rmst"] = km_rmst_v3(curve, tau=max(times))
            summary["km_tau"] = max(times)

    return summary


def _analysis_surface(
    *,
    config_root: Path,
    records: dict[str, dict[str, Any]],
) -> dict[str, object]:
    by_cell: dict[tuple[str, str], list[dict[str, Any]]] = {}
    by_attack: dict[str, list[dict[str, Any]]] = {}
    for record in records.values():
        attack_id = str(record["attack_id"])
        cell_id = str(record["cell_id"])
        by_cell.setdefault((attack_id, cell_id), []).append(record)
        by_attack.setdefault(attack_id, []).append(record)

    cell_specs = _config_cells(config_root)
    cells = [
        _cell_analysis(attack_id, cell_id, spec, by_cell.get((attack_id, cell_id), []))
        for (attack_id, cell_id), spec in sorted(cell_specs.items())
    ]

    figures: dict[str, dict[str, object]] = {}
    for figure in FIGURES_V3:
        exploratory = figure.figure_id in EXPLORATORY_FIGURES
        selected = 0 if exploratory else sum(len(by_attack.get(a, ())) for a in figure.attack_ids)
        figures[figure.figure_id] = {
            "title": figure.title,
            "attack_ids": list(figure.attack_ids),
            "fields": list(figure.fields),
            "transform": figure.transform,
            "uncertainty": figure.uncertainty,
            "records": selected,
            "classification": "exploratory-engineering" if exploratory else "mandatory-confirmatory",
            "excluded_from_r15_pass": exploratory,
        }

    tmto_points: list[tuple[int, int, int]] = []
    for attack_id in ("TMTO-01", "TMTO-02"):
        for record in by_attack.get(attack_id, ()):
            metrics = record["metrics"]
            values = (
                metrics.get("offline_queries"),
                metrics.get("online_queries"),
                metrics.get("memory_entries"),
            )
            if all(isinstance(value, int) and not isinstance(value, bool) for value in values):
                tmto_points.append((int(values[0]), int(values[1]), int(values[2])))
    frontier = pareto_frontier_v3(tmto_points) if tmto_points else ()

    return {
        "schema": "sigma-v3-r15-locked-analysis-surface-v1",
        "mandatory_records": len(records),
        "mandatory_attacks": len(by_attack),
        "bootstrap_replicates_locked": BOOTSTRAP_REPLICATES,
        "cell_summaries": cells,
        "figures": figures,
        "tables": list(TABLES_V3),
        "tmto_pareto_frontier": [list(point) for point in frontier],
        "application_figures_reclassified": sorted(EXPLORATORY_FIGURES),
        "publication_interval_render": "locked estimators; full bootstrap render remains a deterministic post-closure presentation step",
    }


def close_r15(
    *,
    dataset_roots: list[Path],
    config_root: Path,
    output_root: Path,
) -> dict[str, object]:
    if len(dataset_roots) < 5:
        raise ValueError("R15 closure requires W1, W2, W3A, amendment and STAT datasets")

    expected = _expected_runkeys(config_root)
    expected_ids = {key.stable_id for key in expected}
    observed: dict[str, dict[str, Any]] = {}
    statuses: dict[str, Counter[str]] = {}

    for root in dataset_roots:
        for path in sorted(root.glob("raw/**/*.json")):
            record, key = _load_verified_record(path)
            if key.attack_id in ENGINEERING_ATTACKS:
                raise RuntimeError("exploratory engineering record entered mandatory closure")
            if key.stable_id in observed:
                raise RuntimeError(f"duplicate mandatory RunKey: {key.stable_id}")
            if key.stable_id not in expected_ids:
                raise RuntimeError(f"unexpected mandatory RunKey: {key.stable_id}")
            observed[key.stable_id] = record
            statuses.setdefault(key.attack_id, Counter())[str(record["status"])] += 1

    observed_ids = set(observed)
    missing = expected_ids - observed_ids
    extra = observed_ids - expected_ids
    if missing or extra:
        raise RuntimeError(
            f"R15 mandatory coverage mismatch: missing={len(missing)}, extra={len(extra)}"
        )

    output_root.mkdir(parents=True, exist_ok=True)
    merged: list[RunKeyV3] = []
    for key in expected:
        atomic_write_record_v3(output_root, key, observed[key.stable_id])
        merged.append(key)

    ledger = build_ledger_v3(output_root, merged)
    (output_root / "r15-final-ledger.json").write_bytes(canonical_json(ledger) + b"\n")

    analysis = _analysis_surface(config_root=config_root, records=observed)
    (output_root / "r15-locked-analysis-surface.json").write_bytes(
        canonical_json(analysis) + b"\n"
    )

    summary = {
        "schema": "sigma-v3-r15-final-closure-v1",
        "confirmatory": True,
        "mandatory_expected_run_units": len(expected),
        "mandatory_observed_run_units": len(observed),
        "mandatory_attacks": sorted(statuses),
        "excluded_exploratory_attacks": sorted(ENGINEERING_ATTACKS),
        "statuses": {
            attack_id: dict(sorted(counter.items()))
            for attack_id, counter in sorted(statuses.items())
        },
        "ledger_root": ledger["root_sha256"],
        "analysis_surface": "r15-locked-analysis-surface.json",
        "integrity_passed": True,
        "interpretation": "PASS denotes campaign completeness/integrity, not a favorable security result.",
    }
    (output_root / "r15-final-summary.json").write_bytes(canonical_json(summary) + b"\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", action="append", type=Path, required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = close_r15(
            dataset_roots=args.dataset,
            config_root=args.configs,
            output_root=args.output,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
