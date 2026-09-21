#!/usr/bin/env python3
"""Generate the review-approved v2.2 confirmatory configs from final pilots."""

from __future__ import annotations

import argparse
import copy
import itertools
import json
from pathlib import Path
from typing import Any

from experiments.common import canonical_json, sha256_file
from experiments.freeze import preregistration_is_frozen
from experiments.runner import _task_plan
from experiments.schema import validate_config


def _without_tasks(config: dict[str, Any], *, timeout: int = 3600) -> dict[str, Any]:
    config.pop("execution", None)
    config["execution"] = {"timeout_seconds": timeout}
    return config


def _partition(
    config: dict[str, Any],
    dimensions: tuple[str, ...],
    *,
    valid: Any = None,
) -> None:
    """Partition every declared parameter cell while keeping repeats inside a task."""

    values = [list(config[field]) for field in dimensions]
    tasks = []
    for combination in itertools.product(*values):
        cell = dict(zip(dimensions, combination, strict=True))
        if valid is not None and not valid(cell):
            continue
        overrides = {field: [value] for field, value in cell.items()}
        label = "__".join(f"{field}={value}" for field, value in cell.items())
        tasks.append({"label": label, "overrides": overrides})
    if not tasks:
        raise ValueError("confirmatory partition produced no tasks")
    for field in dimensions:
        config[field] = []
    execution = config.setdefault("execution", {"timeout_seconds": 14_400})
    execution["tasks"] = tasks


def _designs(pilot_root: Path) -> dict[str, dict[str, Any]]:
    designs: dict[str, dict[str, Any]] = {}
    for path in sorted(pilot_root.glob("*.json")):
        designs[path.name] = copy.deepcopy(json.loads(path.read_text(encoding="utf-8")))

    c = designs["exp01r-v2-2.json"]
    c.update({"workers": [1, 2, 3, 4, 8], "independent_max_bytes": 1_048_576})
    sizes = [
        0,
        1,
        63,
        64,
        65,
        65_535,
        65_536,
        65_537,
        1_048_576,
        16_777_216,
        268_435_456,
        1_073_741_824,
    ]
    c["presets"] = [
        "reference-v2-2",
        "lightweight-v2-2",
        "simultaneous-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    ]
    c["sizes"] = sizes
    c["execution"] = {"timeout_seconds": 14_400}
    _partition(c, ("presets", "sizes"))

    c = _without_tasks(designs["exp02r-controls.json"], timeout=14_400)
    c.update(widths=[4, 6, 8, 10, 12], repetitions=64, max_candidates=1_048_576)
    _partition(
        c, ("widths", "state_counts", "target_rounds", "anchor_multipliers", "constructions")
    )

    c = _without_tasks(designs["exp03r-controls.json"], timeout=14_400)
    c.update(widths=[4, 6, 8], trials=65_536)
    _partition(c, ("widths", "segments", "constructions", "anchor_relations"))

    c = _without_tasks(designs["exp04r-fault-matrix.json"], timeout=14_400)
    c.update(widths=[4, 6, 8], branch_counts=[2, 3, 4], repetitions=32, max_candidates=65_536)
    _partition(c, ("widths", "branch_counts", "faults", "constructions"))

    c = designs["exp05r-modes.json"]
    c.update(
        message_bytes=64,
        samples=32,
        input_bit_stride=1,
        component_bit_stride=8,
        target_round=4,
        state_count=3,
    )
    c["execution"]["timeout_seconds"] = 14_400

    c = _without_tasks(designs["exp06r-work-span.json"], timeout=14_400)
    c.update(
        target_rounds=[1, 4, 16, 64],
        state_counts=[1, 2, 4],
        candidate_counts=[1, 4, 16, 64],
        candidate_workers=[1, 2, 4, 8],
        repetitions=30,
    )
    _partition(
        c,
        ("profiles", "target_rounds", "state_counts", "candidate_counts", "candidate_workers"),
    )

    c = designs["exp07r-sac-bic.json"]
    c.update(
        message_bytes=64,
        samples=700,
        input_bit_stride=1,
        bic_output_stride=8,
        target_round=4,
        state_count=3,
    )
    c["execution"]["timeout_seconds"] = 14_400

    c = _without_tasks(designs["exp08r-independent-streams.json"], timeout=28_800)
    c.update(message_bytes=64, messages=524_288, streams=32)
    _partition(c, ("constructions", "corpora"))

    c = _without_tasks(designs["exp09r-operation-matrix.json"], timeout=14_400)
    c.update(
        operations=[
            "full-hash",
            "file-hot",
            "file-cold",
            "anchor",
            "rounds",
            "serialization",
            "verification",
            "local-verification",
        ],
        sizes=[0, 64, 4_096, 1_048_576, 16_777_216],
        repetitions=50,
        warmups=10,
    )
    sigma_constructions = {
        "sigma-wide",
        "sigma-cross",
        "sigma-deep",
        "sigma-deep-vector",
    }
    file_or_full = {"full-hash", "file-hot", "file-cold"}
    _partition(
        c,
        ("constructions", "operations", "sizes"),
        valid=lambda cell: (
            cell["constructions"] in sigma_constructions or cell["operations"] in file_or_full
        ),
    )

    c = _without_tasks(designs["exp10-lib02.json"], timeout=14_400)
    c.update(repetitions=10)
    _partition(c, ("profiles", "target_rounds", "state_counts", "trace_policies"))

    c = _without_tasks(designs["exp10r-memory-matrix.json"], timeout=14_400)
    c.update(
        sizes=[0, 65_536, 1_048_576, 16_777_216, 268_435_456],
        target_rounds=[1, 16, 256],
        state_counts=[1, 2, 4],
        workers=[1, 2, 4, 8],
        repetitions=10,
    )
    profiles = list(c["profiles"])
    sizes_10 = list(c["sizes"])
    rounds_10 = list(c["target_rounds"])
    states_10 = list(c["state_counts"])
    traces_10 = list(c["trace_policies"])
    workers_10 = list(c["workers"])
    tasks_10 = []
    for profile, size, target_round, state_count, trace in itertools.product(
        profiles, sizes_10, rounds_10, states_10, traces_10
    ):
        applicable_workers = workers_10 if profile == "parallel-tree-v2-2" else [1]
        for worker in applicable_workers:
            values = (profile, size, target_round, state_count, trace, worker)
            fields = (
                "profiles",
                "sizes",
                "target_rounds",
                "state_counts",
                "trace_policies",
                "workers",
            )
            tasks_10.append(
                {
                    "label": "__".join(
                        f"{field}={value}" for field, value in zip(fields, values, strict=True)
                    ),
                    "overrides": {
                        field: [value] for field, value in zip(fields, values, strict=True)
                    },
                }
            )
    for field in (
        "profiles",
        "sizes",
        "target_rounds",
        "state_counts",
        "trace_policies",
        "workers",
    ):
        c[field] = []
    c["execution"]["tasks"] = tasks_10

    c = _without_tasks(designs["exp11r-protocol-attacks.json"], timeout=14_400)
    c.update(
        max_attempts=262_144,
        target_rounds=[1, 4, 16],
        state_counts=[1, 2, 4],
        total_difficulty_bits=12,
        trials=256,
    )
    _partition(c, ("challenge_modes", "target_rounds", "state_counts"))

    c = _without_tasks(designs["exp11r-parallel-nonces.json"], timeout=14_400)
    c.update(
        max_attempts=262_144,
        nonce_worker_counts=[1, 2, 4, 8],
        parallel_target_round=4,
        parallel_trials=64,
        total_difficulty_bits=16,
        trials=64,
    )
    _partition(c, ("challenge_modes", "target_rounds", "state_counts", "nonce_worker_counts"))

    c = _without_tasks(designs["exp12r-mode-budget.json"], timeout=14_400)
    c.update(candidates=32, memory_kib=[19_456, 65_536], repetitions=20, time_cost=[2, 3])
    _partition(c, ("modes", "memory_kib", "time_cost"))

    c = _without_tasks(designs["exp14r-fault-matrix.json"], timeout=14_400)
    c.update(trials=256)
    _partition(c, ("presets",))

    c = _without_tasks(designs["exp17r-attacker-frontier.json"], timeout=14_400)
    c.update(
        widths=[8, 12, 16],
        anchor_counts=[2, 4, 8],
        table_entries=1_024,
        chain_length=64,
        distinguished_bits=4,
        repetitions=64,
    )
    _partition(c, ("strategies", "widths", "anchor_counts"))

    c = _without_tasks(designs["exp18r-fold-vector-segments.json"], timeout=14_400)
    c.update(widths=[4, 6, 8, 10], state_counts=[1, 2, 4], repetitions=32, max_candidates=65_536)
    _partition(c, ("widths", "branch_counts", "faults", "state_counts", "target_rounds"))

    c = _without_tasks(designs["exp19r-signed-reuse.json"], timeout=14_400)
    c.update(widths=[4, 6, 8, 10], repetitions=32, max_candidates=65_536)
    _partition(c, ("widths", "commitments", "state_counts", "target_rounds", "anchor_multipliers"))

    c = _without_tasks(designs["exp20r-preimage-games.json"], timeout=14_400)
    c.update(
        widths=[3, 5, 7, 9],
        state_counts=[1, 2, 4],
        target_counts=[1, 4, 16],
        repetitions=32,
        max_candidates=65_536,
    )
    _partition(
        c,
        (
            "widths",
            "anchor_multipliers",
            "state_counts",
            "target_counts",
            "games",
            "attackers",
            "target_kinds",
            "constructions",
        ),
        valid=lambda cell: (
            (cell["games"] != "second-preimage" or cell["target_kinds"] == "regular-image")
            and (cell["games"] == "multi-target" or cell["target_counts"] == 1)
        ),
    )

    _without_tasks(designs["exp21r-domains.json"], timeout=14_400)
    return designs


def prepare(
    preregistration: Path,
    pilot_root: Path,
    output: Path,
    artifact_path: str,
    freeze_manifest: Path | None = None,
) -> list[Path]:
    """Write complete configs only after explicit human freeze of the protocol."""

    text = preregistration.read_text(encoding="utf-8")
    if not preregistration_is_frozen(text):
        raise ValueError("preregistration must explicitly declare Status: **frozen**")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory is not empty: {output}")
    if not artifact_path or not artifact_path.endswith(".whl"):
        raise ValueError("artifact_path must identify the campaign wheel")
    designs = _designs(pilot_root)
    if len(designs) != 20:
        raise ValueError(f"expected exactly 20 current designs, found {len(designs)}")
    preregistration_hash = sha256_file(preregistration)
    freeze_path = freeze_manifest or output / "freeze.json"
    output.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, config in sorted(designs.items()):
        config.update(
            artifact_path=artifact_path,
            campaign="confirmatory-v2-2",
            freeze_manifest=str(freeze_path),
            preregistration={
                "path": str(preregistration),
                "sha256": preregistration_hash,
                "status": "frozen",
            },
            suite_family="v2-2",
        )
        config["master_seed"] = config["master_seed"].replace("pilot", "confirmatory")
        validate_config(config)
        # Materialize and validate every effective cell before writing any
        # campaign configuration.  Base-schema validation alone cannot catch
        # invalid values introduced by a task override.
        _task_plan(config)
        path = output / filename
        path.write_bytes(canonical_json(config) + b"\n")
        written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--pilot-root", type=Path, default=Path("experiments/configs/pilots"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-path", required=True)
    parser.add_argument(
        "--freeze-manifest",
        type=Path,
        help="manifest path embedded in configs (defaults to OUTPUT/freeze.json)",
    )
    args = parser.parse_args()
    try:
        written = prepare(
            args.preregistration,
            args.pilot_root,
            args.output,
            args.artifact_path,
            args.freeze_manifest,
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"configs": [str(path) for path in written]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
