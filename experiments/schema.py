"""Closed, versioned configuration schemas for Sigma experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = 1
COMMON_FIELDS = {
    "artifact_path",
    "campaign",
    "execution",
    "experiment",
    "freeze_manifest",
    "master_seed",
    "preregistration",
    "schema_version",
    "suite_family",
}


@dataclass(frozen=True)
class ExperimentSchema:
    fields: frozenset[str]
    required: frozenset[str]


def _schema(fields: str, required: str = "") -> ExperimentSchema:
    return ExperimentSchema(
        frozenset(COMMON_FIELDS | set(fields.split())),
        frozenset({"experiment", "master_seed", "schema_version"} | set(required.split())),
    )


SCHEMAS = {
    "EXP-01": _schema(
        "presets sizes size_ranges state_count target_round workers independent_max_bytes max_in_memory_bytes",
        "presets sizes workers",
    ),
    "EXP-02": _schema(
        "anchor_multipliers constructions max_candidates repetitions resource_note state_counts target_rounds widths",
        "anchor_multipliers constructions max_candidates repetitions state_counts target_rounds widths",
    ),
    "EXP-03": _schema(
        "anchor_relations constructions segments trials widths",
        "anchor_relations constructions segments trials widths",
    ),
    "EXP-04": _schema(
        "branch_counts constructions faults max_candidates repetitions widths",
        "branch_counts constructions faults max_candidates repetitions widths",
    ),
    "EXP-05": _schema(
        "bic_output_stride component_bit_stride include_round_components input_bit_stride message_bytes preset samples state_count structural_interventions target_round",
        "component_bit_stride input_bit_stride message_bytes samples state_count target_round",
    ),
    "EXP-06": _schema(
        "candidate_counts candidate_workers message_bytes profiles repetitions state_counts target_rounds",
        "candidate_counts candidate_workers message_bytes profiles repetitions state_counts target_rounds",
    ),
    "EXP-07": _schema(
        "bic_output_stride detectable_bias family_alpha input_bit_stride message_bytes preset samples state_count target_round",
        "detectable_bias family_alpha input_bit_stride message_bytes samples state_count target_round",
    ),
    "EXP-08": _schema(
        "constructions corpora message_bytes messages streams",
        "constructions corpora message_bytes messages streams",
    ),
    "EXP-09": _schema(
        "constructions operations processes repetitions sizes warmups",
        "constructions operations processes repetitions sizes warmups",
    ),
    "EXP-10": _schema(
        "io_chunks profiles repetitions sizes state_counts target_rounds timeout_seconds trace_policies workers",
        "io_chunks profiles repetitions sizes state_counts target_rounds timeout_seconds trace_policies workers",
    ),
    "EXP-11": _schema(
        "challenge_modes max_attempts nonce_worker_counts parallel_target_round parallel_trials state_counts target_round target_rounds total_difficulty_bits trials",
        "max_attempts total_difficulty_bits trials",
    ),
    "EXP-12": _schema(
        "candidates memory_kib modes parallelism repetitions time_cost",
        "candidates memory_kib modes parallelism repetitions time_cost",
    ),
    "EXP-14": _schema(
        "message_bytes presets state_count target_round trials",
        "message_bytes presets state_count target_round trials",
    ),
    "EXP-17": _schema(
        "anchor_counts chain_length distinguished_bits repetitions strategies table_entries widths",
        "anchor_counts chain_length distinguished_bits repetitions strategies table_entries widths",
    ),
    "EXP-18": _schema(
        "branch_counts faults max_candidates repetitions state_counts target_rounds widths",
        "branch_counts faults max_candidates repetitions state_counts target_rounds widths",
    ),
    "EXP-19": _schema(
        "anchor_multipliers commitments max_candidates repetitions state_counts target_rounds widths",
        "anchor_multipliers commitments max_candidates repetitions state_counts target_rounds widths",
    ),
    "EXP-20": _schema(
        "anchor_multipliers attackers constructions games max_candidates repetitions state_counts target_counts target_kinds widths",
        "anchor_multipliers attackers constructions games max_candidates repetitions state_counts target_counts target_kinds widths",
    ),
    "EXP-21": _schema("presets", "presets"),
}

BOOLEAN_FIELDS = {"include_round_components", "structural_interventions"}
POSITIVE_INTEGER_FIELDS = {
    "bic_output_stride",
    "candidates",
    "chain_length",
    "component_bit_stride",
    "distinguished_bits",
    "independent_max_bytes",
    "input_bit_stride",
    "max_candidates",
    "max_in_memory_bytes",
    "message_bytes",
    "messages",
    "parallel_target_round",
    "parallel_trials",
    "repetitions",
    "samples",
    "state_count",
    "target_round",
    "timeout_seconds",
    "total_difficulty_bits",
    "trials",
    "warmups",
    "parallelism",
    "processes",
    "streams",
    "table_entries",
}
LIST_FIELDS = {
    "anchor_counts",
    "anchor_multipliers",
    "anchor_relations",
    "attackers",
    "branch_counts",
    "candidate_counts",
    "candidate_workers",
    "challenge_modes",
    "collision_widths",
    "commitments",
    "constructions",
    "corpora",
    "faults",
    "games",
    "io_chunks",
    "memory_kib",
    "modes",
    "nonce_worker_counts",
    "operations",
    "presets",
    "profiles",
    "size_ranges",
    "sizes",
    "segments",
    "state_counts",
    "strategies",
    "target_counts",
    "target_kinds",
    "target_rounds",
    "time_cost",
    "trace_policies",
    "widths",
    "workers",
}

ACTIVE_PRESETS = {
    "lightweight-v2-2",
    "paranoid-deep-v2-2",
    "paranoid-deep-vector-v2-2",
    "paranoid-wide-v2-2",
    "reference-v2-2",
    "simultaneous-v2-2",
}
NONNEGATIVE_INTEGER_LIST_FIELDS = {"sizes"}
POSITIVE_INTEGER_LIST_FIELDS = {
    "anchor_counts",
    "anchor_multipliers",
    "branch_counts",
    "candidate_counts",
    "candidate_workers",
    "io_chunks",
    "memory_kib",
    "nonce_worker_counts",
    "segments",
    "state_counts",
    "target_counts",
    "target_rounds",
    "time_cost",
    "widths",
    "workers",
}
ENUM_LIST_FIELDS: dict[tuple[str, str], set[str]] = {
    ("EXP-02", "constructions"): {
        "stationary-single",
        "stationary-consecutive",
        "indexed-single",
        "indexed-consecutive",
        "anchored-single",
        "anchored-consecutive",
        "anchored-indexed-single",
        "anchored-indexed-consecutive",
    },
    ("EXP-03", "anchor_relations"): {"same", "different"},
    ("EXP-03", "constructions"): {"stationary", "indexed", "anchored", "anchored-indexed"},
    ("EXP-04", "constructions"): {
        "single-branch",
        "concat-wide",
        "cross-wide",
        "cross-only",
        "psi-compressed",
        "single-fold",
        "narrow-fold",
        "constant-fold",
        "deep-vector",
    },
    ("EXP-04", "faults"): {
        "normal",
        "constant-first",
        "collidable-first",
        "truncated-first",
        "correlated-first-two",
        "permuted",
        "omitted-last",
    },
    ("EXP-06", "profiles"): {"wide-once", "deep", "deep-vector"},
    ("EXP-08", "constructions"): {
        "sha512",
        "blake2b-512",
        "sigma-wide",
        "sigma-cross",
        "sigma-deep",
        "sigma-deep-vector",
    },
    ("EXP-08", "corpora"): {"counter", "adversarial-ff-tail", "adversarial-alternating"},
    ("EXP-09", "constructions"): {
        "sha512",
        "blake2b-512",
        "concat-branches",
        "sigma-wide",
        "sigma-cross",
        "sigma-deep",
        "sigma-deep-vector",
    },
    ("EXP-09", "operations"): {
        "full-hash",
        "file-hash",
        "file-hot",
        "file-cold",
        "anchor",
        "rounds",
        "serialization",
        "verification",
        "local-verification",
    },
    ("EXP-10", "profiles"): {
        "wide-v2-2",
        "cross-wide-v2-2",
        "deep-v2-2",
        "deep-vector-v2-2",
        "tree-wide-v2-2",
        "parallel-tree-v2-2",
    },
    ("EXP-10", "trace_policies"): {"none", "full"},
    ("EXP-11", "challenge_modes"): {"unique", "reused"},
    ("EXP-12", "modes"): {
        "argon2id",
        "argon2id+wide",
        "argon2id+deep",
        "argon2id+deep-vector",
    },
    ("EXP-17", "strategies"): {
        "direct-table",
        "distinguished-points",
        "rho",
        "hellman",
        "rainbow",
        "multicollision",
    },
    ("EXP-18", "faults"): {
        "normal",
        "constant-first",
        "correlated-first-two",
        "omitted-last",
        "permuted",
        "constant-fold",
    },
    ("EXP-19", "commitments"): {"one-state", "multi-state", "anchor-and-states"},
    ("EXP-20", "attackers"): {"random-search", "exhaustive", "inversion-table"},
    ("EXP-20", "constructions"): {"simple", "reinjected", "deep-vector"},
    ("EXP-20", "games"): {"preimage", "second-preimage", "multi-target"},
    ("EXP-20", "target_kinds"): {"regular-image", "uniform"},
}


def _validate_list_values(experiment: str, field: str, value: list[object]) -> None:
    if field == "presets" and any(
        not isinstance(item, str) or item not in ACTIVE_PRESETS for item in value
    ):
        raise ValueError(f"{field} contains an unsupported v2.2 preset")
    allowed = ENUM_LIST_FIELDS.get((experiment, field))
    if allowed is not None and any(
        not isinstance(item, str) or item not in allowed for item in value
    ):
        raise ValueError(f"{field} contains an unsupported value")
    if field in NONNEGATIVE_INTEGER_LIST_FIELDS and any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value
    ):
        raise ValueError(f"{field} must contain non-negative integers")
    if field in POSITIVE_INTEGER_LIST_FIELDS and any(
        isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in value
    ):
        raise ValueError(f"{field} must contain positive integers")


def _validate_execution(value: object, allowed: frozenset[str]) -> None:
    if not isinstance(value, dict):
        raise ValueError("execution must be an object")
    unknown = set(value) - {"require_clean_tag", "tasks", "timeout_seconds"}
    if unknown:
        raise ValueError(f"unknown execution fields: {sorted(unknown)}")
    if "require_clean_tag" in value and not isinstance(value["require_clean_tag"], bool):
        raise ValueError("execution.require_clean_tag must be boolean")
    timeout = value.get("timeout_seconds")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
    ):
        raise ValueError("execution.timeout_seconds must be positive")
    tasks = value.get("tasks")
    if tasks is None:
        return
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("execution.tasks must be a non-empty list")
    labels: set[str] = set()
    for task in tasks:
        if not isinstance(task, dict) or set(task) - {"label", "overrides"}:
            raise ValueError("execution task has unknown fields")
        label = task.get("label")
        overrides = task.get("overrides", {})
        if not isinstance(label, str) or not label or label in labels:
            raise ValueError("execution task labels must be unique non-empty strings")
        labels.add(label)
        if not isinstance(overrides, dict) or set(overrides) - allowed:
            raise ValueError("execution task overrides contain unknown fields")
        if set(overrides) & {"experiment", "master_seed", "schema_version"}:
            raise ValueError("execution tasks cannot override schema identity")


def validate_config(config: object) -> dict[str, Any]:
    """Validate a configuration completely before any output path is created."""

    if not isinstance(config, dict):
        raise ValueError("config must be an object")
    experiment = config.get("experiment")
    if experiment not in SCHEMAS:
        raise ValueError(f"unsupported experiment: {experiment!r}")
    schema = SCHEMAS[experiment]
    unknown = set(config) - schema.fields
    if unknown:
        raise ValueError(f"unknown {experiment} config fields: {sorted(unknown)}")
    missing = schema.required - set(config)
    if missing:
        raise ValueError(f"missing {experiment} config fields: {sorted(missing)}")
    if config["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported experiment schema version: {config['schema_version']!r}")
    if not isinstance(config["master_seed"], str) or not config["master_seed"]:
        raise ValueError("master_seed must be non-empty text")
    for field in BOOLEAN_FIELDS & set(config):
        if not isinstance(config[field], bool):
            raise ValueError(f"{field} must be boolean")
    for field in POSITIVE_INTEGER_FIELDS & set(config):
        value = config[field]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{field} must be a positive integer")
    for field in LIST_FIELDS & set(config):
        value = config[field]
        if not isinstance(value, list):
            raise ValueError(f"{field} must be a list")
        task_overrides = (
            config.get("execution", {}).get("tasks", [])
            if isinstance(config.get("execution"), dict)
            else []
        )
        supplied_by_task = any(
            isinstance(task, dict)
            and isinstance(task.get("overrides"), dict)
            and field in task["overrides"]
            for task in task_overrides
        )
        if not value and not supplied_by_task:
            raise ValueError(f"{field} must be non-empty")
        _validate_list_values(str(experiment), field, value)
    if "preset" in config and (
        not isinstance(config["preset"], str) or config["preset"] not in ACTIVE_PRESETS
    ):
        raise ValueError("preset must select an active v2.2 preset")
    if experiment in {"EXP-05", "EXP-07"} and "preset" not in config:
        execution = config.get("execution")
        tasks = execution.get("tasks") if isinstance(execution, dict) else None
        if (
            not isinstance(tasks, list)
            or not tasks
            or any(
                not isinstance(task, dict)
                or not isinstance(task.get("overrides"), dict)
                or "preset" not in task["overrides"]
                for task in tasks
            )
        ):
            raise ValueError(f"{experiment} requires preset in every effective task")
    if experiment == "EXP-20":
        games = config.get("games")
        target_kinds = config.get("target_kinds")
        target_counts = config.get("target_counts")
        if games == ["second-preimage"] and target_kinds == ["uniform"]:
            raise ValueError("EXP-20 second-preimage requires a regular-image target")
        if (
            isinstance(games, list)
            and len(games) == 1
            and games[0] != "multi-target"
            and target_counts != [1]
        ):
            raise ValueError("EXP-20 non-multi-target games require target_counts=[1]")
    for field in {"family_alpha", "detectable_bias"} & set(config):
        value = config[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < 1:
            raise ValueError(f"{field} must be between zero and one")
    for field in {"artifact_path", "campaign", "freeze_manifest", "suite_family"} & set(config):
        if not isinstance(config[field], str) or not config[field]:
            raise ValueError(f"{field} must be non-empty text")
    if config.get("campaign", "").startswith("confirmatory"):
        if config.get("suite_family") != "v2-2":
            raise ValueError("confirmatory config must select suite_family v2-2")
        if not isinstance(config.get("artifact_path"), str) or not config["artifact_path"]:
            raise ValueError("confirmatory config requires artifact_path")
        preregistration = config.get("preregistration")
        if not isinstance(preregistration, dict) or set(preregistration) != {
            "path",
            "sha256",
            "status",
        }:
            raise ValueError("confirmatory config requires frozen preregistration fields")
        if (
            not isinstance(preregistration["path"], str)
            or not preregistration["path"]
            or not isinstance(preregistration["sha256"], str)
            or len(preregistration["sha256"]) != 64
            or preregistration["status"] != "frozen"
        ):
            raise ValueError("confirmatory config requires a frozen preregistration binding")
        if not isinstance(config.get("freeze_manifest"), str) or not config["freeze_manifest"]:
            raise ValueError("confirmatory config requires freeze_manifest")
    if "execution" in config:
        _validate_execution(config["execution"], schema.fields)
    return config


__all__ = ["SCHEMAS", "SCHEMA_VERSION", "ExperimentSchema", "validate_config"]
