#!/usr/bin/env python3
"""R15-A staged preflight and confirmatory unlock gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from experiments.common import canonical_json, sha256_file
from experiments.r15_data import RunKeyV3
from experiments.r15_stat_adapters import BATTERIES_V3, validate_battery_manifest_entry_v3
from experiments.r141_protocol import (
    R141_FREEZE_ID,
    confirmatory_attack_ids_r141,
)
from scripts.check_r141_freeze import check_r141_freeze
from scripts.prepare_r141_confirmatory import prepare_r141_configs
from scripts.verify_r141_tag import verify_r141_tag

ROOT = Path(__file__).resolve().parents[1]
PREREG = ROOT / "experiments" / "preregistration-v3-r141.md"
LOCK = ROOT / "constraints" / "r14-v3-py313.txt"

UnlockScope = Literal["internal", "stat", "full"]

ENGINEERING_ATTACKS = ("PARAM-04", "PARAM-05", "PARAM-06")
STAT_ATTACKS = ("STAT-01",)
MANDATORY_STAT_BATTERIES = ("nist-sts", "practrand")
INTERNAL_ATTACKS = tuple(
    attack_id
    for attack_id in confirmatory_attack_ids_r141()
    if attack_id not in {*ENGINEERING_ATTACKS, *STAT_ATTACKS}
)
CORE_CONFIRMATORY_ATTACKS = (*INTERNAL_ATTACKS, *STAT_ATTACKS)


def authorized_attacks_for_scope(scope: UnlockScope) -> tuple[str, ...]:
    if scope == "internal":
        return INTERNAL_ATTACKS
    if scope == "stat":
        return STAT_ATTACKS
    if scope == "full":
        return CORE_CONFIRMATORY_ATTACKS
    raise ValueError("unknown R15 unlock scope")


def _validate_host_manifest(path: Path) -> tuple[str, ...]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "sigma-v3-r15-host-manifest-v1":
        raise ValueError("unexpected R15 host manifest schema")
    if value.get("status") != "ready":
        raise ValueError("host manifest must have status=ready")
    hosts = value.get("hosts")
    if not isinstance(hosts, list):
        raise ValueError("host manifest hosts must be a list")
    physical = [host for host in hosts if isinstance(host, dict) and host.get("physical") is True]
    if len(physical) < 3:
        raise ValueError("R15 requires at least three physical hosts")
    ids: list[str] = []
    for host in physical:
        required = {
            "host_id",
            "physical",
            "platform",
            "architecture",
            "cpu",
            "memory_bytes",
            "operator",
            "calibration_notes",
        }
        if set(host) != required:
            raise ValueError("invalid physical host fields")
        host_id = host["host_id"]
        if not isinstance(host_id, str) or not host_id or "FILL-ME" in host_id:
            raise ValueError("physical host_id must be concrete")
        for field in ("platform", "architecture", "cpu", "operator"):
            value_field = host[field]
            if not isinstance(value_field, str) or not value_field or "FILL-ME" in value_field:
                raise ValueError(f"host {host_id} field {field} is not concrete")
        memory = host["memory_bytes"]
        if isinstance(memory, bool) or not isinstance(memory, int) or memory <= 0:
            raise ValueError("host memory_bytes must be positive")
        ids.append(host_id)
    if len(ids) != len(set(ids)):
        raise ValueError("physical host ids must be unique")
    return tuple(sorted(ids))


def _validate_external_tools(path: Path) -> tuple[str, ...]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "sigma-v3-r15-external-tools-v1":
        raise ValueError("unexpected R15 external-tool manifest schema")
    if value.get("status") != "ready":
        raise ValueError("external-tool manifest must have status=ready")
    entries = value.get("batteries")
    if not isinstance(entries, list):
        raise ValueError("external-tool batteries must be a list")
    expected = set(MANDATORY_STAT_BATTERIES)
    observed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("external-tool entry must be an object")
        validate_battery_manifest_entry_v3(entry)
        battery_id = entry["battery_id"]
        assert isinstance(battery_id, str)
        if battery_id in observed:
            raise ValueError("duplicate external battery id")
        observed.add(battery_id)
    if observed != expected:
        raise ValueError(
            f"external battery coverage mismatch: missing={sorted(expected - observed)}, "
            f"extra={sorted(observed - expected)}"
        )
    return tuple(sorted(observed))


def _verify_artifact(runtime: dict[str, object], artifact: Path) -> str:
    digest = sha256_file(artifact)
    artifacts = runtime.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("runtime manifest has no artifacts")
    wheel_entries = {
        name: metadata
        for name, metadata in artifacts.items()
        if isinstance(name, str) and name.endswith(".whl")
    }
    if len(wheel_entries) != 1:
        raise ValueError("runtime manifest must contain exactly one wheel")
    name, metadata = next(iter(wheel_entries.items()))
    if not isinstance(metadata, dict) or metadata.get("sha256") != digest:
        raise ValueError("campaign wheel SHA-256 does not match runtime manifest")
    if artifact.name != name:
        raise ValueError("campaign wheel filename does not match runtime manifest")
    return digest


def _verify_configs(runtime: dict[str, object], root: Path) -> str:
    prepare_r141_configs(root, check=True)
    manifest = root / "config-manifest.json"
    digest = sha256_file(manifest)
    if runtime.get("config_manifest_sha256") != digest:
        raise ValueError("config manifest SHA-256 mismatch")
    expected_files = runtime.get("config_files")
    if not isinstance(expected_files, dict):
        raise ValueError("runtime manifest config_files is invalid")
    for relative, expected in expected_files.items():
        candidate = root / relative
        if not candidate.is_file() or sha256_file(candidate) != expected:
            raise ValueError(f"generated config hash mismatch: {relative}")
    return digest


def _scope_counts(config_root: Path, attack_ids: tuple[str, ...]) -> tuple[int, int]:
    allowed = set(attack_ids)
    cells = 0
    runs = 0
    for path in sorted(config_root.glob("*.json")):
        if path.name in {"campaign-index.json", "config-manifest.json"}:
            continue
        config = json.loads(path.read_text(encoding="utf-8"))
        if config["attack_id"] not in allowed:
            continue
        cells += len(config["cells"])
        runs += sum(int(cell["replicates"]) for cell in config["cells"])
    return cells, runs


def _runkey_root(config_root: Path, attack_ids: tuple[str, ...]) -> str:
    allowed = set(attack_ids)
    digest = hashlib.sha256(b"sigma-v3-r15-expected-runkeys-v1")
    config_paths = sorted(
        path
        for path in config_root.glob("*.json")
        if path.name not in {"campaign-index.json", "config-manifest.json"}
    )
    for path in config_paths:
        config = json.loads(path.read_text(encoding="utf-8"))
        attack_id = config["attack_id"]
        if attack_id not in allowed:
            continue
        for cell in config["cells"]:
            for replicate_id in range(cell["replicates"]):
                key = RunKeyV3(R141_FREEZE_ID, attack_id, cell["cell_id"], replicate_id)
                encoded = key.stable_id.encode("utf-8")
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
    return digest.hexdigest()


def static_r15_preflight() -> dict[str, object]:
    freeze = check_r141_freeze()
    return {
        "schema": "sigma-v3-r15-preflight-static-v2",
        "freeze_id": R141_FREEZE_ID,
        "passed": True,
        "confirmatory_unlocked": False,
        "staged_unlock": True,
        "internal_attacks": list(INTERNAL_ATTACKS),
        "engineering_attacks": list(ENGINEERING_ATTACKS),
        "stat_attacks": list(STAT_ATTACKS),
        "mandatory_confirmatory_attacks": list(CORE_CONFIRMATORY_ATTACKS),
        "mandatory_confirmatory_run_units": 145_088,
        "r141_freeze": freeze,
    }


def _reject_preexisting_confirmatory_data() -> None:
    for root in (
        ROOT / "experiments" / "v3-confirmatory-results",
        ROOT / "results" / "v3-confirmatory",
        ROOT / "results" / "r15",
    ):
        if root.exists() and any(path.is_file() for path in root.rglob("*")):
            raise RuntimeError(f"pre-existing confirmatory data blocks unlock: {root}")


def unlock_r15(
    *,
    runtime_manifest: Path,
    source_freeze: Path,
    config_root: Path,
    artifact: Path,
    output: Path,
    scope: UnlockScope = "full",
    host_manifest: Path | None = None,
    external_tools: Path | None = None,
) -> dict[str, object]:
    runtime = json.loads(runtime_manifest.read_text(encoding="utf-8"))
    if runtime.get("schema") != "sigma-v3-r14-1-runtime-manifest-v1":
        raise ValueError("unexpected R14.1 runtime manifest")
    if runtime.get("freeze_id") != R141_FREEZE_ID:
        raise ValueError("runtime manifest freeze id mismatch")
    if runtime.get("source_freeze_sha256") != sha256_file(source_freeze):
        raise ValueError("source-freeze SHA-256 mismatch")

    source = json.loads(source_freeze.read_text(encoding="utf-8"))
    if source.get("source_commit") != runtime.get("source_commit"):
        raise ValueError("source-freeze commit differs from runtime manifest")

    _reject_preexisting_confirmatory_data()
    tag = verify_r141_tag(runtime_manifest)
    artifact_sha256 = _verify_artifact(runtime, artifact)
    config_sha256 = _verify_configs(runtime, config_root)

    if runtime.get("preregistration_sha256") != sha256_file(PREREG):
        raise ValueError("preregistration SHA-256 mismatch")
    if runtime.get("dependency_lock_sha256") != sha256_file(LOCK):
        raise ValueError("dependency lock SHA-256 mismatch")

    authorized = authorized_attacks_for_scope(scope)
    hosts: tuple[str, ...] = ()
    batteries: tuple[str, ...] = ()
    host_sha256: str | None = None
    tools_sha256: str | None = None

    # PARAM-04/05/06 were reclassified before their execution as
    # exploratory-engineering evidence.  A host manifest may still be supplied
    # for optional engineering provenance, but it is not part of mandatory R15
    # confirmatory closure and does not authorize those attacks.
    if host_manifest is not None:
        hosts = _validate_host_manifest(host_manifest)
        host_sha256 = sha256_file(host_manifest)

    if scope in ("stat", "full"):
        if external_tools is None:
            raise ValueError(f"R15 scope={scope} requires --external-tools")
        batteries = _validate_external_tools(external_tools)
        tools_sha256 = sha256_file(external_tools)

    cells, runs = _scope_counts(config_root, authorized)
    runkey_root = _runkey_root(config_root, authorized)

    result = {
        "schema": "sigma-v3-r15-execution-manifest-v2",
        "freeze_id": R141_FREEZE_ID,
        "scope": scope,
        "source_commit": runtime["source_commit"],
        "source_tree": runtime["source_tree"],
        "tag": tag["tag"],
        "artifact_sha256": artifact_sha256,
        "config_manifest_sha256": config_sha256,
        "preregistration_sha256": runtime["preregistration_sha256"],
        "dependency_lock_sha256": runtime["dependency_lock_sha256"],
        "authorized_attacks": list(authorized),
        "host_ids": list(hosts),
        "host_manifest_sha256": host_sha256,
        "external_batteries": list(batteries),
        "external_tools_sha256": tools_sha256,
        "expected_cells": cells,
        "expected_run_units": runs,
        "expected_runkey_sha256": runkey_root,
        "confirmatory_unlocked": True,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json(result) + b"\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static", action="store_true")
    parser.add_argument(
        "--scope",
        choices=("internal", "stat", "full"),
        default="full",
    )
    parser.add_argument("--runtime-manifest", type=Path)
    parser.add_argument("--source-freeze", type=Path)
    parser.add_argument("--configs", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--host-manifest", type=Path)
    parser.add_argument("--external-tools", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.static:
            result = static_r15_preflight()
        else:
            required = (
                args.runtime_manifest,
                args.source_freeze,
                args.configs,
                args.artifact,
                args.output,
            )
            if any(value is None for value in required):
                parser.error(
                    "unlock requires --runtime-manifest --source-freeze "
                    "--configs --artifact --output"
                )
            assert args.runtime_manifest is not None
            assert args.source_freeze is not None
            assert args.configs is not None
            assert args.artifact is not None
            assert args.output is not None
            result = unlock_r15(
                runtime_manifest=args.runtime_manifest,
                source_freeze=args.source_freeze,
                config_root=args.configs,
                artifact=args.artifact,
                output=args.output,
                scope=args.scope,
                host_manifest=args.host_manifest,
                external_tools=args.external_tools,
            )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
