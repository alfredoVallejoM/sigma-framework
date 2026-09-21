from __future__ import annotations

import hashlib
import json
from pathlib import Path

from experiments.common import sha256_file
from experiments.r141_protocol import R141_FREEZE_ID, R141_TAG
from scripts.prepare_r141_confirmatory import prepare_r141_configs
from scripts.r15_preflight import (
    INTERNAL_ATTACKS,
    PHYSICAL_ATTACKS,
    STAT_ATTACKS,
    authorized_attacks_for_scope,
    unlock_r15,
)


def _host_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "sigma-v3-r15-host-manifest-v1",
                "status": "ready",
                "required_physical_hosts": 3,
                "hosts": [
                    {
                        "host_id": f"HOST-{index}",
                        "physical": True,
                        "platform": "linux",
                        "architecture": "x86_64",
                        "cpu": f"fixture-cpu-{index}",
                        "memory_bytes": 16 * 1024**3,
                        "operator": "fixture",
                        "calibration_notes": "fixture only",
                    }
                    for index in range(1, 4)
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _tool_manifest(path: Path) -> None:
    battery_ids = (
        "nist-sts",
        "practrand",
        "testu01-smallcrush",
        "testu01-crush",
    )
    path.write_text(
        json.dumps(
            {
                "schema": "sigma-v3-r15-external-tools-v1",
                "status": "ready",
                "batteries": [
                    {
                        "battery_id": battery_id,
                        "version": "fixture-1",
                        "binary_sha256": hashlib.sha256(battery_id.encode("ascii")).hexdigest(),
                        "command": [battery_id, "--fixture"],
                        "transport": "fixture",
                    }
                    for battery_id in battery_ids
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_full_r15_preflight_emits_exact_execution_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_root = tmp_path / "configs"
    prepare_r141_configs(config_root)

    source_freeze = tmp_path / "source-freeze.json"
    source_commit = "1" * 40
    source_tree = "2" * 40
    source_freeze.write_text(
        json.dumps(
            {
                "schema": "sigma-v3-r14-1-source-freeze-v1",
                "freeze_id": R141_FREEZE_ID,
                "source_commit": source_commit,
                "source_tree": source_tree,
                "confirmatory_executed": False,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    wheel = tmp_path / "sigma_framework-3.0.0a1-py3-none-any.whl"
    wheel.write_bytes(b"fixture-wheel")
    config_files = {path.name: sha256_file(path) for path in sorted(config_root.glob("*.json"))}

    from scripts import r15_preflight

    prereg_hash = sha256_file(r15_preflight.PREREG)
    lock_hash = sha256_file(r15_preflight.LOCK)
    runtime = tmp_path / "runtime.json"
    runtime.write_text(
        json.dumps(
            {
                "schema": "sigma-v3-r14-1-runtime-manifest-v1",
                "freeze_id": R141_FREEZE_ID,
                "source_commit": source_commit,
                "source_tree": source_tree,
                "source_freeze_sha256": sha256_file(source_freeze),
                "preregistration_sha256": prereg_hash,
                "dependency_lock_sha256": lock_hash,
                "config_manifest_sha256": sha256_file(config_root / "config-manifest.json"),
                "config_files": config_files,
                "artifacts": {
                    wheel.name: {
                        "sha256": sha256_file(wheel),
                        "size": wheel.stat().st_size,
                    }
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    hosts = tmp_path / "hosts.json"
    tools = tmp_path / "tools.json"
    _host_manifest(hosts)
    _tool_manifest(tools)

    monkeypatch.setattr(
        r15_preflight,
        "verify_r141_tag",
        lambda _runtime: {
            "schema": "sigma-v3-r14-1-tag-check-v1",
            "tag": R141_TAG,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "passed": True,
        },
    )

    output = tmp_path / "execution-manifest.json"
    result = unlock_r15(
        runtime_manifest=runtime,
        source_freeze=source_freeze,
        config_root=config_root,
        artifact=wheel,
        host_manifest=hosts,
        external_tools=tools,
        output=output,
    )
    assert result["confirmatory_unlocked"] is True
    assert result["expected_run_units"] == 153_536
    expected_cells = result["expected_cells"]
    assert isinstance(expected_cells, int) and expected_cells > 200
    host_ids = result["host_ids"]
    batteries = result["external_batteries"]
    runkey_sha256 = result["expected_runkey_sha256"]
    assert isinstance(host_ids, list) and len(host_ids) == 3
    assert isinstance(batteries, list) and len(batteries) == 4
    assert isinstance(runkey_sha256, str) and len(runkey_sha256) == 64
    assert json.loads(output.read_text(encoding="utf-8")) == result



def test_staged_unlock_scopes_partition_confirmatory_attacks() -> None:
    internal = set(authorized_attacks_for_scope("internal"))
    physical = set(authorized_attacks_for_scope("physical"))
    stat = set(authorized_attacks_for_scope("stat"))
    full = set(authorized_attacks_for_scope("full"))
    assert internal == set(INTERNAL_ATTACKS)
    assert physical == set(PHYSICAL_ATTACKS) == {"PARAM-04", "PARAM-05", "PARAM-06"}
    assert stat == set(STAT_ATTACKS) == {"STAT-01"}
    assert not (internal & physical)
    assert not (internal & stat)
    assert not (physical & stat)
    assert internal | physical | stat == full
    assert len(internal) == 17
