import csv
import gzip
import json
import subprocess
import sys
from pathlib import Path


def test_exp01_runner_writes_raw_summary_and_manifest(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "experiment": "EXP-01",
                "master_seed": "test-seed",
                "presets": ["lightweight-v2", "simultaneous-v2"],
                "sizes": [0, 65],
                "workers": [1, 2],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "run"
    result = subprocess.run(
        [sys.executable, "-m", "experiments.runner", str(config), str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    with gzip.open(output / "observations.csv.gz", "rt", encoding="utf-8") as source:
        records = list(csv.DictReader(source))
    assert summary["passed"] is True
    assert summary["failures"] == 0
    assert summary["observations"] == len(records)
    assert manifest["master_seed"] == "test-seed"
    assert set(manifest["artifacts"]) == {
        "config.json",
        "observations.csv.gz",
        "summary.json",
    }
    assert (
        json.loads((output / "config.json").read_text(encoding="utf-8"))["master_seed"]
        == "test-seed"
    )
    assert all(record["digest_match"] == "True" for record in records)
