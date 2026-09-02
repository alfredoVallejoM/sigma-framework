import csv
import gzip
import hashlib
import json

import pytest

from scripts.export_distribution_streams import export


def test_distribution_export_preserves_groups_indices_and_bytes(tmp_path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "config.json").write_text(
        json.dumps({"experiment": "EXP-08", "master_seed": "test"}), encoding="utf-8"
    )
    with gzip.open(run / "observations.csv.gz", "wt", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(
            target,
            fieldnames=["construction", "corpus", "domain", "stream", "index", "output_hex"],
        )
        writer.writeheader()
        writer.writerows(
            [
                {
                    "construction": "sha512",
                    "corpus": "counter",
                    "domain": "digest",
                    "stream": 0,
                    "index": 1,
                    "output_hex": "bb",
                },
                {
                    "construction": "sha512",
                    "corpus": "counter",
                    "domain": "digest",
                    "stream": 0,
                    "index": 0,
                    "output_hex": "aa",
                },
                {
                    "construction": "sigma-wide",
                    "corpus": "counter",
                    "domain": "state-0",
                    "stream": 1,
                    "index": 0,
                    "output_hex": "cc",
                },
            ]
        )
    output = tmp_path / "export"
    manifest = export(run, output)
    first = output / "sha512--counter--digest--stream-0000.bin"
    assert first.read_bytes() == b"\xaa\xbb"
    assert manifest["streams"][0]["sha256"] == hashlib.sha256(b"\xaa\xbb").hexdigest()
    assert set(manifest["battery_tools"]) == {"nist-sp-800-22", "practrand", "testu01"}


def test_distribution_export_rejects_non_distribution_run(tmp_path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "config.json").write_text(json.dumps({"experiment": "EXP-07"}), encoding="utf-8")
    (run / "observations.csv.gz").write_bytes(gzip.compress(b""))
    with pytest.raises(ValueError, match="only accepts EXP-08"):
        export(run, tmp_path / "output")
