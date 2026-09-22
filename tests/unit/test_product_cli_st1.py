from __future__ import annotations

import json
from pathlib import Path

from sigma.product_cli import build_parser
from sigma.tree import ManifestV1


def test_provisional_manifest_cli_writes_canonical_wire(tmp_path: Path, capsys):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "x.bin").write_bytes(b"payload")
    output = tmp_path / "manifest.sigma"

    parser = build_parser()
    args = parser.parse_args(["manifest", str(root), "--output", str(output)])
    assert args.handler(args) == 0

    manifest = ManifestV1.from_bytes(output.read_bytes())
    assert [entry.path for entry in manifest.entries] == ["x.bin"]

    report = json.loads(capsys.readouterr().out)
    assert report["entries"] == 1
    assert report["output"] == str(output)
    assert report["symlink_policy"] == "reject"
