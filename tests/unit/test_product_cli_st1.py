from __future__ import annotations

import json

import pytest
from pathlib import Path

from sigma.product_cli import build_parser
from sigma.tree import ManifestV1, TreeRoot, build_tree


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


def test_provisional_checkpoint_resume_cli(tmp_path: Path, capsys):
    source = tmp_path / "source.bin"
    data = bytes((i * 17 + 3) % 251 for i in range(2 * 65_536 + 123))
    source.write_bytes(data)
    checkpoint_path = tmp_path / "tree.chk"
    root_path = tmp_path / "tree.root"

    parser = build_parser()
    checkpoint_args = parser.parse_args(["checkpoint-tree", str(source), "--offset", str(65_536 + 19), "--output", str(checkpoint_path)])
    assert checkpoint_args.handler(checkpoint_args) == 0
    checkpoint_report = json.loads(capsys.readouterr().out)
    assert checkpoint_report["completed_bytes"] == 65_536 + 19
    assert checkpoint_report["source_hint"] == "heuristic-only"

    resume_args = parser.parse_args(["resume-tree", str(checkpoint_path), str(source), "--require-hint-match", "--output", str(root_path)])
    assert resume_args.handler(resume_args) == 0
    resume_report = json.loads(capsys.readouterr().out)
    assert resume_report["source_hint_match"] is True
    assert resume_report["source_hint_security_evidence"] is False
    assert TreeRoot.from_bytes(root_path.read_bytes()) == build_tree(data)


def test_resume_cli_can_require_heuristic_hint_match(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abcdef")
    checkpoint_path = tmp_path / "tree.chk"

    parser = build_parser()
    checkpoint_args = parser.parse_args(["checkpoint-tree", str(source), "--offset", "3", "--output", str(checkpoint_path)])
    assert checkpoint_args.handler(checkpoint_args) == 0
    source.write_bytes(b"abcXYZ")
    resume_args = parser.parse_args(["resume-tree", str(checkpoint_path), str(source), "--require-hint-match"])
    with pytest.raises(ValueError, match="heuristic"):
        resume_args.handler(resume_args)
