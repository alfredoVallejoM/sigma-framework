"""Provisional product CLI for Sigma structural workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from sigma.interop.cli_oci import add_oci_commands
from sigma.tree import (
    SymlinkPolicy,
    TreeBuilder,
    build_directory_manifest,
    checkpoint_builder,
    read_checkpoint,
    restore_builder,
    source_hint_from_path,
    source_hint_matches_path,
    write_checkpoint_atomic,
)


def _manifest_command(args: argparse.Namespace) -> int:
    policy = SymlinkPolicy.TEXT if args.allow_symlinks else SymlinkPolicy.REJECT
    manifest = build_directory_manifest(args.directory, symlink_policy=policy)
    encoded = manifest.to_bytes()

    if args.output is not None:
        args.output.write_bytes(encoded)
        print(
            json.dumps(
                {
                    "entries": len(manifest.entries),
                    "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                    "output": str(args.output),
                    "symlink_policy": policy.value,
                },
                sort_keys=True,
            )
        )
        return 0

    if args.format == "binary":
        sys.stdout.buffer.write(encoded)
    elif args.format == "json":
        print(
            json.dumps(
                {
                    "entries": len(manifest.entries),
                    "manifest_hex": encoded.hex(),
                    "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                    "symlink_policy": policy.value,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(encoded.hex())
    return 0


def _checkpoint_tree_command(args: argparse.Namespace) -> int:
    size = args.file.stat().st_size
    offset = size if args.offset is None else args.offset
    if offset < 0 or offset > size:
        raise ValueError("checkpoint offset must be within the current file")

    builder = TreeBuilder()
    remaining = offset
    with args.file.open("rb") as handle:
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("file ended before requested checkpoint offset")
            builder.update(chunk)
            remaining -= len(chunk)

    hint = source_hint_from_path(args.file)
    checkpoint = checkpoint_builder(builder, source_hint=hint)
    write_checkpoint_atomic(args.output, checkpoint)
    encoded = checkpoint.to_bytes()
    print(
        json.dumps(
            {
                "checkpoint": str(args.output),
                "checkpoint_sha256": hashlib.sha256(encoded).hexdigest(),
                "completed_bytes": checkpoint.completed_bytes,
                "completed_leaf_count": checkpoint.completed_leaf_count,
                "frontier_nodes": len(checkpoint.frontier.nodes),
                "tail_bytes": len(checkpoint.tail),
                "source_hint": "heuristic-only",
            },
            sort_keys=True,
        )
    )
    return 0


def _resume_tree_command(args: argparse.Namespace) -> int:
    checkpoint = read_checkpoint(args.checkpoint)
    size = args.file.stat().st_size
    if checkpoint.completed_bytes > size:
        raise ValueError("checkpoint offset exceeds current file size")

    hint_match = (
        source_hint_matches_path(checkpoint.source_hint, args.file)
        if checkpoint.source_hint is not None
        else None
    )
    if args.require_hint_match and hint_match is not True:
        raise ValueError("source hint mismatch; hint is heuristic and does not prove source identity")

    builder = restore_builder(checkpoint)
    with args.file.open("rb") as handle:
        handle.seek(checkpoint.completed_bytes)
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            builder.update(chunk)
    root = builder.finalize()
    encoded = root.to_bytes()

    if args.output is not None:
        args.output.write_bytes(encoded)

    print(
        json.dumps(
            {
                "completed_from_checkpoint": checkpoint.completed_bytes,
                "file": str(args.file),
                "root_sha256": hashlib.sha256(encoded).hexdigest(),
                "root_wire_hex": None if args.output is not None else encoded.hex(),
                "output": str(args.output) if args.output is not None else None,
                "source_hint_match": hint_match,
                "source_hint_security_evidence": False,
            },
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigma",
        description="Sigma product utilities; cryptographic security claims remain profile-specific",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser("manifest", help="build a canonical Sigma Manifest V1")
    manifest.add_argument("directory", type=Path)
    manifest.add_argument("--allow-symlinks", action="store_true")
    manifest.add_argument("--output", type=Path)
    manifest.add_argument("--format", choices=("hex", "json", "binary"), default="hex")
    manifest.set_defaults(handler=_manifest_command)

    checkpoint = commands.add_parser(
        "checkpoint-tree",
        help="write a portable Sigma Tree V1 checkpoint for a file prefix",
    )
    checkpoint.add_argument("file", type=Path)
    checkpoint.add_argument("--offset", type=int)
    checkpoint.add_argument("--output", type=Path, required=True)
    checkpoint.set_defaults(handler=_checkpoint_tree_command)

    resume = commands.add_parser(
        "resume-tree",
        help="resume Sigma Tree V1 from a portable checkpoint",
    )
    resume.add_argument("checkpoint", type=Path)
    resume.add_argument("file", type=Path)
    resume.add_argument("--output", type=Path)
    resume.add_argument("--require-hint-match", action="store_true")
    resume.set_defaults(handler=_resume_tree_command)

    add_oci_commands(commands)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
