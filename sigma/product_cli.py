"""Provisional product CLI for Sigma structural workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from sigma.tree import SymlinkPolicy, build_directory_manifest


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
