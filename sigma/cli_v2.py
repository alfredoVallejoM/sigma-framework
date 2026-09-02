"""Explicit command-line interface for self-describing Sigma v2 digests."""

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

from sigma.backends import MultiprocessingTreeBackend
from sigma.outputs import SigmaDigestV2
from sigma.policy import DEFAULT_RESOURCE_POLICY
from sigma.presets import get_preset
from sigma.v2 import hash_bytes, hash_file, verify_full, verify_full_file
from sigma.vectors import ALL_VECTORS

PRESETS = (
    "lightweight-v2",
    "simultaneous-v2",
    "realtime-v2",
    "paranoid-wide-v2",
    "paranoid-deep-v2",
    "lightweight-v2-2",
    "simultaneous-v2-2",
    "paranoid-wide-v2-2",
    "paranoid-deep-v2-2",
    "paranoid-deep-vector-v2-2",
)


def _hex_bytes(value: str, label: str) -> bytes:
    try:
        if len(value) % 2:
            raise ValueError
        return bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be even-length hexadecimal") from exc


def _context(args):
    return get_preset(
        args.preset,
        target_round=args.target_round,
        state_count=args.state_count,
        salt=_hex_bytes(args.salt_hex, "salt"),
        challenge=_hex_bytes(args.challenge_hex, "challenge"),
        application_context=args.application_context.encode("utf-8"),
    )


def _digest_argument(value: str) -> SigmaDigestV2:
    try:
        if value.lstrip().startswith("{"):
            return SigmaDigestV2.from_json(value)
        return SigmaDigestV2.from_bytes(bytes.fromhex(value))
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError(f"invalid Sigma v2 digest: {exc}") from exc


def _digest_file(path: Path) -> SigmaDigestV2:
    data = path.read_bytes()
    try:
        return SigmaDigestV2.from_bytes(data)
    except ValueError as binary_error:
        try:
            return _digest_argument(data.decode("utf-8").strip())
        except (UnicodeError, argparse.ArgumentTypeError) as text_error:
            raise ValueError(
                f"invalid binary, hexadecimal, or JSON digest file: {binary_error}"
            ) from text_error


def _selected_digest(args) -> SigmaDigestV2:
    if args.digest_file is not None and args.digest is not None:
        raise ValueError("digest and --digest-file are mutually exclusive")
    if args.digest_file is not None:
        return _digest_file(args.digest_file)
    if args.digest is None:
        raise ValueError("provide a digest or --digest-file")
    return args.digest


def _add_digest_input(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("digest", nargs="?", type=_digest_argument)
    parser.add_argument("--digest-file", type=Path)


def _add_input(parser: argparse.ArgumentParser) -> None:
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--text", help="UTF-8 text input")
    inputs.add_argument("--file", type=Path, help="binary file input")


def _add_suite_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--preset", choices=PRESETS, required=True)
    parser.add_argument("--target-round", type=int, default=1)
    parser.add_argument("--state-count", type=int, default=2)
    parser.add_argument("--salt-hex", default="")
    parser.add_argument("--challenge-hex", default="")
    parser.add_argument("--application-context", default="")


def _hash_input(args, context, backend=None):
    if args.text is not None:
        return hash_bytes(args.text.encode("utf-8"), context, backend)
    if backend is not None:
        return hash_file(args.file, context, backend)
    return hash_file(args.file, context)


def _hash_command(args) -> int:
    context = _context(args)
    backend = None
    if args.workers is not None:
        if args.preset not in ("simultaneous-v2", "simultaneous-v2-2"):
            raise ValueError("--workers is only valid with a simultaneous preset")
        backend = MultiprocessingTreeBackend(args.workers)
    digest = _hash_input(args, context, backend)
    if args.format == "binary":
        sys.stdout.buffer.write(digest.to_bytes())
    else:
        print(digest.to_json(indent=2) if args.format == "json" else digest.hex())
    return 0


def _inspect_command(args) -> int:
    print(json.dumps(_selected_digest(args).metadata(), indent=2, sort_keys=True))
    return 0


def _verify_command(args) -> int:
    digest = _selected_digest(args)
    valid = (
        verify_full(args.text.encode("utf-8"), digest)
        if args.text is not None
        else verify_full_file(args.file, digest)
    )
    print("valid" if valid else "invalid")
    return 0 if valid else 1


def _vectors_command(_args) -> int:
    print(json.dumps(ALL_VECTORS, indent=2, sort_keys=True))
    return 0


def _benchmark_command(args) -> int:
    context = _context(args)
    observations = []
    for _ in range(args.repeats):
        started = time.perf_counter_ns()
        _hash_input(args, context)
        observations.append(time.perf_counter_ns() - started)
    report = {
        "implementation": platform.python_implementation(),
        "median_ns": int(statistics.median(observations)),
        "observations_ns": observations,
        "preset": args.preset,
        "python": platform.python_version(),
        "repeats": args.repeats,
        "resource_policy": DEFAULT_RESOURCE_POLICY.as_dict(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmahash-v2",
        description="Sigma v2 alpha research CLI; not a production security primitive",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    hash_parser = commands.add_parser("hash")
    _add_input(hash_parser)
    _add_suite_options(hash_parser)
    hash_parser.add_argument("--workers", type=int)
    hash_parser.add_argument("--format", choices=("hex", "json", "binary"), default="hex")
    hash_parser.set_defaults(handler=_hash_command)

    inspect_parser = commands.add_parser("inspect")
    _add_digest_input(inspect_parser)
    inspect_parser.set_defaults(handler=_inspect_command)

    verify_parser = commands.add_parser("verify")
    _add_digest_input(verify_parser)
    _add_input(verify_parser)
    verify_parser.set_defaults(handler=_verify_command)

    vectors_parser = commands.add_parser("vectors")
    vectors_parser.set_defaults(handler=_vectors_command)

    benchmark_parser = commands.add_parser("benchmark")
    _add_input(benchmark_parser)
    _add_suite_options(benchmark_parser)
    benchmark_parser.add_argument("--repeats", type=int, choices=range(1, 101), default=5)
    benchmark_parser.set_defaults(handler=_benchmark_command)
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
    sys.exit(main())
