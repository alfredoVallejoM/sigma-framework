#!/usr/bin/env python3
"""Coverage-guided fuzz target for all public v2 binary codecs.

The first input byte selects a codec and the remaining bytes are the candidate
wire object. Accepted inputs must serialize to exactly the same bytes.
"""

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts.fuzz_codecs import canonical_codec_cases
from sigma.spec.encoding import DecodeError

MAX_FUZZ_INPUT = 1 << 16


CODEC_CASES = canonical_codec_cases()
PARSERS: tuple[Callable[[bytes], Any], ...] = tuple(case[2] for case in CODEC_CASES)


def write_corpus(directory: Path) -> tuple[Path, ...]:
    """Write deterministic valid seeds, including each parser selector."""

    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for selector, (name, encoded, _) in enumerate(CODEC_CASES):
        path = directory / f"{selector:02d}-{name}"
        path.write_bytes(bytes([selector]) + encoded)
        paths.append(path)
    return tuple(paths)


def TestOneInput(data: bytes) -> None:
    """Exercise one selected parser while preserving unexpected failures."""

    if not data or len(data) > MAX_FUZZ_INPUT:
        return
    parser = PARSERS[data[0] % len(PARSERS)]
    candidate = data[1:]
    try:
        decoded = parser(candidate)
    except (DecodeError, TypeError, ValueError):
        return
    if decoded.to_bytes() != candidate:
        raise AssertionError("parser accepted a non-canonical representation")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--write-corpus", type=Path)
    known, remaining = parser.parse_known_args()
    if known.write_corpus is not None:
        for path in write_corpus(known.write_corpus):
            print(path)
        return 0
    try:
        import atheris
    except ImportError as exc:
        raise SystemExit("install the 'fuzz' extra to run coverage-guided fuzzing") from exc
    atheris.instrument_all()
    atheris.Setup([sys.argv[0], *remaining], TestOneInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
