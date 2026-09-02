"""Deliberately regenerate v2-2 vectors; never run as an implicit build step."""

import argparse
import json
from pathlib import Path

from sigma.anchors import StreamWide
from sigma.rounds import WideOnce
from sigma.spec import SigmaContextV2, SuiteId


def generate() -> dict[str, object]:
    context = SigmaContextV2(suite_id=SuiteId.REFERENCE_STREAM_WIDE_V2_2)
    message = b"abc"
    anchor = StreamWide.compute(context, (message,))
    digest, transcript = WideOnce(context).evaluate(anchor)
    return {
        "context_hex": context.to_bytes().hex(),
        "digest_hex": digest.to_bytes().hex(),
        "evidence_hex": anchor.to_bytes().hex(),
        "message_hex": message.hex(),
        "roots_hex": [root.hex() for root in anchor.roots],
        "state_count": context.state_count,
        "suite": "reference-stream-wide-v2-2",
        "target_round": context.target_round,
        "transcript_states_hex": [state.hex() for state in transcript.states],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite existing vector: {args.output}")
    args.output.write_text(
        json.dumps(generate(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
