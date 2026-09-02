"""Generate the complete core-suite and PoW conformance vectors explicitly."""

import argparse
import json
from pathlib import Path

from sigma.anchors import AnchorEvidence, CrossWide, CrossWideEvidence, StreamWide, TreeWide
from sigma.applications.pow import PowParameters, PowPredicate, evaluate_nonce
from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
    simultaneous_v2_2,
)
from sigma.rounds import Deep, DeepVector, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, RoundProfileId, SuiteId
from sigma.suites.registry import get_suite

MESSAGE = b"sigma-v2.2-conformance"


def _reference_context() -> SigmaContextV2:
    suite_id = SuiteId.REFERENCE_STREAM_WIDE_V2_2
    return SigmaContextV2(
        suite_id=suite_id,
        anchor_profile=AnchorProfileId.STREAM_WIDE,
        round_profile=RoundProfileId.WIDE_ONCE,
        branches=get_suite(suite_id).branches,
        target_round=2,
        state_count=3,
    )


def _suite_vector(name: str, context: SigmaContextV2) -> dict[str, object]:
    anchor: AnchorEvidence | CrossWideEvidence
    if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
        anchor = StreamWide.compute(context, (MESSAGE,))
    elif context.anchor_profile is AnchorProfileId.TREE_WIDE:
        anchor = TreeWide.compute(context, (MESSAGE,))
    else:
        anchor = CrossWide.compute(context, (MESSAGE,))
    if context.round_profile is RoundProfileId.WIDE_ONCE:
        digest, transcript = WideOnce(context).evaluate(anchor)
    elif context.round_profile is RoundProfileId.DEEP:
        digest, transcript = Deep(context).evaluate(anchor)  # type: ignore[arg-type]
    else:
        digest, transcript = DeepVector(context).evaluate(anchor)  # type: ignore[arg-type]
    return {
        "anchor_evidence_hex": anchor.to_bytes().hex(),
        "branch_outputs_hex": [
            [component.hex() for component in row] for row in transcript.branch_outputs
        ],
        "context_hex": context.to_bytes().hex(),
        "cross_roots_hex": [root.hex() for root in getattr(anchor, "cross_roots", ())],
        "digest_hex": digest.to_bytes().hex(),
        "message_hex": MESSAGE.hex(),
        "name": name,
        "roots_hex": [root.hex() for root in anchor.roots],
        "states_hex": [state.hex() for state in transcript.states],
    }


def generate() -> dict[str, object]:
    contexts = (
        ("reference-stream-wide-v2-2", _reference_context()),
        ("lightweight-stream-wide-v2-2", lightweight_v2_2(target_round=2, state_count=3)),
        ("simultaneous-tree-wide-v2-2", simultaneous_v2_2(target_round=2, state_count=3)),
        ("paranoid-cross-wide-v2-2", paranoid_wide_v2_2(target_round=2, state_count=3)),
        ("paranoid-deep-v2-2", paranoid_deep_v2_2(target_round=2, state_count=3)),
        (
            "paranoid-deep-vector-v2-2",
            paranoid_deep_vector_v2_2(target_round=2, state_count=3),
        ),
    )
    parameters = PowParameters(b"vector-challenge", 2, 3, PowPredicate.CONCATENATED, 0)
    proof = evaluate_nonce(b"vector-payload", 7, parameters)
    return {
        "format": "sigma-conformance-v1",
        "pow": {
            "digest_hex": proof.digest.to_bytes().hex(),
            "nonce": proof.nonce,
            "parameters_hex": parameters.to_bytes().hex(),
            "payload_hex": b"vector-payload".hex(),
        },
        "suites": [_suite_vector(name, context) for name, context in contexts],
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
