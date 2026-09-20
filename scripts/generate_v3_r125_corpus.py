"""Generate the byte-exact Sigma v3 R12.5 history-feedback corpus."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from reference.independent_v3 import evaluate_suite

ROOT = Path(__file__).parents[1]
DEFAULT_OUTPUT = (
    ROOT / "specification" / "test-vectors" / "conformance-v3-r12-5.json.gz.b64"
)
MESSAGE = b"Sigma v3 R12.5 history feedback corpus"
CHALLENGE = b"R12.5-history-conformance-challenge"
APPLICATION_CONTEXT = b"specification/test-vectors/conformance-v3-r12-5"
CASES = (
    ("wide-once-history-v3", 0x0321, b"R125-0321-129"),
    ("deep-history-v3", 0x0323, b"R125-0323-76"),
    ("deep-vector-history-v3", 0x0324, b"R125-0324-52"),
)


def _hex(value: bytes) -> str:
    return value.hex()


def _hex_items(values: tuple[bytes, ...]) -> list[str]:
    return [_hex(value) for value in values]


def _placements(values: tuple[tuple[int, int], ...]) -> list[dict[str, int]]:
    return [{"field_id": field, "slot": slot} for field, slot in values]


def _case(case_id: str, suite_id: int, salt: bytes) -> dict[str, Any]:
    result = cast(
        dict[str, Any],
        evaluate_suite(
            MESSAGE,
            suite_id=suite_id,
            salt=salt,
            challenge=CHALLENGE,
            application_context=APPLICATION_CONTEXT,
        ),
    )
    round_layouts = [
        {
            "round_index": index,
            "wire_hex": _hex(wire),
            "placements": _placements(placements),
        }
        for index, (wire, placements) in enumerate(
            zip(result["round_layouts"], result["round_placements"], strict=True)
        )
    ]
    digest = cast(bytes, result["digest"])
    return {
        "id": case_id,
        "suite_id": f"0x{suite_id:04x}",
        "message_hex": _hex(MESSAGE),
        "salt_hex": _hex(salt),
        "challenge_hex": _hex(CHALLENGE),
        "application_context_hex": _hex(APPLICATION_CONTEXT),
        "context_hex": _hex(result["context"]),
        "kappa_hex": _hex(result["cardinality"]),
        "anchor_hex": _hex(result["anchor"]),
        "anchor_components_hex": _hex_items(result["anchor_components"]),
        "lambda_hex": _hex(result["length_signature"]),
        "joint_hex": _hex(result["joint"]),
        "joint_components_hex": _hex_items(result["joint_components"]),
        "binding_hex": _hex(result["binding"]),
        "t": result["target_round"],
        "k": result["state_count"],
        "parameters_hex": _hex(result["parameters"]),
        "init_layout": {
            "wire_hex": _hex(result["init_layout"]),
            "placements": _placements(result["init_placements"]),
        },
        "histories_hex": _hex_items(result["histories"]),
        "round_bindings_hex": _hex_items(result["round_bindings"]),
        "round_layouts": round_layouts,
        "init_frame_hex": _hex(result["init_frame"]),
        "round_frames_hex": _hex_items(result["round_frames"]),
        "branch_frames_hex": [_hex_items(frames) for frames in result["branch_frames"]],
        "branch_outputs_hex": [_hex_items(outputs) for outputs in result["branch_outputs"]],
        "fold_frames_hex": _hex_items(result["fold_frames"]),
        "states_hex": _hex_items(result["states"]),
        "header_hex": _hex(result["header"]),
        "window_hex": _hex(result["window"]),
        "digest_hex": _hex(digest),
        "digest_sha256": hashlib.sha256(digest).hexdigest(),
    }


def render_corpus() -> str:
    document = {
        "schema": "sigma-v3-conformance-r12-5-history",
        "record_version": 3,
        "generator": "reference.independent_v3.evaluate_suite",
        "history_semantics": "H_i commits through S_(i-1); round i consumes (H_i,S_i)",
        "cases": [_case(*case) for case in CASES],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    rendered = render_corpus()
    if arguments.check:
        if not arguments.output.is_file():
            raise SystemExit("Sigma v3 R12.5 corpus is missing")
        try:
            frozen = gzip.decompress(
                base64.b64decode(arguments.output.read_text(encoding="ascii"))
            ).decode("utf-8")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise SystemExit("Sigma v3 R12.5 corpus cannot be decoded") from exc
        if frozen != rendered:
            raise SystemExit("Sigma v3 R12.5 corpus is stale")
        return 0
    compressed = gzip.compress(rendered.encode("utf-8"), compresslevel=9, mtime=0)
    arguments.output.write_text(base64.b64encode(compressed).decode("ascii"), encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
