"""Reproducible SV0 closure gate for Sigma v3 trajectory audits."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import random
from dataclasses import replace
from pathlib import Path
from typing import Any

from reference.independent_v3 import evaluate_suite
from reference.trajectory_audit_v3 import (
    MODE_COMPACT,
    MODE_FULL,
    audit_from_reference_evaluation,
)
from sigma.binding import HistoryCommitmentV3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import RoundProfileIdV3, SuiteIdV3
from sigma.trajectory import (
    TrajectoryAuditModeV3,
    TrajectoryAuditV3,
    audit_from_evaluation_v3,
    project_digest_v3,
    verify_trajectory_audit_full_v3,
    verify_trajectory_audit_structure_v3,
)
from sigma.v3 import evaluate_v3

ROOT = Path(__file__).parents[2]
R125_CORPUS = (
    ROOT / "specification" / "test-vectors" / "conformance-v3-r12-5.json.gz.b64"
)

ALL_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)

MIN_DIFFERENTIAL_CASES = 600
MIN_MUTATION_CASES = 2_000
MIN_FULL_SOURCE_REPLAYS = 60


def _r125_document() -> dict[str, Any]:
    decoded = gzip.decompress(base64.b64decode(R125_CORPUS.read_text(encoding="ascii")))
    return json.loads(decoded.decode("utf-8"))


def _reference_from_frozen_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "states": tuple(bytes.fromhex(value) for value in case["states_hex"]),
        "round_layouts": tuple(
            bytes.fromhex(item["wire_hex"]) for item in case["round_layouts"]
        ),
        "histories": tuple(bytes.fromhex(value) for value in case["histories_hex"]),
        "round_bindings": tuple(
            bytes.fromhex(value) for value in case["round_bindings_hex"]
        ),
        "round_frames": tuple(
            bytes.fromhex(value) for value in case["round_frames_hex"]
        ),
        "branch_frames": tuple(
            tuple(bytes.fromhex(value) for value in group)
            for group in case["branch_frames_hex"]
        ),
        "branch_outputs": tuple(
            tuple(bytes.fromhex(value) for value in group)
            for group in case["branch_outputs_hex"]
        ),
        "fold_frames": tuple(
            bytes.fromhex(value) for value in case["fold_frames_hex"]
        ),
        "digest": bytes.fromhex(case["digest_hex"]),
        "binding": bytes.fromhex(case["binding_hex"]),
        "init_layout": bytes.fromhex(case["init_layout"]["wire_hex"]),
    }


def _mutate_bytes(value: bytes, offset: int = 0) -> bytes:
    if not value:
        raise ValueError("cannot mutate empty bytes")
    raw = bytearray(value)
    raw[offset % len(raw)] ^= 1
    return bytes(raw)


def _mutation_rejects(audit: TrajectoryAuditV3) -> bool:
    try:
        return not verify_trajectory_audit_structure_v3(audit)
    except (TypeError, ValueError):
        return True


def _exercise_mutations(
    audit: TrajectoryAuditV3,
    *,
    history_enabled: bool,
    deep: bool,
) -> int:
    count = 0

    # S_0 is always before the public window because t>=2 in registered suites.
    state0 = _mutate_bytes(audit.states[0])
    candidate = replace(audit, states=(state0, *audit.states[1:]))
    if not _mutation_rejects(candidate):
        raise AssertionError("mutated S_0 remained replay-valid")
    count += 1

    first = audit.rounds[0]
    candidate = replace(
        audit,
        rounds=(
            replace(first, layout=_mutate_bytes(first.layout, -1)),
            *audit.rounds[1:],
        ),
    )
    if not _mutation_rejects(candidate):
        raise AssertionError("mutated layout remained replay-valid")
    count += 1

    if history_enabled:
        history = HistoryCommitmentV3.from_bytes(audit.histories[1])
        corrupted = HistoryCommitmentV3(
            history.round_index,
            _mutate_bytes(history.digest, -1),
        ).to_bytes()
        candidate = replace(
            audit,
            histories=(audit.histories[0], corrupted, *audit.histories[2:]),
        )
        if not _mutation_rejects(candidate):
            raise AssertionError("mutated H_i remained replay-valid")
        count += 1

    if audit.mode is TrajectoryAuditModeV3.FULL:
        candidate = replace(
            audit,
            rounds=(
                replace(first, state_frame=_mutate_bytes(first.state_frame, -1)),
                *audit.rounds[1:],
            ),
        )
        if not _mutation_rejects(candidate):
            raise AssertionError("mutated state frame remained replay-valid")
        count += 1

        if deep:
            output = _mutate_bytes(first.branch_outputs[0])
            candidate = replace(
                audit,
                rounds=(
                    replace(
                        first,
                        branch_outputs=(output, *first.branch_outputs[1:]),
                    ),
                    *audit.rounds[1:],
                ),
            )
            if not _mutation_rejects(candidate):
                raise AssertionError("mutated branch output remained replay-valid")
            count += 1

    return count


def run_gate(
    *,
    differential_cases: int,
    minimum_mutations: int,
    full_source_replays: int,
) -> dict[str, Any]:
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(
            f"SV0 requires at least {MIN_DIFFERENTIAL_CASES} differential cases"
        )
    if minimum_mutations < MIN_MUTATION_CASES:
        raise ValueError(
            f"SV0 requires at least {MIN_MUTATION_CASES} directed mutations"
        )
    if full_source_replays < MIN_FULL_SOURCE_REPLAYS:
        raise ValueError(
            f"SV0 requires at least {MIN_FULL_SOURCE_REPLAYS} full source replays"
        )

    compact_stream = hashlib.sha256()
    full_stream = hashlib.sha256()
    digest_stream = hashlib.sha256()

    # Frozen R12.5 replay is a blocking, byte-exact gate.
    document = _r125_document()
    if document.get("schema") != "sigma-v3-conformance-r12-5-history":
        raise AssertionError("unexpected R12.5 corpus schema")
    frozen_cases = document["cases"]
    for case in frozen_cases:
        suite_id = SuiteIdV3(int(case["suite_id"], 16))
        message = bytes.fromhex(case["message_hex"])
        context = SigmaContextV3.for_suite(
            suite_id,
            salt=bytes.fromhex(case["salt_hex"]),
            challenge=bytes.fromhex(case["challenge_hex"]),
            application_context=bytes.fromhex(case["application_context_hex"]),
        )
        evaluation = evaluate_v3(context, BytesSource(message))
        reference = _reference_from_frozen_case(case)

        compact = audit_from_evaluation_v3(
            evaluation, mode=TrajectoryAuditModeV3.COMPACT
        )
        full = audit_from_evaluation_v3(
            evaluation, mode=TrajectoryAuditModeV3.FULL
        )
        if project_digest_v3(compact).to_bytes().hex() != case["digest_hex"]:
            raise AssertionError("SV0 compact projection changed R12.5 digest")
        if project_digest_v3(full).to_bytes().hex() != case["digest_hex"]:
            raise AssertionError("SV0 full projection changed R12.5 digest")
        if compact.to_bytes() != audit_from_reference_evaluation(
            reference, mode=MODE_COMPACT
        ):
            raise AssertionError("SV0 compact frozen-corpus reference divergence")
        if full.to_bytes() != audit_from_reference_evaluation(
            reference, mode=MODE_FULL
        ):
            raise AssertionError("SV0 full frozen-corpus reference divergence")
        if not verify_trajectory_audit_structure_v3(compact):
            raise AssertionError("SV0 compact frozen audit failed replay")
        if not verify_trajectory_audit_structure_v3(full):
            raise AssertionError("SV0 full frozen audit failed replay")
        if not verify_trajectory_audit_full_v3(BytesSource(message), full):
            raise AssertionError("SV0 full frozen audit failed message binding")

    rng = random.Random(0x53563047415445)
    per_suite = differential_cases // len(ALL_SUITES)
    remainder = differential_cases % len(ALL_SUITES)
    executed = 0
    mutation_count = 0
    source_replay_count = 0
    deep_vector_checks = 0

    for suite_position, suite_id in enumerate(ALL_SUITES):
        cases = per_suite + (1 if suite_position < remainder else 0)
        for case_index in range(cases):
            message = rng.randbytes(rng.randrange(0, 65))
            salt = rng.randbytes(rng.randrange(0, 9))
            challenge = rng.randbytes(rng.randrange(0, 9))
            application_context = rng.randbytes(rng.randrange(0, 17))

            context = SigmaContextV3.for_suite(
                suite_id,
                salt=salt,
                challenge=challenge,
                application_context=application_context,
            )
            evaluation = evaluate_v3(context, BytesSource(message))
            expected = evaluate_suite(
                message,
                suite_id=int(suite_id),
                salt=salt,
                challenge=challenge,
                application_context=application_context,
            )

            compact = audit_from_evaluation_v3(
                evaluation, mode=TrajectoryAuditModeV3.COMPACT
            )
            full = audit_from_evaluation_v3(
                evaluation, mode=TrajectoryAuditModeV3.FULL
            )

            compact_wire = compact.to_bytes()
            full_wire = full.to_bytes()
            if compact_wire != audit_from_reference_evaluation(
                expected, mode=MODE_COMPACT
            ):
                raise AssertionError(f"compact reference divergence at {executed}")
            if full_wire != audit_from_reference_evaluation(
                expected, mode=MODE_FULL
            ):
                raise AssertionError(f"full reference divergence at {executed}")
            if project_digest_v3(compact).to_bytes() != expected["digest"]:
                raise AssertionError(f"compact digest projection divergence at {executed}")
            if project_digest_v3(full).to_bytes() != expected["digest"]:
                raise AssertionError(f"full digest projection divergence at {executed}")
            if not verify_trajectory_audit_structure_v3(compact):
                raise AssertionError(f"compact structural replay failed at {executed}")
            if not verify_trajectory_audit_structure_v3(full):
                raise AssertionError(f"full structural replay failed at {executed}")

            # Canonical codec replay.
            if TrajectoryAuditV3.from_bytes(compact_wire) != compact:
                raise AssertionError("compact audit codec round-trip failed")
            if TrajectoryAuditV3.from_bytes(full_wire) != full:
                raise AssertionError("full audit codec round-trip failed")

            parameters = compact.digest.header.parameters
            if len(compact.states) != parameters.target_round + parameters.state_count:
                raise AssertionError("SV0 state cardinality does not equal t+k")
            if len(compact.rounds) != len(compact.states) - 1:
                raise AssertionError("SV0 transition cardinality drift")

            history_enabled = bool(compact.histories)
            deep = context.round_profile in (
                RoundProfileIdV3.DEEP,
                RoundProfileIdV3.DEEP_VECTOR,
            )
            mutation_count += _exercise_mutations(
                compact,
                history_enabled=history_enabled,
                deep=deep,
            )
            mutation_count += _exercise_mutations(
                full,
                history_enabled=history_enabled,
                deep=deep,
            )

            if (
                source_replay_count < full_source_replays
                and case_index % max(1, cases // max(1, full_source_replays // 6)) == 0
            ):
                if not verify_trajectory_audit_full_v3(
                    BytesSource(message), compact
                ):
                    raise AssertionError("compact full-source replay failed")
                if not verify_trajectory_audit_full_v3(
                    BytesSource(message), full
                ):
                    raise AssertionError("full full-source replay failed")
                wrong = message + b"\x00"
                if verify_trajectory_audit_full_v3(BytesSource(wrong), compact):
                    raise AssertionError("audit accepted wrong source")
                source_replay_count += 1

            if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
                if not full.rounds[0].branch_outputs:
                    raise AssertionError("DeepVector FULL audit lacks branches")
                if full.states[1] != b"".join(full.rounds[0].branch_outputs):
                    raise AssertionError("DeepVector audit lost vector successor semantics")
                if full.rounds[0].fold_frame:
                    raise AssertionError("DeepVector audit unexpectedly contains fold frame")
                deep_vector_checks += 1
            elif context.round_profile is RoundProfileIdV3.DEEP:
                if not full.rounds[0].fold_frame:
                    raise AssertionError("Deep FULL audit lacks scalar fold frame")
                if full.states[1] == b"".join(full.rounds[0].branch_outputs):
                    raise AssertionError("Deep audit collapsed scalar fold into vector state")

            compact_stream.update(hashlib.sha256(compact_wire).digest())
            full_stream.update(hashlib.sha256(full_wire).digest())
            digest_stream.update(hashlib.sha256(compact.digest.to_bytes()).digest())
            executed += 1

    if executed != differential_cases:
        raise AssertionError("SV0 differential case accounting mismatch")
    if mutation_count < minimum_mutations:
        raise AssertionError(
            f"SV0 mutation campaign too small: {mutation_count} < {minimum_mutations}"
        )
    if source_replay_count < full_source_replays:
        raise AssertionError(
            f"SV0 source replay campaign too small: {source_replay_count}"
        )

    return {
        "schema": "sigma-sv0-trajectory-audit-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "r125_frozen_cases": len(frozen_cases),
        "differential_cases": executed,
        "directed_mutations": mutation_count,
        "full_source_replays": source_replay_count,
        "deep_vector_semantic_checks": deep_vector_checks,
        "compact_stream_sha256": compact_stream.hexdigest(),
        "full_stream_sha256": full_stream.hexdigest(),
        "digest_projection_stream_sha256": digest_stream.hexdigest(),
        "suites": [f"0x{int(suite):04x}" for suite in ALL_SUITES],
        "security_width_claim": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--differential-cases",
        type=int,
        default=MIN_DIFFERENTIAL_CASES,
    )
    parser.add_argument(
        "--minimum-mutations",
        type=int,
        default=MIN_MUTATION_CASES,
    )
    parser.add_argument(
        "--full-source-replays",
        type=int,
        default=MIN_FULL_SOURCE_REPLAYS,
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        differential_cases=args.differential_cases,
        minimum_mutations=args.minimum_mutations,
        full_source_replays=args.full_source_replays,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
