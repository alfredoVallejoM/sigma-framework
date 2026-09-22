"""Reproducible SV1 semantic gate for trajectory checkpoint/continuation."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import replace
from pathlib import Path

from reference.independent_v3 import evaluate_suite
from reference.trajectory_checkpoint_v3 import checkpoint_from_reference_evaluation
from sigma.binding import HistoryCommitmentV3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    TrajectoryCheckpointV1,
    checkpoint_from_evaluation_v3,
    continue_trajectory_checkpoint_v3,
    verify_trajectory_checkpoint_source_v3,
)
from sigma.v3 import evaluate_v3

ALL_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)

MIN_EVALUATIONS = 60
MIN_DIRECTED_MUTATIONS = 500
MIN_SOURCE_REBINDS = 30


def _mutate(value: bytes) -> bytes:
    raw = bytearray(value)
    raw[len(raw) // 2] ^= 1
    return bytes(raw)


def run_gate(
    *,
    evaluations: int,
    minimum_mutations: int,
    source_rebinds: int,
) -> dict[str, object]:
    if evaluations < MIN_EVALUATIONS:
        raise ValueError(f"SV1 requires at least {MIN_EVALUATIONS} evaluations")
    if minimum_mutations < MIN_DIRECTED_MUTATIONS:
        raise ValueError(
            f"SV1 requires at least {MIN_DIRECTED_MUTATIONS} directed mutations"
        )
    if source_rebinds < MIN_SOURCE_REBINDS:
        raise ValueError(
            f"SV1 requires at least {MIN_SOURCE_REBINDS} source rebind checks"
        )

    rng = random.Random(0x53563147415445)
    per_suite = evaluations // len(ALL_SUITES)
    remainder = evaluations % len(ALL_SUITES)

    checkpoint_stream = hashlib.sha256()
    continuation_stream = hashlib.sha256()
    all_index_cases = 0
    mutations = 0
    rebind_count = 0

    for suite_position, suite_id in enumerate(ALL_SUITES):
        suite_cases = per_suite + (1 if suite_position < remainder else 0)
        for _case_index in range(suite_cases):
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
            reference = evaluate_suite(
                message,
                suite_id=int(suite_id),
                salt=salt,
                challenge=challenge,
                application_context=application_context,
            )
            expected_states = tuple(reference["states"])
            expected_histories = tuple(reference["histories"])
            expected_digest = reference["digest"]

            for index in range(len(evaluation.states)):
                checkpoint = checkpoint_from_evaluation_v3(evaluation, index)
                wire = checkpoint.to_bytes()
                if wire != checkpoint_from_reference_evaluation(reference, index):
                    raise AssertionError(
                        f"SV1 independent checkpoint divergence suite={suite_id} index={index}"
                    )
                if TrajectoryCheckpointV1.from_bytes(wire) != checkpoint:
                    raise AssertionError("SV1 checkpoint codec round-trip divergence")

                continuation = continue_trajectory_checkpoint_v3(checkpoint)
                if continuation.states != expected_states[index:]:
                    raise AssertionError("SV1 continuation state suffix divergence")
                if expected_histories:
                    if continuation.histories != expected_histories[index:]:
                        raise AssertionError("SV1 continuation history suffix divergence")
                elif continuation.histories:
                    raise AssertionError("non-history continuation exposed histories")
                if continuation.digest.to_bytes() != expected_digest:
                    raise AssertionError("SV1 final digest divergence")

                checkpoint_stream.update(hashlib.sha256(wire).digest())
                continuation_stream.update(
                    hashlib.sha256(continuation.digest.to_bytes()).digest()
                )
                all_index_cases += 1

                # Directed state mutation must not preserve the expected suffix/digest.
                corrupted = replace(checkpoint, state=_mutate(checkpoint.state))
                changed = continue_trajectory_checkpoint_v3(corrupted)
                if changed.digest.to_bytes() == expected_digest:
                    raise AssertionError("mutated checkpoint state preserved final digest")
                mutations += 1

                if checkpoint.history is not None:
                    bad_history = HistoryCommitmentV3(
                        checkpoint.history.round_index,
                        _mutate(checkpoint.history.digest),
                    )
                    corrupted_history = replace(checkpoint, history=bad_history)
                    if index < checkpoint.final_round_index:
                        changed_history = continue_trajectory_checkpoint_v3(
                            corrupted_history
                        )
                        if changed_history.digest.to_bytes() == expected_digest:
                            raise AssertionError(
                                "mutated checkpoint history preserved final digest"
                            )
                    elif verify_trajectory_checkpoint_source_v3(
                        BytesSource(message),
                        corrupted_history,
                    ):
                        raise AssertionError(
                            "mutated final history incorrectly rebound to source"
                        )
                    mutations += 1

                if checkpoint.window_prefix:
                    prefix = list(checkpoint.window_prefix)
                    prefix[0] = _mutate(prefix[0])
                    corrupted_prefix = replace(
                        checkpoint,
                        window_prefix=tuple(prefix),
                    )
                    changed_prefix = continue_trajectory_checkpoint_v3(
                        corrupted_prefix
                    )
                    if changed_prefix.digest.to_bytes() == expected_digest:
                        raise AssertionError(
                            "mutated window prefix preserved final digest"
                        )
                    mutations += 1

            if rebind_count < source_rebinds:
                index = min(
                    len(evaluation.states) - 1,
                    evaluation.parameters.target_round,
                )
                checkpoint = checkpoint_from_evaluation_v3(evaluation, index)
                if not verify_trajectory_checkpoint_source_v3(
                    BytesSource(message), checkpoint
                ):
                    raise AssertionError("SV1 correct source rebind failed")
                if verify_trajectory_checkpoint_source_v3(
                    BytesSource(message + b"\x00"), checkpoint
                ):
                    raise AssertionError("SV1 wrong source rebind accepted")
                rebind_count += 1

    if mutations < minimum_mutations:
        raise AssertionError(
            f"SV1 mutation campaign too small: {mutations} < {minimum_mutations}"
        )
    if rebind_count < source_rebinds:
        raise AssertionError(
            f"SV1 source-rebind campaign too small: {rebind_count} < {source_rebinds}"
        )

    return {
        "schema": "sigma-sv1-trajectory-checkpoint-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "evaluations": evaluations,
        "all_index_cases": all_index_cases,
        "directed_mutations": mutations,
        "source_rebinds": rebind_count,
        "checkpoint_stream_sha256": checkpoint_stream.hexdigest(),
        "continuation_digest_stream_sha256": continuation_stream.hexdigest(),
        "suites": [f"0x{int(suite):04x}" for suite in ALL_SUITES],
        "empirical_performance_claims": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluations", type=int, default=MIN_EVALUATIONS)
    parser.add_argument(
        "--minimum-mutations", type=int, default=MIN_DIRECTED_MUTATIONS
    )
    parser.add_argument(
        "--source-rebinds", type=int, default=MIN_SOURCE_REBINDS
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        evaluations=args.evaluations,
        minimum_mutations=args.minimum_mutations,
        source_rebinds=args.source_rebinds,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
