from __future__ import annotations

import ast
import random
from pathlib import Path

from reference.independent_v3 import evaluate_suite
from reference.trajectory_checkpoint_v3 import checkpoint_from_reference_evaluation
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    checkpoint_from_evaluation_v3,
    continue_trajectory_checkpoint_v3,
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


def test_all_indices_match_independent_checkpoint_encoder():
    rng = random.Random(0x53563144494646)
    for suite_id in ALL_SUITES:
        for case in range(5):
            message = rng.randbytes(rng.randrange(0, 49))
            salt = rng.randbytes(rng.randrange(0, 9))
            challenge = rng.randbytes(rng.randrange(0, 9))
            application_context = rng.randbytes(rng.randrange(0, 13))

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

            for index in range(len(evaluation.states)):
                checkpoint = checkpoint_from_evaluation_v3(evaluation, index)
                assert checkpoint.to_bytes() == checkpoint_from_reference_evaluation(
                    reference, index
                )

                continuation = continue_trajectory_checkpoint_v3(checkpoint)
                assert continuation.states == tuple(reference["states"])[index:]
                if reference["histories"]:
                    assert continuation.histories == tuple(reference["histories"])[
                        index:
                    ]
                else:
                    assert continuation.histories == ()
                assert continuation.digest.to_bytes() == reference["digest"]


def test_independent_checkpoint_encoder_never_imports_sigma():
    path = Path(__file__).parents[2] / "reference" / "trajectory_checkpoint_v3.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(name == "sigma" or name.startswith("sigma.") for name in imported)
