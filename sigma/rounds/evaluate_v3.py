"""Round-profile dispatch without changing canonical evaluation semantics."""

from __future__ import annotations

from sigma.rounds.backends_v3 import DeepBranchBackendV3
from sigma.rounds.control_v3 import CancellationTokenV3
from sigma.rounds.deep_v3 import (
    DeepEvaluationV3,
    DeepVectorEvaluationV3,
    evaluate_deep_v3,
    evaluate_deep_vector_v3,
)
from sigma.rounds.history_v3 import (
    HistoryDeepEvaluationV3,
    HistoryDeepVectorEvaluationV3,
    HistoryWideOnceEvaluationV3,
    evaluate_history_deep_v3,
    evaluate_history_deep_vector_v3,
    evaluate_history_wide_once_v3,
)
from sigma.rounds.wide_once_v3 import WideOnceEvaluationV3, evaluate_wide_once_v3
from sigma.sources import CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import RoundProfileIdV3, TrajectoryProfileIdV3

EvaluationV3 = (
    WideOnceEvaluationV3
    | DeepEvaluationV3
    | DeepVectorEvaluationV3
    | HistoryWideOnceEvaluationV3
    | HistoryDeepEvaluationV3
    | HistoryDeepVectorEvaluationV3
)


def evaluate_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    *,
    backend: DeepBranchBackendV3 | None = None,
    cancellation: CancellationTokenV3 | None = None,
) -> EvaluationV3:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")

    if context.trajectory_profile is TrajectoryProfileIdV3.HISTORY_FEEDBACK:
        if context.round_profile is RoundProfileIdV3.WIDE_ONCE:
            if backend is not None:
                raise ValueError("WideOnce does not accept a Deep branch backend")
            return evaluate_history_wide_once_v3(
                context, source, cancellation=cancellation
            )
        if backend is None:
            if context.round_profile is RoundProfileIdV3.DEEP:
                return evaluate_history_deep_v3(
                    context, source, cancellation=cancellation
                )
            if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
                return evaluate_history_deep_vector_v3(
                    context, source, cancellation=cancellation
                )
        elif context.round_profile is RoundProfileIdV3.DEEP:
            return evaluate_history_deep_v3(
                context, source, backend, cancellation=cancellation
            )
        elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
            return evaluate_history_deep_vector_v3(
                context, source, backend, cancellation=cancellation
            )
        raise ValueError("unsupported history-feedback round profile")

    if context.round_profile is RoundProfileIdV3.WIDE_ONCE:
        if backend is not None:
            raise ValueError("WideOnce does not accept a Deep branch backend")
        return evaluate_wide_once_v3(context, source, cancellation=cancellation)
    if backend is None:
        if context.round_profile is RoundProfileIdV3.DEEP:
            return evaluate_deep_v3(context, source, cancellation=cancellation)
        if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
            return evaluate_deep_vector_v3(context, source, cancellation=cancellation)
    elif context.round_profile is RoundProfileIdV3.DEEP:
        return evaluate_deep_v3(context, source, backend, cancellation=cancellation)
    elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        return evaluate_deep_vector_v3(context, source, backend, cancellation=cancellation)
    raise ValueError("unsupported Sigma v3 round profile")  # pragma: no cover


__all__ = ["EvaluationV3", "evaluate_v3"]
