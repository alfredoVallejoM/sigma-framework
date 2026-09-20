"""Sigma v3 R12.5 trajectories with causal history feedback."""

from __future__ import annotations

from dataclasses import dataclass

from sigma.binding import (
    HistoryCommitmentV3,
    PreparedBindingV3,
    PublicTrajectoryHeader,
    RoundBindingV3,
    TrajectoryParameters,
    TrajectoryWindow,
    derive_trajectory_parameters,
    history_seed_v3,
    history_step_v3,
    prepare_input_v3,
)
from sigma.crypto.primitives import HashAccumulator, hash_bytes
from sigma.layout import HistoryLayoutPlan, LayoutPlan, derive_history_layout_v3, derive_layout_v3
from sigma.rounds.backends_v3 import (
    SERIAL_DEEP_BRANCH_BACKEND_V3,
    DeepBranchBackendV3,
    DeepBranchTaskV3,
    execute_deep_tasks_v3,
)
from sigma.rounds.control_v3 import (
    CancellationTokenV3,
    check_cancellation_v3,
    checked_source_v3,
)
from sigma.rounds.framing_v3 import InitFrame
from sigma.rounds.history_framing_v3 import (
    HistoryDeepBranchFrame,
    HistoryDeepFoldFrame,
    HistoryRoundFrame,
    HistoryVectorRoundFrame,
)
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import (
    DomainIdV3,
    LayoutKindV3,
    RoundProfileIdV3,
    TrajectoryProfileIdV3,
)


@dataclass(frozen=True, init=False)
class HistoryWideOnceEvaluationV3:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    parameters: TrajectoryParameters
    init_layout: LayoutPlan
    round_layouts: tuple[HistoryLayoutPlan, ...]
    histories: tuple[HistoryCommitmentV3, ...]
    states: tuple[bytes, ...]
    header: PublicTrajectoryHeader
    window: TrajectoryWindow

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("HistoryWideOnceEvaluationV3 is created only by its evaluator")

    def _validate(self) -> None:
        _validate_wide(self)


@dataclass(frozen=True, init=False)
class HistoryDeepEvaluationV3:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    parameters: TrajectoryParameters
    init_layout: LayoutPlan
    round_layouts: tuple[HistoryLayoutPlan, ...]
    histories: tuple[HistoryCommitmentV3, ...]
    branch_outputs: tuple[tuple[bytes, ...], ...]
    states: tuple[bytes, ...]
    header: PublicTrajectoryHeader
    window: TrajectoryWindow

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("HistoryDeepEvaluationV3 is created only by its evaluator")

    def _validate(self) -> None:
        _validate_deep(self, RoundProfileIdV3.DEEP)


@dataclass(frozen=True, init=False)
class HistoryDeepVectorEvaluationV3:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    parameters: TrajectoryParameters
    init_layout: LayoutPlan
    round_layouts: tuple[HistoryLayoutPlan, ...]
    histories: tuple[HistoryCommitmentV3, ...]
    branch_outputs: tuple[tuple[bytes, ...], ...]
    states: tuple[bytes, ...]
    header: PublicTrajectoryHeader
    window: TrajectoryWindow

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("HistoryDeepVectorEvaluationV3 is created only by its evaluator")

    def _validate(self) -> None:
        _validate_deep(self, RoundProfileIdV3.DEEP_VECTOR)


HistoryEvaluationV3 = (
    HistoryWideOnceEvaluationV3
    | HistoryDeepEvaluationV3
    | HistoryDeepVectorEvaluationV3
)
HistoryDeepEvaluationLikeV3 = HistoryDeepEvaluationV3 | HistoryDeepVectorEvaluationV3


class _HashFanout:
    def __init__(self, sinks: tuple[HashAccumulator, ...]) -> None:
        self._sinks = sinks

    def update(self, data: bytes) -> None:
        for sink in self._sinks:
            sink.update(data)


def _require_history_context(
    context: SigmaContextV3,
    profile: RoundProfileIdV3 | None = None,
) -> None:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if context.trajectory_profile is not TrajectoryProfileIdV3.HISTORY_FEEDBACK:
        raise ValueError("context does not use history feedback")
    if profile is not None and context.round_profile is not profile:
        raise ValueError("context has the wrong round profile")


def _initial_state(
    context: SigmaContextV3,
    prepared: PreparedBindingV3,
    init_layout: LayoutPlan,
    source: CanonicalSource,
) -> bytes:
    frame = InitFrame(context, prepared, init_layout, source)
    if context.round_profile is not RoundProfileIdV3.DEEP_VECTOR:
        accumulator = HashAccumulator(context.state_algorithm, DomainIdV3.INIT_FRAME)
        frame.write_to(accumulator)
        return accumulator.digest()
    accumulators = tuple(
        HashAccumulator(algorithm, DomainIdV3.INIT_FRAME) for algorithm in context.joint_algorithms
    )
    frame.write_to(_HashFanout(accumulators))
    return b"".join(accumulator.digest() for accumulator in accumulators)


def _base_setup(
    context: SigmaContextV3,
    source: CanonicalSource,
    cancellation: CancellationTokenV3 | None,
) -> tuple[
    PreparedBindingV3,
    TrajectoryParameters,
    LayoutPlan,
    bytes,
    HistoryCommitmentV3,
]:
    _require_history_context(context)
    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")
    source = checked_source_v3(source, cancellation)
    check_cancellation_v3(cancellation)
    prepared = prepare_input_v3(context, source)
    binding = prepared.binding
    parameters = derive_trajectory_parameters(context, binding)
    init_layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=binding.cardinality.byte_length,
    )
    state = _initial_state(context, prepared, init_layout, source)
    history = history_seed_v3(context, binding)
    return prepared, parameters, init_layout, state, history


def _header_window(
    prepared: PreparedBindingV3,
    parameters: TrajectoryParameters,
    states: tuple[bytes, ...],
) -> tuple[PublicTrajectoryHeader, TrajectoryWindow]:
    binding = prepared.binding
    return (
        PublicTrajectoryHeader(
            binding.cardinality,
            binding.anchor,
            binding.length_signature,
            parameters,
        ),
        TrajectoryWindow(parameters, states[parameters.target_round :]),
    )


def _history_wide_transition(
    context: SigmaContextV3,
    prepared: PreparedBindingV3,
    round_index: int,
    state: bytes,
    history: HistoryCommitmentV3,
) -> tuple[HistoryLayoutPlan, bytes, HistoryCommitmentV3]:
    binding = prepared.binding
    round_binding = RoundBindingV3(binding, history)
    layout = derive_history_layout_v3(
        context,
        round_binding,
        round_index=round_index,
        base_length=len(state),
    )
    frame = HistoryRoundFrame(context, round_binding, layout, round_index, state)
    successor = hash_bytes(
        context.state_algorithm,
        DomainIdV3.HISTORY_ROUND_FRAME,
        frame.to_bytes(),
    )
    next_history = history_step_v3(context, binding, history, round_index, state)
    return layout, successor, next_history


def evaluate_history_wide_once_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    *,
    cancellation: CancellationTokenV3 | None = None,
) -> HistoryWideOnceEvaluationV3:
    _require_history_context(context, RoundProfileIdV3.WIDE_ONCE)
    prepared, parameters, init_layout, state, history = _base_setup(
        context, source, cancellation
    )
    states = [state]
    histories = [history]
    layouts: list[HistoryLayoutPlan] = []
    transition_count = parameters.target_round + parameters.state_count - 1
    for round_index in range(transition_count):
        check_cancellation_v3(cancellation)
        layout, state, history = _history_wide_transition(
            context, prepared, round_index, state, history
        )
        layouts.append(layout)
        states.append(state)
        histories.append(history)
    state_tuple = tuple(states)
    header, window = _header_window(prepared, parameters, state_tuple)
    evaluation = object.__new__(HistoryWideOnceEvaluationV3)
    object.__setattr__(evaluation, "context", context)
    object.__setattr__(evaluation, "prepared", prepared)
    object.__setattr__(evaluation, "parameters", parameters)
    object.__setattr__(evaluation, "init_layout", init_layout)
    object.__setattr__(evaluation, "round_layouts", tuple(layouts))
    object.__setattr__(evaluation, "histories", tuple(histories))
    object.__setattr__(evaluation, "states", state_tuple)
    object.__setattr__(evaluation, "header", header)
    object.__setattr__(evaluation, "window", window)
    evaluation._validate()
    return evaluation


def evaluate_history_wide_once_bytes_v3(
    context: SigmaContextV3,
    message: bytes,
    *,
    cancellation: CancellationTokenV3 | None = None,
) -> HistoryWideOnceEvaluationV3:
    return evaluate_history_wide_once_v3(
        context, BytesSource(message), cancellation=cancellation
    )


def _history_deep_tasks(
    context: SigmaContextV3,
    round_binding: RoundBindingV3,
    round_index: int,
    state: bytes,
    layout: HistoryLayoutPlan,
) -> tuple[DeepBranchTaskV3, ...]:
    if context.round_profile is RoundProfileIdV3.DEEP:
        state_frame: HistoryRoundFrame | HistoryVectorRoundFrame = HistoryRoundFrame(
            context, round_binding, layout, round_index, state
        )
    elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        state_frame = HistoryVectorRoundFrame(
            context, round_binding, layout, round_index, state
        )
    else:
        raise ValueError("context is not a history Deep suite")
    return tuple(
        DeepBranchTaskV3(
            position,
            algorithm,
            HistoryDeepBranchFrame(
                context, round_index, position, algorithm, state_frame
            ).to_bytes(),
            DomainIdV3.HISTORY_DEEP_BRANCH_FRAME,
        )
        for position, algorithm in enumerate(context.joint_algorithms)
    )


def _history_deep_transition(
    context: SigmaContextV3,
    prepared: PreparedBindingV3,
    round_index: int,
    state: bytes,
    history: HistoryCommitmentV3,
    backend: DeepBranchBackendV3,
) -> tuple[HistoryLayoutPlan, tuple[bytes, ...], bytes, HistoryCommitmentV3]:
    binding = prepared.binding
    round_binding = RoundBindingV3(binding, history)
    layout = derive_history_layout_v3(
        context,
        round_binding,
        round_index=round_index,
        base_length=len(state),
    )
    branches = execute_deep_tasks_v3(
        backend,
        _history_deep_tasks(context, round_binding, round_index, state, layout),
    )
    if context.round_profile is RoundProfileIdV3.DEEP:
        successor = hash_bytes(
            context.state_algorithm,
            DomainIdV3.HISTORY_DEEP_FOLD,
            HistoryDeepFoldFrame(context, round_index, branches).to_bytes(),
        )
    elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        successor = b"".join(branches)
    else:  # pragma: no cover
        raise ValueError("context is not a history Deep suite")
    if len(successor) != context.state_size:
        raise RuntimeError("history Deep successor width does not match suite")
    next_history = history_step_v3(context, binding, history, round_index, state)
    return layout, branches, successor, next_history


def _evaluate_history_deep(
    context: SigmaContextV3,
    source: CanonicalSource,
    backend: DeepBranchBackendV3,
    evaluation_type: type[HistoryDeepEvaluationV3]
    | type[HistoryDeepVectorEvaluationV3],
    cancellation: CancellationTokenV3 | None,
) -> HistoryDeepEvaluationLikeV3:
    if not isinstance(backend, DeepBranchBackendV3):
        raise TypeError("backend must be DeepBranchBackendV3")
    prepared, parameters, init_layout, state, history = _base_setup(
        context, source, cancellation
    )
    states = [state]
    histories = [history]
    layouts: list[HistoryLayoutPlan] = []
    branch_outputs: list[tuple[bytes, ...]] = []
    transition_count = parameters.target_round + parameters.state_count - 1
    for round_index in range(transition_count):
        check_cancellation_v3(cancellation)
        layout, branches, state, history = _history_deep_transition(
            context, prepared, round_index, state, history, backend
        )
        layouts.append(layout)
        branch_outputs.append(branches)
        states.append(state)
        histories.append(history)
    state_tuple = tuple(states)
    header, window = _header_window(prepared, parameters, state_tuple)
    evaluation = object.__new__(evaluation_type)
    object.__setattr__(evaluation, "context", context)
    object.__setattr__(evaluation, "prepared", prepared)
    object.__setattr__(evaluation, "parameters", parameters)
    object.__setattr__(evaluation, "init_layout", init_layout)
    object.__setattr__(evaluation, "round_layouts", tuple(layouts))
    object.__setattr__(evaluation, "histories", tuple(histories))
    object.__setattr__(evaluation, "branch_outputs", tuple(branch_outputs))
    object.__setattr__(evaluation, "states", state_tuple)
    object.__setattr__(evaluation, "header", header)
    object.__setattr__(evaluation, "window", window)
    evaluation._validate()
    return evaluation


def evaluate_history_deep_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
    *,
    cancellation: CancellationTokenV3 | None = None,
) -> HistoryDeepEvaluationV3:
    _require_history_context(context, RoundProfileIdV3.DEEP)
    value = _evaluate_history_deep(
        context, source, backend, HistoryDeepEvaluationV3, cancellation
    )
    assert isinstance(value, HistoryDeepEvaluationV3)
    return value


def evaluate_history_deep_vector_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
    *,
    cancellation: CancellationTokenV3 | None = None,
) -> HistoryDeepVectorEvaluationV3:
    _require_history_context(context, RoundProfileIdV3.DEEP_VECTOR)
    value = _evaluate_history_deep(
        context, source, backend, HistoryDeepVectorEvaluationV3, cancellation
    )
    assert isinstance(value, HistoryDeepVectorEvaluationV3)
    return value


def evaluate_history_deep_bytes_v3(
    context: SigmaContextV3,
    message: bytes,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
    *,
    cancellation: CancellationTokenV3 | None = None,
) -> HistoryDeepEvaluationV3:
    return evaluate_history_deep_v3(
        context, BytesSource(message), backend, cancellation=cancellation
    )


def evaluate_history_deep_vector_bytes_v3(
    context: SigmaContextV3,
    message: bytes,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
    *,
    cancellation: CancellationTokenV3 | None = None,
) -> HistoryDeepVectorEvaluationV3:
    return evaluate_history_deep_vector_v3(
        context, BytesSource(message), backend, cancellation=cancellation
    )


def _validate_common(
    evaluation: HistoryEvaluationV3,
) -> None:
    _require_history_context(evaluation.context)
    if not isinstance(evaluation.prepared, PreparedBindingV3):
        raise TypeError("prepared must be PreparedBindingV3")
    binding = evaluation.prepared.binding
    if derive_trajectory_parameters(evaluation.context, binding) != evaluation.parameters:
        raise ValueError("parameters do not match context and persistent binding")
    expected_init = derive_layout_v3(
        evaluation.context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=binding.cardinality.byte_length,
    )
    if evaluation.init_layout != expected_init:
        raise ValueError("init layout does not match persistent binding")
    expected_count = evaluation.parameters.target_round + evaluation.parameters.state_count
    if len(evaluation.states) != expected_count:
        raise ValueError("trace does not cover requested window")
    if len(evaluation.histories) != len(evaluation.states):
        raise ValueError("one causal history required per state")
    if len(evaluation.round_layouts) != len(evaluation.states) - 1:
        raise ValueError("one history layout required per transition")
    if any(len(state) != evaluation.context.state_size for state in evaluation.states):
        raise ValueError("trace contains state with incorrect width")
    if evaluation.histories[0] != history_seed_v3(evaluation.context, binding):
        raise ValueError("genesis history does not match persistent binding")
    expected_header = PublicTrajectoryHeader(
        binding.cardinality,
        binding.anchor,
        binding.length_signature,
        evaluation.parameters,
    )
    if evaluation.header != expected_header:
        raise ValueError("header does not match persistent binding")
    expected_window = TrajectoryWindow(
        evaluation.parameters,
        evaluation.states[evaluation.parameters.target_round :],
    )
    if evaluation.window != expected_window:
        raise ValueError("window does not match trace tail")


def _validate_wide(evaluation: HistoryWideOnceEvaluationV3) -> None:
    _require_history_context(evaluation.context, RoundProfileIdV3.WIDE_ONCE)
    _validate_common(evaluation)
    binding = evaluation.prepared.binding
    for index, (layout, history, next_history, state, successor) in enumerate(
        zip(
            evaluation.round_layouts,
            evaluation.histories[:-1],
            evaluation.histories[1:],
            evaluation.states[:-1],
            evaluation.states[1:],
            strict=True,
        )
    ):
        round_binding = RoundBindingV3(binding, history)
        expected_layout = derive_history_layout_v3(
            evaluation.context,
            round_binding,
            round_index=index,
            base_length=len(state),
        )
        if layout != expected_layout:
            raise ValueError("history layout does not match trajectory")
        expected_successor = hash_bytes(
            evaluation.context.state_algorithm,
            DomainIdV3.HISTORY_ROUND_FRAME,
            HistoryRoundFrame(
                evaluation.context, round_binding, layout, index, state
            ).to_bytes(),
        )
        if successor != expected_successor:
            raise ValueError("state transition does not match history frame")
        if next_history != history_step_v3(
            evaluation.context, binding, history, index, state
        ):
            raise ValueError("history transition does not match causal step")


def _validate_deep(
    evaluation: HistoryDeepEvaluationLikeV3,
    profile: RoundProfileIdV3,
) -> None:
    _require_history_context(evaluation.context, profile)
    _validate_common(evaluation)
    if len(evaluation.branch_outputs) != len(evaluation.round_layouts):
        raise ValueError("one branch set required per transition")
    binding = evaluation.prepared.binding
    for index, (layout, history, next_history, branches, state, successor) in enumerate(
        zip(
            evaluation.round_layouts,
            evaluation.histories[:-1],
            evaluation.histories[1:],
            evaluation.branch_outputs,
            evaluation.states[:-1],
            evaluation.states[1:],
            strict=True,
        )
    ):
        round_binding = RoundBindingV3(binding, history)
        expected_layout = derive_history_layout_v3(
            evaluation.context,
            round_binding,
            round_index=index,
            base_length=len(state),
        )
        if layout != expected_layout:
            raise ValueError("history layout does not match trajectory")
        expected_branches = execute_deep_tasks_v3(
            SERIAL_DEEP_BRANCH_BACKEND_V3,
            _history_deep_tasks(
                evaluation.context, round_binding, index, state, layout
            ),
        )
        if branches != expected_branches:
            raise ValueError("branch outputs do not match history tasks")
        if profile is RoundProfileIdV3.DEEP:
            expected_successor = hash_bytes(
                evaluation.context.state_algorithm,
                DomainIdV3.HISTORY_DEEP_FOLD,
                HistoryDeepFoldFrame(
                    evaluation.context, index, branches
                ).to_bytes(),
            )
        else:
            expected_successor = b"".join(branches)
        if successor != expected_successor:
            raise ValueError("state transition does not match history Deep profile")
        if next_history != history_step_v3(
            evaluation.context, binding, history, index, state
        ):
            raise ValueError("history transition does not match causal step")


__all__ = [
    "HistoryDeepEvaluationV3",
    "HistoryDeepVectorEvaluationV3",
    "HistoryEvaluationV3",
    "HistoryWideOnceEvaluationV3",
    "evaluate_history_deep_bytes_v3",
    "evaluate_history_deep_v3",
    "evaluate_history_deep_vector_bytes_v3",
    "evaluate_history_deep_vector_v3",
    "evaluate_history_wide_once_bytes_v3",
    "evaluate_history_wide_once_v3",
]
