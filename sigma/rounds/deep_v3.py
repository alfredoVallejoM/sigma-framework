"""Sigma v3 Deep scalar and vector trajectories."""

from __future__ import annotations

from dataclasses import dataclass

from sigma.binding import (
    PreparedBindingV3,
    PublicTrajectoryHeader,
    TrajectoryParameters,
    TrajectoryWindow,
    derive_trajectory_parameters,
    prepare_input_v3,
)
from sigma.binding.types import PersistentBinding
from sigma.crypto.primitives import HashAccumulator, hash_bytes
from sigma.layout import LayoutPlan, derive_layout_v3
from sigma.rounds.backends_v3 import (
    SERIAL_DEEP_BRANCH_BACKEND_V3,
    DeepBranchBackendV3,
    DeepBranchTaskV3,
    execute_deep_tasks_v3,
)
from sigma.rounds.framing_v3 import (
    DeepBranchFrame,
    DeepFoldFrame,
    InitFrame,
    RoundFrame,
    VectorRoundFrame,
)
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3, LayoutKindV3, RoundProfileIdV3


@dataclass(frozen=True, init=False)
class DeepEvaluationV3:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    parameters: TrajectoryParameters
    init_layout: LayoutPlan
    round_layouts: tuple[LayoutPlan, ...]
    branch_outputs: tuple[tuple[bytes, ...], ...]
    states: tuple[bytes, ...]
    header: PublicTrajectoryHeader
    window: TrajectoryWindow

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("DeepEvaluationV3 is created by evaluate_deep_v3")

    def _validate(self) -> None:
        _validate_evaluation(self, RoundProfileIdV3.DEEP)


@dataclass(frozen=True, init=False)
class DeepVectorEvaluationV3:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    parameters: TrajectoryParameters
    init_layout: LayoutPlan
    round_layouts: tuple[LayoutPlan, ...]
    branch_outputs: tuple[tuple[bytes, ...], ...]
    states: tuple[bytes, ...]
    header: PublicTrajectoryHeader
    window: TrajectoryWindow

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("DeepVectorEvaluationV3 is created by evaluate_deep_vector_v3")

    def _validate(self) -> None:
        _validate_evaluation(self, RoundProfileIdV3.DEEP_VECTOR)


DeepEvaluationLikeV3 = DeepEvaluationV3 | DeepVectorEvaluationV3


class _HashFanout:
    def __init__(self, sinks: tuple[HashAccumulator, ...]) -> None:
        self._sinks = sinks

    def update(self, data: bytes) -> None:
        for sink in self._sinks:
            sink.update(data)


def _require_profile(context: SigmaContextV3, profile: RoundProfileIdV3) -> None:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if context.round_profile is not profile:
        raise ValueError("context has the wrong Deep round profile")


def _initial_state(
    context: SigmaContextV3,
    prepared: PreparedBindingV3,
    init_layout: LayoutPlan,
    source: CanonicalSource,
) -> bytes:
    frame = InitFrame(context, prepared, init_layout, source)
    if context.round_profile is RoundProfileIdV3.DEEP:
        accumulator = HashAccumulator(context.state_algorithm, DomainIdV3.INIT_FRAME)
        frame.write_to(accumulator)
        return accumulator.digest()
    accumulators = tuple(
        HashAccumulator(algorithm, DomainIdV3.INIT_FRAME) for algorithm in context.joint_algorithms
    )
    frame.write_to(_HashFanout(accumulators))
    return b"".join(accumulator.digest() for accumulator in accumulators)


def _canonical_tasks(
    context: SigmaContextV3,
    binding: PersistentBinding,
    round_index: int,
    state: bytes,
    layout: LayoutPlan,
) -> tuple[DeepBranchTaskV3, ...]:
    if context.round_profile is RoundProfileIdV3.DEEP:
        state_frame: RoundFrame | VectorRoundFrame = RoundFrame(
            context, binding, layout, round_index, state
        )
    elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        state_frame = VectorRoundFrame(context, binding, layout, round_index, state)
    else:
        raise ValueError("context is not a Deep suite")
    return tuple(
        DeepBranchTaskV3(
            position,
            algorithm,
            DeepBranchFrame(context, round_index, position, algorithm, state_frame).to_bytes(),
        )
        for position, algorithm in enumerate(context.joint_algorithms)
    )


def _transition(
    context: SigmaContextV3,
    binding: PersistentBinding,
    round_index: int,
    state: bytes,
    backend: DeepBranchBackendV3,
) -> tuple[LayoutPlan, tuple[bytes, ...], bytes]:
    if not isinstance(state, bytes) or len(state) != context.state_size:
        raise ValueError("state width does not match context")
    layout = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=round_index,
        base_length=len(state),
    )
    branches = execute_deep_tasks_v3(
        backend,
        _canonical_tasks(context, binding, round_index, state, layout),
    )
    if context.round_profile is RoundProfileIdV3.DEEP:
        successor = hash_bytes(
            context.state_algorithm,
            DomainIdV3.DEEP_FOLD,
            DeepFoldFrame(context, round_index, branches).to_bytes(),
        )
    elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        successor = b"".join(branches)
    else:
        raise ValueError("context is not a Deep suite")
    if len(successor) != context.state_size:
        raise RuntimeError("Deep successor width does not match suite")
    return layout, branches, successor


def next_deep_state_v3(
    context: SigmaContextV3,
    binding: PersistentBinding,
    round_index: int,
    state: bytes,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
) -> bytes:
    _require_profile(context, RoundProfileIdV3.DEEP)
    return _transition(context, binding, round_index, state, backend)[2]


def next_deep_vector_state_v3(
    context: SigmaContextV3,
    binding: PersistentBinding,
    round_index: int,
    state: bytes,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
) -> bytes:
    _require_profile(context, RoundProfileIdV3.DEEP_VECTOR)
    return _transition(context, binding, round_index, state, backend)[2]


def _validate_evaluation(
    evaluation: DeepEvaluationLikeV3,
    profile: RoundProfileIdV3,
) -> None:
    _require_profile(evaluation.context, profile)
    if not isinstance(evaluation.prepared, PreparedBindingV3):
        raise TypeError("prepared must be PreparedBindingV3")
    binding = evaluation.prepared.binding
    if derive_trajectory_parameters(evaluation.context, binding) != evaluation.parameters:
        raise ValueError("parameters do not match context and binding")
    expected_init = derive_layout_v3(
        evaluation.context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=binding.cardinality.byte_length,
    )
    if evaluation.init_layout != expected_init:
        raise ValueError("init layout does not match context and binding")
    expected_states = evaluation.parameters.target_round + evaluation.parameters.state_count
    if len(evaluation.states) != expected_states:
        raise ValueError("trace does not cover requested window")
    if len(evaluation.round_layouts) != len(evaluation.states) - 1:
        raise ValueError("one round layout required per transition")
    if len(evaluation.branch_outputs) != len(evaluation.round_layouts):
        raise ValueError("one branch set required per transition")
    if any(len(state) != evaluation.context.state_size for state in evaluation.states):
        raise ValueError("trace contains state with incorrect width")
    expected_header = PublicTrajectoryHeader(
        binding.cardinality,
        binding.anchor,
        binding.length_signature,
        evaluation.parameters,
    )
    if evaluation.header != expected_header:
        raise ValueError("header does not match prepared binding")
    expected_window = TrajectoryWindow(
        evaluation.parameters,
        evaluation.states[evaluation.parameters.target_round :],
    )
    if evaluation.window != expected_window:
        raise ValueError("window does not match trace tail")

    for index, (layout, branches, state, successor) in enumerate(
        zip(
            evaluation.round_layouts,
            evaluation.branch_outputs,
            evaluation.states[:-1],
            evaluation.states[1:],
            strict=True,
        )
    ):
        expected_layout = derive_layout_v3(
            evaluation.context,
            binding,
            kind=LayoutKindV3.ROUND,
            round_index=index,
            base_length=len(state),
        )
        if layout != expected_layout:
            raise ValueError("round layout does not match trajectory")
        expected_branches = execute_deep_tasks_v3(
            SERIAL_DEEP_BRANCH_BACKEND_V3,
            _canonical_tasks(evaluation.context, binding, index, state, layout),
        )
        if branches != expected_branches:
            raise ValueError("branch outputs do not match canonical tasks")
        if profile is RoundProfileIdV3.DEEP:
            expected_successor = hash_bytes(
                evaluation.context.state_algorithm,
                DomainIdV3.DEEP_FOLD,
                DeepFoldFrame(evaluation.context, index, branches).to_bytes(),
            )
        else:
            expected_successor = b"".join(branches)
        if successor != expected_successor:
            raise ValueError("state transition does not match Deep profile")


def _evaluate(
    context: SigmaContextV3,
    source: CanonicalSource,
    backend: DeepBranchBackendV3,
    evaluation_type: type[DeepEvaluationV3] | type[DeepVectorEvaluationV3],
) -> DeepEvaluationLikeV3:
    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")
    if not isinstance(backend, DeepBranchBackendV3):
        raise TypeError("backend must be DeepBranchBackendV3")
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
    states = [state]
    layouts: list[LayoutPlan] = []
    branch_outputs: list[tuple[bytes, ...]] = []
    transition_count = parameters.target_round + parameters.state_count - 1
    for round_index in range(transition_count):
        layout, branches, state = _transition(context, binding, round_index, state, backend)
        layouts.append(layout)
        branch_outputs.append(branches)
        states.append(state)
    state_tuple = tuple(states)
    header = PublicTrajectoryHeader(
        binding.cardinality,
        binding.anchor,
        binding.length_signature,
        parameters,
    )
    window = TrajectoryWindow(parameters, state_tuple[parameters.target_round :])
    evaluation = object.__new__(evaluation_type)
    object.__setattr__(evaluation, "context", context)
    object.__setattr__(evaluation, "prepared", prepared)
    object.__setattr__(evaluation, "parameters", parameters)
    object.__setattr__(evaluation, "init_layout", init_layout)
    object.__setattr__(evaluation, "round_layouts", tuple(layouts))
    object.__setattr__(evaluation, "branch_outputs", tuple(branch_outputs))
    object.__setattr__(evaluation, "states", state_tuple)
    object.__setattr__(evaluation, "header", header)
    object.__setattr__(evaluation, "window", window)
    evaluation._validate()
    return evaluation


def evaluate_deep_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
) -> DeepEvaluationV3:
    _require_profile(context, RoundProfileIdV3.DEEP)
    evaluation = _evaluate(context, source, backend, DeepEvaluationV3)
    assert isinstance(evaluation, DeepEvaluationV3)
    return evaluation


def evaluate_deep_vector_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
) -> DeepVectorEvaluationV3:
    _require_profile(context, RoundProfileIdV3.DEEP_VECTOR)
    evaluation = _evaluate(context, source, backend, DeepVectorEvaluationV3)
    assert isinstance(evaluation, DeepVectorEvaluationV3)
    return evaluation


def evaluate_deep_bytes_v3(
    context: SigmaContextV3,
    message: bytes,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
) -> DeepEvaluationV3:
    return evaluate_deep_v3(context, BytesSource(message), backend)


def evaluate_deep_vector_bytes_v3(
    context: SigmaContextV3,
    message: bytes,
    backend: DeepBranchBackendV3 = SERIAL_DEEP_BRANCH_BACKEND_V3,
) -> DeepVectorEvaluationV3:
    return evaluate_deep_vector_v3(context, BytesSource(message), backend)


__all__ = [
    "DeepEvaluationV3",
    "DeepVectorEvaluationV3",
    "evaluate_deep_bytes_v3",
    "evaluate_deep_v3",
    "evaluate_deep_vector_bytes_v3",
    "evaluate_deep_vector_v3",
    "next_deep_state_v3",
    "next_deep_vector_state_v3",
]
