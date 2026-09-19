"""First end-to-end Sigma v3 reference trajectory."""

from __future__ import annotations

from dataclasses import dataclass, field

from sigma.binding import (
    PreparedBindingV3,
    PublicTrajectoryHeader,
    TrajectoryParameters,
    TrajectoryWindow,
    derive_trajectory_parameters,
    prepare_input_v3,
)
from sigma.crypto.primitives import HashAccumulator, hash_bytes
from sigma.layout import LayoutPlan, derive_layout_v3
from sigma.rounds.framing_v3 import InitFrame, RoundFrame
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3, LayoutKindV3


@dataclass(frozen=True)
class WideOnceEvaluationV3:
    context: SigmaContextV3
    prepared: PreparedBindingV3
    parameters: TrajectoryParameters
    init_layout: LayoutPlan
    round_layouts: tuple[LayoutPlan, ...]
    states: tuple[bytes, ...]
    header: PublicTrajectoryHeader
    window: TrajectoryWindow
    _source: CanonicalSource = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV3):
            raise TypeError("context must be SigmaContextV3")
        if not isinstance(self.prepared, PreparedBindingV3):
            raise TypeError("prepared must be PreparedBindingV3")
        if not isinstance(self._source, CanonicalSource):
            raise TypeError("_source must be CanonicalSource")
        binding = self.prepared.binding
        expected_parameters = derive_trajectory_parameters(self.context, binding)
        if self.parameters != expected_parameters:
            raise ValueError("parameters do not match context and binding")
        expected_init_layout = derive_layout_v3(
            self.context,
            binding,
            kind=LayoutKindV3.INIT,
            round_index=0,
            base_length=binding.cardinality.byte_length,
        )
        if self.init_layout != expected_init_layout:
            raise ValueError("init layout does not match context and binding")
        if len(self.states) != self.parameters.target_round + self.parameters.state_count:
            raise ValueError("trace does not cover the requested window")
        if len(self.round_layouts) != len(self.states) - 1:
            raise ValueError("one round layout is required per transition")
        if any(len(state) != self.context.state_size for state in self.states):
            raise ValueError("trace contains a state with incorrect width")
        init_hash = HashAccumulator(
            self.context.state_algorithm,
            DomainIdV3.INIT_FRAME,
        )
        InitFrame(
            self.context,
            self.prepared,
            self.init_layout,
            self._source,
        ).write_to(init_hash)
        if self.states[0] != init_hash.digest():
            raise ValueError("initial state does not match init frame and source")
        expected_header = PublicTrajectoryHeader(
            binding.cardinality,
            binding.anchor,
            binding.length_signature,
            self.parameters,
        )
        if self.header != expected_header:
            raise ValueError("header does not match prepared binding")
        expected_window = TrajectoryWindow(
            self.parameters, self.states[self.parameters.target_round :]
        )
        if self.window != expected_window:
            raise ValueError("window does not match trace tail")
        if self.window.states != self.states[self.parameters.target_round :]:
            raise ValueError("window does not match trace tail")
        for index, (layout, state, successor) in enumerate(
            zip(self.round_layouts, self.states[:-1], self.states[1:], strict=True)
        ):
            expected_layout = derive_layout_v3(
                self.context,
                binding,
                kind=LayoutKindV3.ROUND,
                round_index=index,
                base_length=len(state),
            )
            if layout != expected_layout:
                raise ValueError("round layout does not match trajectory")
            frame = RoundFrame(self.context, binding, layout, index, state)
            expected_successor = hash_bytes(
                self.context.state_algorithm,
                DomainIdV3.ROUND_FRAME,
                frame.to_bytes(),
            )
            if successor != expected_successor:
                raise ValueError("state transition does not match round frame")


def evaluate_wide_once_v3(context: SigmaContextV3, source: CanonicalSource) -> WideOnceEvaluationV3:
    """Evaluate the registered reference suite with a bounded public window."""

    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")

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
    init_hash = HashAccumulator(context.state_algorithm, DomainIdV3.INIT_FRAME)
    InitFrame(context, prepared, init_layout, source).write_to(init_hash)
    state = init_hash.digest()
    states = [state]
    round_layouts: list[LayoutPlan] = []
    last_state_index = parameters.target_round + parameters.state_count - 1
    for round_index in range(last_state_index):
        layout = derive_layout_v3(
            context,
            binding,
            kind=LayoutKindV3.ROUND,
            round_index=round_index,
            base_length=len(state),
        )
        frame = RoundFrame(context, binding, layout, round_index, state)
        state = hash_bytes(
            context.state_algorithm,
            DomainIdV3.ROUND_FRAME,
            frame.to_bytes(),
        )
        round_layouts.append(layout)
        states.append(state)

    state_tuple = tuple(states)
    header = PublicTrajectoryHeader(
        binding.cardinality,
        binding.anchor,
        binding.length_signature,
        parameters,
    )
    window = TrajectoryWindow(parameters, state_tuple[parameters.target_round :])
    return WideOnceEvaluationV3(
        context,
        prepared,
        parameters,
        init_layout,
        tuple(round_layouts),
        state_tuple,
        header,
        window,
        source,
    )


def evaluate_wide_once_bytes_v3(context: SigmaContextV3, message: bytes) -> WideOnceEvaluationV3:
    return evaluate_wide_once_v3(context, BytesSource(message))
