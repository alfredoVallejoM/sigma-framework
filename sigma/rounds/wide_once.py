"""Reference WideOnce transition with persistent anchor reinjection."""

import warnings
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Union

from sigma.anchors.base import AnchorEvidence, CrossWideEvidence
from sigma.anchors.branches import hash_once
from sigma.outputs.digest import SigmaDigestV2
from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import AnchorProfileId, DomainId
from sigma.suites.registry import get_suite
from sigma.validation import require_int


@dataclass(frozen=True)
class RoundTranscript:
    """Diagnostic trace. Callers must avoid persisting secret-bearing inputs."""

    states: Tuple[bytes, ...]
    branch_outputs: Tuple[Tuple[bytes, ...], ...] = ()
    state_indices: Tuple[int, ...] = ()
    branch_output_indices: Tuple[int, ...] = ()


class TracePolicy(Enum):
    NONE = "none"
    SELECTED = "selected"
    EVERY_N = "every-n"
    FULL = "full"


@dataclass(frozen=True)
class TraceConfig:
    policy: TracePolicy = TracePolicy.FULL
    selected_indices: Tuple[int, ...] = ()
    every_n: int = 1
    max_entries: int = 100_000

    def __post_init__(self) -> None:
        if not isinstance(self.policy, TracePolicy):
            raise TypeError("policy must be TracePolicy")
        for index in self.selected_indices:
            require_int("selected trace index", index, minimum=0, maximum=(1 << 64) - 1)
        if len(set(self.selected_indices)) != len(self.selected_indices):
            raise ValueError("selected trace indices must be unique")
        require_int("every_n", self.every_n, minimum=1, maximum=(1 << 64) - 1)
        require_int("max_entries", self.max_entries, minimum=0, maximum=(1 << 64) - 1)

    def captures(self, index: int) -> bool:
        if self.policy is TracePolicy.NONE:
            return False
        if self.policy is TracePolicy.FULL:
            return True
        if self.policy is TracePolicy.SELECTED:
            return index in self.selected_indices
        return index % self.every_n == 0

    def validate_budget(self, last_state_index: int) -> None:
        if self.policy is TracePolicy.FULL:
            requested = last_state_index + 1
        elif self.policy is TracePolicy.SELECTED:
            requested = sum(index <= last_state_index for index in self.selected_indices)
        elif self.policy is TracePolicy.EVERY_N:
            requested = last_state_index // self.every_n + 1
        else:
            requested = 0
        if requested > self.max_entries:
            raise ValueError(
                f"trace requests {requested} entries, exceeding max_entries={self.max_entries}"
            )
        if self.policy is TracePolicy.FULL and requested > 4096:
            warnings.warn(
                "FULL trace retention grows linearly with target_round; use NONE or a sampled policy",
                ResourceWarning,
                stacklevel=3,
            )


class WideOnce:
    def __init__(self, context: SigmaContextV2):
        self.context = context
        self.suite = get_suite(context.suite_id)
        self.suite.validate_context(context)

    def _validate_anchor(self, anchor: Union[AnchorEvidence, CrossWideEvidence]) -> None:
        expected_type = (
            CrossWideEvidence
            if self.context.anchor_profile is AnchorProfileId.CROSS_WIDE
            else AnchorEvidence
        )
        if not isinstance(anchor, expected_type):
            raise TypeError(f"anchor must be {expected_type.__name__}")
        if anchor.algorithms != self.context.branches:
            raise ValueError("anchor branch descriptors differ from context")
        if any(len(root) != 64 for root in anchor.roots):
            raise ValueError("reference suite anchor roots must contain 64 bytes")
        if isinstance(anchor, CrossWideEvidence) and any(
            len(root) != 64 for root in anchor.cross_roots
        ):
            raise ValueError("reference suite cross roots must contain 64 bytes")

    def _initial_state(self, anchor: Union[AnchorEvidence, CrossWideEvidence]) -> bytes:
        self._validate_anchor(anchor)
        framed = encode_tlv(((1, self.context.to_bytes()), (2, anchor.to_bytes())))
        return hash_once(self.suite.state_algorithm, domain_tag(DomainId.INIT) + framed)

    def next_state(
        self,
        anchor: Union[AnchorEvidence, CrossWideEvidence],
        index: int,
        state: bytes,
    ) -> bytes:
        self._validate_anchor(anchor)
        require_int("round index", index, minimum=0, maximum=(1 << 64) - 1)
        if not isinstance(state, bytes) or len(state) != self.suite.state_size:
            raise ValueError(f"state must contain exactly {self.suite.state_size} bytes")
        framed = encode_tlv(
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(index, 8)),
                (3, anchor.to_bytes()),
                (4, state),
            )
        )
        return hash_once(self.suite.state_algorithm, domain_tag(DomainId.ROUND) + framed)

    def evaluate_digest(
        self, anchor: Union[AnchorEvidence, CrossWideEvidence]
    ) -> SigmaDigestV2:
        """Evaluate with memory bounded by the published state window ``k``."""

        self._validate_anchor(anchor)
        state = self._initial_state(anchor)
        selected = deque((state,), maxlen=self.context.state_count)
        last_index = self.context.target_round + self.context.state_count - 1
        for index in range(last_index):
            state = self.next_state(anchor, index, state)
            selected.append(state)
        return SigmaDigestV2(self.context, tuple(selected))

    def evaluate_trace(
        self,
        anchor: Union[AnchorEvidence, CrossWideEvidence],
        trace: Optional[TraceConfig] = None,
    ) -> Tuple[SigmaDigestV2, RoundTranscript]:
        self._validate_anchor(anchor)
        trace = trace if trace is not None else TraceConfig()
        last_index = self.context.target_round + self.context.state_count - 1
        trace.validate_budget(last_index)
        state = self._initial_state(anchor)
        selected = deque((state,), maxlen=self.context.state_count)
        states = [state] if trace.captures(0) else []
        indices = [0] if trace.captures(0) else []
        for index in range(last_index):
            state = self.next_state(anchor, index, state)
            state_index = index + 1
            selected.append(state)
            if trace.captures(state_index):
                states.append(state)
                indices.append(state_index)
        return (
            SigmaDigestV2(self.context, tuple(selected)),
            RoundTranscript(tuple(states), state_indices=tuple(indices)),
        )

    def evaluate(
        self, anchor: Union[AnchorEvidence, CrossWideEvidence]
    ) -> Tuple[SigmaDigestV2, RoundTranscript]:
        """Compatibility alias for an explicit full diagnostic trace."""

        last_index = self.context.target_round + self.context.state_count - 1
        return self.evaluate_trace(
            anchor,
            TraceConfig(policy=TracePolicy.FULL, max_entries=last_index + 1),
        )
