"""Deep profile: every branch is evaluated at every sequential level."""

from collections import deque
from typing import List, Optional, Tuple

from sigma.anchors.base import CrossWideEvidence
from sigma.anchors.branches import hash_once
from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import DomainId, RoundProfileId
from sigma.suites.registry import get_suite
from sigma.validation import require_int

from .wide_once import RoundTranscript, TraceConfig, TracePolicy


class Deep:
    def __init__(self, context: SigmaContextV2):
        self.context = context
        self.suite = get_suite(context.suite_id)
        self.suite.validate_context(context)
        if context.round_profile is not RoundProfileId.DEEP:
            raise ValueError("Deep requires the DEEP round profile")

    def _validate_anchor(self, anchor: CrossWideEvidence) -> None:
        if not isinstance(anchor, CrossWideEvidence):
            raise TypeError("Deep requires CrossWideEvidence")
        if anchor.algorithms != self.context.branches:
            raise ValueError("anchor branch descriptors differ from context")
        if any(len(root) != 64 for root in anchor.roots + anchor.cross_roots):
            raise ValueError("Deep suite anchor components must contain 64 bytes")

    def _initial_state(self, anchor: CrossWideEvidence) -> bytes:
        self._validate_anchor(anchor)
        framed = encode_tlv(((1, self.context.to_bytes()), (2, anchor.to_bytes())))
        return hash_once(self.suite.state_algorithm, domain_tag(DomainId.INIT) + framed)

    def _next_with_branches(
        self, anchor: CrossWideEvidence, index: int, state: bytes
    ) -> Tuple[bytes, Tuple[bytes, ...]]:
        self._validate_anchor(anchor)
        require_int("round index", index, minimum=0, maximum=(1 << 64) - 1)
        if not isinstance(state, bytes) or len(state) != self.suite.state_size:
            raise ValueError(f"state must contain exactly {self.suite.state_size} bytes")
        branch_outputs = []
        for algorithm in self.context.branches:
            framed = encode_tlv(
                (
                    (1, self.context.to_bytes()),
                    (2, encode_uint(index, 8)),
                    (3, encode_uint(algorithm, 2)),
                    (4, anchor.to_bytes()),
                    (5, state),
                )
            )
            branch_outputs.append(hash_once(algorithm, domain_tag(DomainId.DEEP) + framed))
        encoded_outputs = encode_uint(len(branch_outputs), 2) + b"".join(
            encode_uint(algorithm, 2) + encode_uint(len(output), 2) + output
            for algorithm, output in zip(self.context.branches, branch_outputs, strict=False)
        )
        fold_input = encode_tlv(
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(index, 8)),
                (3, anchor.to_bytes()),
                (4, encoded_outputs),
            )
        )
        successor = hash_once(
            self.suite.state_algorithm,
            domain_tag(DomainId.FOLD) + fold_input,
        )
        return successor, tuple(branch_outputs)

    def next_state(self, anchor: CrossWideEvidence, index: int, state: bytes) -> bytes:
        successor, _ = self._next_with_branches(anchor, index, state)
        return successor

    def evaluate_digest(self, anchor: CrossWideEvidence) -> SigmaDigestV2:
        """Evaluate without retaining diagnostic branch outputs or prior states."""

        self._validate_anchor(anchor)
        state = self._initial_state(anchor)
        selected = deque((state,), maxlen=self.context.state_count)
        last_index = self.context.target_round + self.context.state_count - 1
        for index in range(last_index):
            state = self.next_state(anchor, index, state)
            selected.append(state)
        return SigmaDigestV2(self.context, tuple(selected))

    def evaluate_trace(
        self, anchor: CrossWideEvidence, trace: Optional[TraceConfig] = None
    ) -> Tuple[SigmaDigestV2, RoundTranscript]:
        self._validate_anchor(anchor)
        trace = trace if trace is not None else TraceConfig()
        last_index = self.context.target_round + self.context.state_count - 1
        trace.validate_budget(last_index)
        state = self._initial_state(anchor)
        selected = deque((state,), maxlen=self.context.state_count)
        states: List[bytes] = [state] if trace.captures(0) else []
        state_indices: List[int] = [0] if trace.captures(0) else []
        outputs: List[Tuple[bytes, ...]] = []
        output_indices: List[int] = []
        for index in range(last_index):
            state, round_outputs = self._next_with_branches(anchor, index, state)
            state_index = index + 1
            selected.append(state)
            if trace.captures(state_index):
                states.append(state)
                state_indices.append(state_index)
            if trace.captures(index):
                outputs.append(round_outputs)
                output_indices.append(index)
        return (
            SigmaDigestV2(self.context, tuple(selected)),
            RoundTranscript(
                tuple(states),
                tuple(outputs),
                tuple(state_indices),
                tuple(output_indices),
            ),
        )

    def evaluate(self, anchor: CrossWideEvidence) -> Tuple[SigmaDigestV2, RoundTranscript]:
        """Compatibility alias for an explicit full diagnostic trace."""

        last_index = self.context.target_round + self.context.state_count - 1
        return self.evaluate_trace(
            anchor,
            TraceConfig(policy=TracePolicy.FULL, max_entries=last_index + 1),
        )
