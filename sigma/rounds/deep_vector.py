"""DeepVector profile retaining every branch across sequential levels."""

from collections import deque
from typing import List, Optional, Tuple

from sigma.anchors.base import CrossWideEvidence
from sigma.anchors.branches import hash_once
from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv_field, encode_uint
from sigma.spec.ids import DomainId, RoundProfileId
from sigma.suites.registry import get_suite
from sigma.validation import require_int

from .wide_once import RoundTranscript, TraceConfig, TracePolicy


class DeepVector:
    def __init__(self, context: SigmaContextV2):
        self.context = context
        self.suite = get_suite(context.suite_id)
        self.suite.validate_context(context)
        if context.round_profile is not RoundProfileId.DEEP_VECTOR:
            raise ValueError("DeepVector requires the DEEP_VECTOR round profile")

    def _validate_anchor(self, anchor: CrossWideEvidence) -> None:
        if not isinstance(anchor, CrossWideEvidence):
            raise TypeError("DeepVector requires CrossWideEvidence")
        if anchor.algorithms != self.context.branches:
            raise ValueError("anchor branch descriptors differ from context")
        if anchor.suite_id is not self.context.suite_id:
            raise ValueError("DeepVector anchor must carry the exact context suite")
        if any(
            len(root) != self.suite.anchor_component_size
            for root in anchor.roots + anchor.cross_roots
        ):
            raise ValueError("DeepVector anchor component width differs from the selected suite")

    def _initial_components(self, anchor: CrossWideEvidence) -> List[bytes]:
        self._validate_anchor(anchor)
        prefix = domain_tag(DomainId.VECTOR_INIT)
        common = encode_tlv_field(1, self.context.to_bytes())
        common += encode_tlv_field(2, anchor.to_bytes())
        return [
            hash_once(
                algorithm,
                prefix + common + encode_tlv_field(3, encode_uint(position, 2)),
            )
            for position, algorithm in enumerate(self.context.branches)
        ]

    def _next_with_components(
        self, anchor: CrossWideEvidence, index: int, vector: bytes
    ) -> Tuple[bytes, List[bytes]]:
        self._validate_anchor(anchor)
        require_int("round index", index, minimum=0, maximum=(1 << 64) - 1)
        if not isinstance(vector, bytes) or len(vector) != self.suite.state_size:
            raise ValueError(f"vector must contain exactly {self.suite.state_size} bytes")
        prefix = domain_tag(DomainId.VECTOR_ROUND)
        common = encode_tlv_field(1, self.context.to_bytes())
        common += encode_tlv_field(2, encode_uint(index, 8))
        common += encode_tlv_field(3, anchor.to_bytes())
        common += encode_tlv_field(4, vector)
        components = [
            hash_once(
                algorithm,
                prefix + common + encode_tlv_field(5, encode_uint(position, 2)),
            )
            for position, algorithm in enumerate(self.context.branches)
        ]
        return b"".join(components), components

    def _initial_state(self, anchor: CrossWideEvidence) -> bytes:
        return b"".join(self._initial_components(anchor))

    def next_state(self, anchor: CrossWideEvidence, index: int, state: bytes) -> bytes:
        successor, _ = self._next_with_components(anchor, index, state)
        return successor

    def evaluate_digest(self, anchor: CrossWideEvidence) -> SigmaDigestV2:
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
        initial_components = self._initial_components(anchor)
        state = b"".join(initial_components)
        selected = deque((state,), maxlen=self.context.state_count)
        states = [state] if trace.captures(0) else []
        state_indices = [0] if trace.captures(0) else []
        outputs = [tuple(initial_components)] if trace.captures(0) else []
        output_indices = [0] if trace.captures(0) else []
        for index in range(last_index):
            state, components = self._next_with_components(anchor, index, state)
            state_index = index + 1
            selected.append(state)
            if trace.captures(state_index):
                states.append(state)
                state_indices.append(state_index)
                outputs.append(tuple(components))
                output_indices.append(state_index)
        return (
            SigmaDigestV2(self.context, tuple(selected)),
            RoundTranscript(
                tuple(states), tuple(outputs), tuple(state_indices), tuple(output_indices)
            ),
        )

    def evaluate(self, anchor: CrossWideEvidence) -> Tuple[SigmaDigestV2, RoundTranscript]:
        last_index = self.context.target_round + self.context.state_count - 1
        return self.evaluate_trace(
            anchor, TraceConfig(policy=TracePolicy.FULL, max_entries=last_index + 1)
        )
