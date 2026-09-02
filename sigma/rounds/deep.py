"""Deep profile: every branch is evaluated at every sequential level."""

from typing import List, Tuple

from sigma.anchors.base import CrossWideEvidence
from sigma.anchors.branches import hash_once
from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import DomainId, RoundProfileId
from sigma.suites.registry import get_suite

from .wide_once import RoundTranscript


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
        if isinstance(index, bool) or not 0 <= index < 1 << 64:
            raise ValueError("round index must fit in an unsigned 64-bit integer")
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

    def evaluate(self, anchor: CrossWideEvidence):
        state = self._initial_state(anchor)
        states: List[bytes] = [state]
        outputs: List[Tuple[bytes, ...]] = []
        last_index = self.context.target_round + self.context.state_count - 1
        for index in range(last_index):
            state, round_outputs = self._next_with_branches(anchor, index, state)
            states.append(state)
            outputs.append(round_outputs)
        selected = tuple(states[self.context.target_round : last_index + 1])
        return (
            SigmaDigestV2(self.context, selected),
            RoundTranscript(tuple(states), tuple(outputs)),
        )
