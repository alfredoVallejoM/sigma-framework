"""Reference WideOnce transition with persistent anchor reinjection."""

from dataclasses import dataclass
from typing import Tuple, Union

from sigma.anchors.base import AnchorEvidence, CrossWideEvidence
from sigma.anchors.branches import hash_once
from sigma.outputs.digest import SigmaDigestV2
from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import AnchorProfileId, DomainId
from sigma.suites.registry import get_suite


@dataclass(frozen=True)
class RoundTranscript:
    """Diagnostic trace. Callers must avoid persisting secret-bearing inputs."""

    states: Tuple[bytes, ...]
    branch_outputs: Tuple[Tuple[bytes, ...], ...] = ()


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
        if isinstance(index, bool) or not 0 <= index < 1 << 64:
            raise ValueError("round index must fit in an unsigned 64-bit integer")
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

    def evaluate(
        self, anchor: Union[AnchorEvidence, CrossWideEvidence]
    ) -> Tuple[SigmaDigestV2, RoundTranscript]:
        self._validate_anchor(anchor)
        state = self._initial_state(anchor)
        states = [state]
        last_index = self.context.target_round + self.context.state_count - 1
        for index in range(last_index):
            state = self.next_state(anchor, index, state)
            states.append(state)
        selected = tuple(states[self.context.target_round : last_index + 1])
        return SigmaDigestV2(self.context, selected), RoundTranscript(tuple(states))
