"""Pure mathematical branch operation shared by every Deep scheduler."""

from sigma.anchors.base import CrossWideEvidence
from sigma.anchors.branches import hash_once
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import AlgorithmId, DomainId


def evaluate_deep_branch(
    position: int,
    algorithm: AlgorithmId,
    context: SigmaContextV2,
    anchor: CrossWideEvidence,
    index: int,
    state: bytes,
) -> tuple[int, bytes]:
    framed = encode_tlv(
        (
            (1, context.to_bytes()),
            (2, encode_uint(index, 8)),
            (3, encode_uint(algorithm, 2)),
            (4, anchor.to_bytes()),
            (5, state),
        )
    )
    output = hash_once(algorithm, domain_tag(DomainId.DEEP) + framed)
    return position, output
