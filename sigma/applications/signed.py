"""Ed25519-authenticated commitments to v2-2 anchor evidence and states."""

import hmac
from dataclasses import dataclass
from typing import Union

from sigma.anchors import AnchorEvidence, CrossWide, CrossWideEvidence, StreamWide, TreeWide
from sigma.anchors.base import parse_evidence
from sigma.outputs import SigmaDigestV2
from sigma.policy import DEFAULT_RESOURCE_POLICY, PolicyViolation, ResourcePolicy
from sigma.rounds import Deep, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import (
    DecodeError,
    decode_tlv,
    decode_uint,
    domain_tag,
    encode_tlv,
    encode_uint,
)
from sigma.spec.ids import (
    AnchorProfileId,
    DomainId,
    RoundProfileId,
    SignatureAlgorithmId,
)
from sigma.suites.registry import get_suite
from sigma.version import SIGNED_COMMITMENT_WIRE_VERSION

SIGNED_COMMITMENT_MAGIC = b"SIGMASIG"
SIGNED_FIELDS = frozenset(range(1, 7))
MAX_PUBLIC_KEY_ID_LENGTH = 255
ED25519_PRIVATE_KEY_LENGTH = 32
ED25519_PUBLIC_KEY_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64

Evidence = Union[AnchorEvidence, CrossWideEvidence]


def _validate_public_key_id(public_key_id: bytes) -> None:
    if not isinstance(public_key_id, bytes) or not (
        1 <= len(public_key_id) <= MAX_PUBLIC_KEY_ID_LENGTH
    ):
        raise ValueError("public_key_id must contain 1..255 bytes")


def _encode_states(states: tuple[bytes, ...]) -> bytes:
    return encode_uint(len(states), 2) + b"".join(
        encode_uint(len(state), 2) + state for state in states
    )


def _decode_states(data: bytes) -> tuple[bytes, ...]:
    if len(data) < 2:
        raise DecodeError("truncated signed state count")
    count = decode_uint(data[:2], 2)
    offset = 2
    states = []
    for _ in range(count):
        if offset + 2 > len(data):
            raise DecodeError("truncated signed state length")
        length = decode_uint(data[offset : offset + 2], 2)
        offset += 2
        end = offset + length
        if end > len(data):
            raise DecodeError("truncated signed state")
        states.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise DecodeError("trailing signed state bytes")
    return tuple(states)


@dataclass(frozen=True)
class SigmaSignedCommitmentV2:
    context: SigmaContextV2
    anchor_evidence: Evidence
    states: tuple[bytes, ...]
    signature_algorithm: SignatureAlgorithmId
    public_key_id: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV2):
            raise TypeError("context must be SigmaContextV2")
        if not isinstance(self.anchor_evidence, (AnchorEvidence, CrossWideEvidence)):
            raise TypeError("anchor_evidence must be canonical anchor evidence")
        if not isinstance(self.states, tuple) or not all(
            isinstance(state, bytes) for state in self.states
        ):
            raise TypeError("states must be a tuple of bytes")
        suite = get_suite(self.context.suite_id)
        if suite.suite_family != "v2-2":
            raise ValueError("signed commitments require a v2-2 suite")
        if parse_evidence(self.anchor_evidence.to_bytes(), self.context) != self.anchor_evidence:
            raise ValueError("anchor evidence does not match the signed context")
        SigmaDigestV2(self.context, self.states)
        if self.signature_algorithm is not SignatureAlgorithmId.ED25519:
            raise ValueError("unsupported signature algorithm")
        _validate_public_key_id(self.public_key_id)
        if not isinstance(self.signature, bytes) or len(self.signature) != ED25519_SIGNATURE_LENGTH:
            raise ValueError("Ed25519 signature must contain exactly 64 bytes")

    def _fields_without_signature(self) -> tuple[tuple[int, bytes], ...]:
        return (
            (1, self.context.to_bytes()),
            (2, self.anchor_evidence.to_bytes()),
            (3, _encode_states(self.states)),
            (4, encode_uint(self.signature_algorithm, 2)),
            (5, self.public_key_id),
        )

    def unsigned_bytes(self) -> bytes:
        return (
            SIGNED_COMMITMENT_MAGIC
            + encode_uint(SIGNED_COMMITMENT_WIRE_VERSION, 2)
            + encode_tlv(self._fields_without_signature())
        )

    def signing_input(self) -> bytes:
        return domain_tag(DomainId.SIGNED_COMMITMENT) + self.unsigned_bytes()

    def to_bytes(self) -> bytes:
        return self.unsigned_bytes() + encode_tlv(((6, self.signature),))

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaSignedCommitmentV2":
        header_size = len(SIGNED_COMMITMENT_MAGIC) + 2
        if (
            not isinstance(data, bytes)
            or len(data) < header_size
            or not data.startswith(SIGNED_COMMITMENT_MAGIC)
        ):
            raise DecodeError("invalid signed commitment magic")
        version = decode_uint(data[len(SIGNED_COMMITMENT_MAGIC) : header_size], 2)
        if version != SIGNED_COMMITMENT_WIRE_VERSION:
            raise DecodeError(f"unsupported signed commitment version: {version}")
        fields = decode_tlv(data[header_size:], allowed_tags=SIGNED_FIELDS)
        if set(fields) != set(SIGNED_FIELDS):
            raise DecodeError("missing signed commitment fields")
        try:
            context = SigmaContextV2.from_bytes(fields[1])
            algorithm = SignatureAlgorithmId(decode_uint(fields[4], 2))
            return cls(
                context,
                parse_evidence(fields[2], context),
                _decode_states(fields[3]),
                algorithm,
                fields[5],
                fields[6],
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid signed commitment: {exc}") from exc

    @property
    def digest(self) -> SigmaDigestV2:
        return SigmaDigestV2(self.context, self.states)


def _anchor_for_message(data: bytes, context: SigmaContextV2) -> Evidence:
    if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
        return StreamWide.compute(context, (data,))
    if context.anchor_profile is AnchorProfileId.CROSS_WIDE:
        return CrossWide.compute(context, (data,))
    if context.anchor_profile is AnchorProfileId.TREE_WIDE:
        return TreeWide.compute(context, (data,))
    raise ValueError("unsupported signed anchor profile")


def _digest_from_anchor(context: SigmaContextV2, anchor: Evidence) -> SigmaDigestV2:
    if context.round_profile is RoundProfileId.WIDE_ONCE:
        return WideOnce(context).evaluate_digest(anchor)
    if context.round_profile is RoundProfileId.DEEP:
        if not isinstance(anchor, CrossWideEvidence):
            raise ValueError("Deep signed commitments require CrossWide evidence")
        return Deep(context).evaluate_digest(anchor)
    raise ValueError("unsupported signed round profile")


def sign_ed25519(
    data: bytes,
    context: SigmaContextV2,
    private_key: bytes,
    public_key_id: bytes,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaSignedCommitmentV2:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(private_key, bytes) or len(private_key) != ED25519_PRIVATE_KEY_LENGTH:
        raise ValueError("Ed25519 private key must contain exactly 32 bytes")
    _validate_public_key_id(public_key_id)
    policy.validate_context(context)
    policy.validate_message_size(len(data))
    anchor = _anchor_for_message(data, context)
    digest = _digest_from_anchor(context, anchor)
    unsigned = SigmaSignedCommitmentV2(
        context,
        anchor,
        digest.states,
        SignatureAlgorithmId.ED25519,
        public_key_id,
        b"\x00" * ED25519_SIGNATURE_LENGTH,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(unsigned.signing_input())
    return SigmaSignedCommitmentV2(
        context, anchor, digest.states, unsigned.signature_algorithm, public_key_id, signature
    )


def verify_signed_attestation(
    commitment: SigmaSignedCommitmentV2,
    public_key: bytes,
    *,
    expected_public_key_id: bytes | None = None,
) -> bool:
    if not isinstance(commitment, SigmaSignedCommitmentV2):
        raise TypeError("commitment must be SigmaSignedCommitmentV2")
    if not isinstance(public_key, bytes) or len(public_key) != ED25519_PUBLIC_KEY_LENGTH:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")
    if expected_public_key_id is not None and not hmac.compare_digest(
        commitment.public_key_id, expected_public_key_id
    ):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            commitment.signature, commitment.signing_input()
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_full_signed(
    data: bytes,
    commitment: SigmaSignedCommitmentV2,
    public_key: bytes,
    *,
    expected_public_key_id: bytes | None = None,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    if not verify_signed_attestation(
        commitment, public_key, expected_public_key_id=expected_public_key_id
    ):
        return False
    try:
        policy.validate_context(commitment.context)
        policy.validate_message_size(len(data))
        anchor = _anchor_for_message(data, commitment.context)
        digest = _digest_from_anchor(commitment.context, anchor)
    except (PolicyViolation, TypeError, ValueError):
        return False
    return hmac.compare_digest(
        anchor.to_bytes(), commitment.anchor_evidence.to_bytes()
    ) and hmac.compare_digest(digest.to_bytes(), commitment.digest.to_bytes())
