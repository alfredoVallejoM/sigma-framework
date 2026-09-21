"""Ed25519 authentication for canonical Sigma v3 digest bytes."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import IntEnum

from sigma.crypto.primitives import domain_tag_v3
from sigma.outputs.digest_v3 import SigmaDigestV3, verify_full_v3
from sigma.sources import CanonicalSource
from sigma.spec.codec_v3 import decode_record, encode_record, validate_record_prefix
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids import SignatureAlgorithmId
from sigma.spec.ids_v3 import DomainIdV3


class _SignedField(IntEnum):
    DOMAIN = 1
    DIGEST = 2
    ALGORITHM = 3
    PUBLIC_KEY_ID = 4
    SIGNATURE = 5


@dataclass(frozen=True)
class SigmaSignedCommitmentV3:
    """A signature over one exact ``SigmaDigestV3.to_bytes()`` value."""

    digest: SigmaDigestV3
    signature_algorithm: SignatureAlgorithmId
    public_key_id: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.digest, SigmaDigestV3):
            raise TypeError("digest must be SigmaDigestV3")
        if self.signature_algorithm is not SignatureAlgorithmId.ED25519:
            raise ValueError("unsupported signature algorithm")
        _validate_public_key_id(self.public_key_id)
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("signature must contain exactly 64 bytes")

    def _unsigned_fields(self) -> tuple[tuple[int, bytes], ...]:
        return (
            (_SignedField.DOMAIN, domain_tag_v3(DomainIdV3.SIGNED_COMMITMENT)),
            (_SignedField.DIGEST, self.digest.to_bytes()),
            (_SignedField.ALGORITHM, encode_uint(self.signature_algorithm, 2)),
            (_SignedField.PUBLIC_KEY_ID, self.public_key_id),
        )

    def unsigned_bytes(self) -> bytes:
        return encode_record(SIGNED_V3_MAGIC, self._unsigned_fields())

    def signing_input(self) -> bytes:
        return domain_tag_v3(DomainIdV3.SIGNED_COMMITMENT) + self.unsigned_bytes()

    def to_bytes(self) -> bytes:
        return encode_record(
            SIGNED_V3_MAGIC,
            (*self._unsigned_fields(), (_SignedField.SIGNATURE, self.signature)),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SigmaSignedCommitmentV3:
        validate_record_prefix(
            data,
            magic=SIGNED_V3_MAGIC,
            expected_fields=(
                (
                    int(_SignedField.DOMAIN),
                    domain_tag_v3(DomainIdV3.SIGNED_COMMITMENT),
                ),
            ),
        )
        fields = decode_record(
            data,
            magic=SIGNED_V3_MAGIC,
            allowed_tags=_SIGNED_FIELDS,
            required_tags=_SIGNED_FIELDS,
        )
        try:
            algorithm = SignatureAlgorithmId(decode_uint(fields[_SignedField.ALGORITHM], 2))
            return cls(
                SigmaDigestV3.from_bytes(fields[_SignedField.DIGEST]),
                algorithm,
                fields[_SignedField.PUBLIC_KEY_ID],
                fields[_SignedField.SIGNATURE],
            )
        except DecodeError:
            raise
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 signed commitment") from exc


def sign_digest_ed25519_v3(
    digest: SigmaDigestV3,
    private_key: bytes,
    public_key_id: bytes,
) -> SigmaSignedCommitmentV3:
    """Sign the canonical digest wire; this makes no message-history claim."""
    if not isinstance(digest, SigmaDigestV3):
        raise TypeError("digest must be SigmaDigestV3")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError("private key must contain exactly 32 bytes")
    _validate_public_key_id(public_key_id)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - dependency-specific
        raise RuntimeError("Ed25519 support requires the signatures extra") from exc

    placeholder = SigmaSignedCommitmentV3(
        digest,
        SignatureAlgorithmId.ED25519,
        public_key_id,
        bytes(64),
    )
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(placeholder.signing_input())
    return SigmaSignedCommitmentV3(
        digest,
        SignatureAlgorithmId.ED25519,
        public_key_id,
        signature,
    )


def verify_signed_digest_v3(
    commitment: SigmaSignedCommitmentV3,
    public_key: bytes,
    *,
    expected_public_key_id: bytes | None = None,
) -> bool:
    """Authenticate the digest wire without claiming message recomputation."""
    if not isinstance(commitment, SigmaSignedCommitmentV3):
        raise TypeError("commitment must be SigmaSignedCommitmentV3")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    if expected_public_key_id is not None:
        _validate_public_key_id(expected_public_key_id)
        if not hmac.compare_digest(commitment.public_key_id, expected_public_key_id):
            return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - dependency-specific
        raise RuntimeError("Ed25519 support requires the signatures extra") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            commitment.signature,
            commitment.signing_input(),
        )
    except InvalidSignature:
        return False
    return True


def verify_full_signed_v3(
    source: CanonicalSource,
    commitment: SigmaSignedCommitmentV3,
    public_key: bytes,
    *,
    expected_public_key_id: bytes | None = None,
) -> bool:
    """Authenticate the digest and independently recompute its message binding."""
    if not verify_signed_digest_v3(
        commitment,
        public_key,
        expected_public_key_id=expected_public_key_id,
    ):
        return False
    return verify_full_v3(source, commitment.digest)


def _validate_public_key_id(public_key_id: bytes) -> None:
    if not isinstance(public_key_id, bytes) or not 1 <= len(public_key_id) <= 255:
        raise ValueError("public_key_id must contain 1..255 bytes")


SIGNED_V3_MAGIC = b"SIG3SIGN"
_SIGNED_FIELDS = frozenset(int(field) for field in _SignedField)

__all__ = [
    "SigmaSignedCommitmentV3",
    "sign_digest_ed25519_v3",
    "verify_full_signed_v3",
    "verify_signed_digest_v3",
]
