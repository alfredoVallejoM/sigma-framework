from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sigma.applications.signed import (
    SigmaSignedCommitmentV2,
    sign_ed25519,
    verify_full_signed,
    verify_signed_attestation,
)
from sigma.presets import lightweight_v2_2, paranoid_deep_v2_2
from sigma.spec.encoding import DecodeError

PRIVATE_KEY = bytes(range(32))
PUBLIC_KEY = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY).public_key().public_bytes_raw()
KEY_ID = b"test-key-2026"


@pytest.mark.parametrize("context", [lightweight_v2_2(target_round=2), paranoid_deep_v2_2()])
def test_signed_commitment_round_trip_and_full_verification(context) -> None:
    commitment = sign_ed25519(b"signed message", context, PRIVATE_KEY, KEY_ID)
    assert SigmaSignedCommitmentV2.from_bytes(commitment.to_bytes()) == commitment
    assert verify_signed_attestation(commitment, PUBLIC_KEY, expected_public_key_id=KEY_ID)
    assert verify_full_signed(
        b"signed message", commitment, PUBLIC_KEY, expected_public_key_id=KEY_ID
    )
    assert not verify_full_signed(b"different", commitment, PUBLIC_KEY)


def test_attestation_does_not_claim_state_history() -> None:
    commitment = sign_ed25519(b"history", lightweight_v2_2(), PRIVATE_KEY, KEY_ID)
    false_state = bytes([commitment.states[0][0] ^ 1]) + commitment.states[0][1:]
    unsigned_false_claim = replace(
        commitment,
        states=(false_state, *commitment.states[1:]),
        signature=b"\x00" * 64,
    )
    signature = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY).sign(
        unsigned_false_claim.signing_input()
    )
    false_claim = replace(unsigned_false_claim, signature=signature)
    assert verify_signed_attestation(false_claim, PUBLIC_KEY)
    assert not verify_full_signed(b"history", false_claim, PUBLIC_KEY)


def test_signature_authenticates_key_id_and_every_commitment_field() -> None:
    commitment = sign_ed25519(b"binding", lightweight_v2_2(), PRIVATE_KEY, KEY_ID)
    assert not verify_signed_attestation(commitment, PUBLIC_KEY, expected_public_key_id=b"other")
    corrupted = bytearray(commitment.signature)
    corrupted[0] ^= 1
    assert not verify_signed_attestation(
        replace(commitment, signature=bytes(corrupted)), PUBLIC_KEY
    )


def test_signed_profile_rejects_key_boundaries() -> None:
    with pytest.raises(ValueError, match="private key"):
        sign_ed25519(b"key", lightweight_v2_2(), b"short", KEY_ID)
    with pytest.raises(ValueError, match="public_key_id"):
        sign_ed25519(b"key", lightweight_v2_2(), PRIVATE_KEY, b"")


def test_every_truncated_signed_commitment_prefix_is_rejected() -> None:
    encoded = sign_ed25519(b"truncate", lightweight_v2_2(), PRIVATE_KEY, KEY_ID).to_bytes()
    for end in range(len(encoded)):
        with pytest.raises(DecodeError):
            SigmaSignedCommitmentV2.from_bytes(encoded[:end])
