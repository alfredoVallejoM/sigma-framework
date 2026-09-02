import hashlib

import pytest

from sigma.anchors.branches import BranchHasher, hash_once
from sigma.spec.ids import AlgorithmId


@pytest.mark.parametrize(
    "algorithm,expected",
    [
        (AlgorithmId.SHA512, hashlib.sha512(b"abc").digest()),
        (AlgorithmId.SHA3_512, hashlib.sha3_512(b"abc").digest()),
        (AlgorithmId.BLAKE2B_512, hashlib.blake2b(b"abc", digest_size=64).digest()),
        (AlgorithmId.SHAKE256_512, hashlib.shake_256(b"abc").digest(64)),
    ],
)
def test_registered_primitive_configuration(algorithm: AlgorithmId, expected: bytes) -> None:
    assert hash_once(algorithm, b"abc") == expected


def test_branch_full_and_incremental_updates_match() -> None:
    incremental = BranchHasher(AlgorithmId.SHA3_512)
    incremental.update(b"a")
    incremental.update(b"bc")
    assert incremental.digest() == hash_once(AlgorithmId.SHA3_512, b"abc")


def test_branch_finalization_is_single_use() -> None:
    branch = BranchHasher(AlgorithmId.SHA512)
    branch.digest()
    with pytest.raises(RuntimeError, match="finalized"):
        branch.digest()
    with pytest.raises(RuntimeError, match="finalized"):
        branch.update(b"late")
