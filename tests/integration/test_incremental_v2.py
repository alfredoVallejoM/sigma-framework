import pytest

from sigma.incremental import IncrementalSigmaV2
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, SuiteId
from sigma.v2 import hash_bytes, verify_full


def cross_context() -> SigmaContextV2:
    return SigmaContextV2(
        suite_id=SuiteId.PARANOID_CROSS_WIDE_V2,
        anchor_profile=AnchorProfileId.CROSS_WIDE,
    )


@pytest.mark.parametrize("context", [SigmaContextV2(), cross_context()])
def test_checkpoint_is_provisional_and_does_not_finalize(
    context: SigmaContextV2,
) -> None:
    incremental = IncrementalSigmaV2(context)
    incremental.update(b"prefix")
    checkpoint = incremental.checkpoint()
    assert checkpoint.provisional is True
    assert checkpoint.offset == 6
    assert checkpoint.digest == hash_bytes(b"prefix", context)

    incremental.update(b" suffix")
    final = incremental.finalize()
    assert final == hash_bytes(b"prefix suffix", context)
    assert final != checkpoint.digest
    assert verify_full(b"prefix suffix", final)


def test_empty_incremental_finalization_is_canonical_and_nonzero() -> None:
    incremental = IncrementalSigmaV2(SigmaContextV2())
    digest = incremental.finalize()
    assert digest == hash_bytes(b"")
    assert all(state != b"\x00" * len(state) for state in digest.states)


def test_finalization_is_unique() -> None:
    incremental = IncrementalSigmaV2(SigmaContextV2())
    incremental.finalize()
    with pytest.raises(RuntimeError, match="finalized"):
        incremental.finalize()
    with pytest.raises(RuntimeError, match="finalized"):
        incremental.update(b"late")
    with pytest.raises(RuntimeError, match="finalized"):
        incremental.checkpoint()


def test_tree_profile_rejects_incremental_checkpoint_api() -> None:
    with pytest.raises(ValueError, match="stream-based"):
        IncrementalSigmaV2(
            SigmaContextV2(
                suite_id=SuiteId.SIMULTANEOUS_TREE_WIDE_V2,
                anchor_profile=AnchorProfileId.TREE_WIDE,
                chunk_size=65536,
            )
        )
