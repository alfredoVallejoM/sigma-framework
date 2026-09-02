import pytest

from sigma.backends.base import ExecutionBackend
from sigma.incremental import IncrementalSigmaV2
from sigma.policy import PolicyViolation, ResourcePolicy, classify_context
from sigma.presets import lightweight_v2
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId
from sigma.v2 import hash_bytes, verify_full


class RecordingBackend(ExecutionBackend):
    def __init__(self) -> None:
        self.called = False

    @property
    def name(self) -> str:
        return "recording"

    def compute_anchor(self, data: bytes, context: SigmaContextV2):
        self.called = True
        raise AssertionError("backend must not run after policy rejection")


def test_context_status_separates_shape_suite_and_policy() -> None:
    assert classify_context(object()).well_formed is False

    mismatched = SigmaContextV2(anchor_profile=AnchorProfileId.CROSS_WIDE)
    status = classify_context(mismatched)
    assert status.well_formed is True
    assert status.suite_valid is False
    assert status.policy_acceptable is False

    context = lightweight_v2(target_round=5)
    status = classify_context(context, ResourcePolicy(max_target_round=4))
    assert status.well_formed is True
    assert status.suite_valid is True
    assert status.policy_acceptable is False

    accepted = classify_context(context, ResourcePolicy(max_target_round=5))
    assert accepted.well_formed is accepted.suite_valid is accepted.policy_acceptable is True


def test_policy_rejects_context_before_backend_work() -> None:
    backend = RecordingBackend()
    context = lightweight_v2(target_round=5)
    with pytest.raises(PolicyViolation, match="target_round"):
        hash_bytes(
            b"payload",
            context,
            backend,
            policy=ResourcePolicy(max_target_round=4),
        )
    assert backend.called is False


def test_policy_rejects_message_before_backend_work() -> None:
    backend = RecordingBackend()
    with pytest.raises(PolicyViolation, match="message size"):
        hash_bytes(
            b"12345",
            lightweight_v2(),
            backend,
            policy=ResourcePolicy(max_message_bytes=4),
        )
    assert backend.called is False


def test_incremental_policy_rejects_before_mutating_state() -> None:
    incremental = IncrementalSigmaV2(
        lightweight_v2(), policy=ResourcePolicy(max_message_bytes=4)
    )
    with pytest.raises(PolicyViolation, match="message size"):
        incremental.update(b"12345")
    assert incremental.checkpoint().offset == 0
    incremental.update(b"1234")
    assert incremental.finalize() == hash_bytes(b"1234", lightweight_v2())


def test_policy_is_not_part_of_digest_bytes() -> None:
    context = lightweight_v2(target_round=3)
    strict = ResourcePolicy(name="strict", max_target_round=3, max_message_bytes=3)
    relaxed = ResourcePolicy(name="relaxed", max_target_round=9, max_message_bytes=99)
    assert hash_bytes(b"abc", context, policy=strict) == hash_bytes(
        b"abc", context, policy=relaxed
    )
    assert strict.as_dict()["name"] == "strict"


def test_verifier_turns_policy_rejection_into_false() -> None:
    context = lightweight_v2(target_round=5)
    digest = hash_bytes(b"abc", context, policy=ResourcePolicy(max_target_round=5))
    assert not verify_full(
        b"abc", digest, policy=ResourcePolicy(max_target_round=4)
    )


def test_pow_and_argon2_policy_limits_are_explicit() -> None:
    policy = ResourcePolicy(
        max_pow_difficulty_bits=8,
        max_pow_attempts=100,
        min_argon2_memory_kib=1024,
        max_argon2_memory_kib=2048,
        min_argon2_time_cost=2,
        max_argon2_time_cost=3,
    )
    policy.validate_pow(8, 100)
    policy.validate_argon2(1024, 2)
    with pytest.raises(PolicyViolation, match="difficulty"):
        policy.validate_pow(9)
    with pytest.raises(PolicyViolation, match="attempts"):
        policy.validate_pow(8, 101)
    with pytest.raises(PolicyViolation, match="memory"):
        policy.validate_argon2(512, 2)
    with pytest.raises(PolicyViolation, match="time"):
        policy.validate_argon2(1024, 1)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_target_round": 2, "max_target_round": 1},
        {"min_state_count": 3, "max_state_count": 2},
        {"min_argon2_memory_kib": 2, "max_argon2_memory_kib": 1},
        {"min_argon2_time_cost": 2, "max_argon2_time_cost": 1},
        {"max_message_bytes": True},
    ],
)
def test_invalid_resource_policies_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ResourcePolicy(**kwargs)  # type: ignore[arg-type]
