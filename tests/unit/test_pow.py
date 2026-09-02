from dataclasses import replace

import pytest

from sigma.applications.pow import (
    PowParameters,
    PowPredicate,
    accepts,
    evaluate_nonce,
    solve,
    verify,
)
from sigma.outputs import SigmaDigestV2
from sigma.policy import ResourcePolicy
from sigma.spec import SigmaContextV2


def _parameters(predicate: PowPredicate, difficulty: int = 2) -> PowParameters:
    return PowParameters(b"challenge", 1, 2, predicate, difficulty)


@pytest.mark.parametrize("predicate", list(PowPredicate))
def test_pow_solver_and_full_verifier(predicate: PowPredicate) -> None:
    proof, attempts = solve(b"payload", _parameters(predicate), max_attempts=10_000)
    assert attempts >= 1
    assert verify(b"payload", proof, _parameters(predicate))
    assert not verify(b"changed", proof, _parameters(predicate))


def test_pow_binds_protocol_parameters() -> None:
    parameters = _parameters(PowPredicate.SINGLE_STATE, 0)
    assert PowParameters.from_bytes(parameters.to_bytes()) == parameters
    proof = evaluate_nonce(b"payload", 7, parameters)
    assert accepts(proof.digest, parameters)
    assert not accepts(proof.digest, replace(parameters, challenge=b"other"))


def test_pow_rejects_invalid_dual_state_and_nonce() -> None:
    with pytest.raises(ValueError, match="two states"):
        PowParameters(b"challenge", 1, 1, PowPredicate.DUAL_STATE, 1)
    with pytest.raises(ValueError, match="nonce"):
        evaluate_nonce(b"payload", -1, _parameters(PowPredicate.SINGLE_STATE))
    with pytest.raises(ValueError):
        PowParameters.from_bytes(_parameters(PowPredicate.SINGLE_STATE).to_bytes()[:-1])


@pytest.mark.parametrize("value", [True, 1.0, "1", -1, 2**64])
def test_pow_rejects_invalid_nonce_types_and_bounds(value: object) -> None:
    with pytest.raises((TypeError, ValueError), match="nonce"):
        evaluate_nonce(b"payload", value, _parameters(PowPredicate.SINGLE_STATE))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name,value",
    [("start_nonce", True), ("start_nonce", 1.0), ("max_attempts", "1"), ("max_attempts", 0)],
)
def test_pow_solver_rejects_invalid_numeric_inputs(name: str, value: object) -> None:
    arguments = {name: value}
    with pytest.raises(ValueError, match=name):
        solve(b"payload", _parameters(PowPredicate.SINGLE_STATE), **arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field,value",
    [("target_round", True), ("target_round", 1.0), ("state_count", "2"), ("difficulty_bits", 1.5)],
)
def test_pow_parameters_reject_non_integer_numeric_fields(field: str, value: object) -> None:
    values = {
        "challenge": b"challenge",
        "target_round": 1,
        "state_count": 2,
        "predicate": PowPredicate.SINGLE_STATE,
        "difficulty_bits": 1,
    }
    values[field] = value
    with pytest.raises(ValueError, match=field):
        PowParameters(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("state_size", [0, 1, 63, 65, 1024, 1025])
def test_pow_predicate_rejects_malformed_state_width_without_crashing(state_size: int) -> None:
    malformed = object.__new__(SigmaDigestV2)
    object.__setattr__(malformed, "context", SigmaContextV2())
    object.__setattr__(malformed, "states", (b"a" * state_size, b"b" * state_size))
    assert not accepts(malformed, _parameters(PowPredicate.CONCATENATED, 513))


def test_pow_policy_rejects_before_nonce_search_and_verification() -> None:
    parameters = _parameters(PowPredicate.SINGLE_STATE, 2)
    strict = ResourcePolicy(max_pow_difficulty_bits=1)
    with pytest.raises(ValueError, match="difficulty"):
        solve(b"payload", parameters, policy=strict)
    proof = evaluate_nonce(b"payload", 0, parameters)
    assert not verify(b"payload", proof, parameters, policy=strict)
