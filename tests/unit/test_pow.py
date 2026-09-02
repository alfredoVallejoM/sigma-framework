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
