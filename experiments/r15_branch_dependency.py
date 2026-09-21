"""R15 DeepVector dependency intervention profiler."""

from __future__ import annotations

from dataclasses import dataclass

from .reduced_oracle import ReducedOracle, encode_integer


@dataclass(frozen=True)
class BranchDependencyResultV3:
    candidates: int
    branch_count: int
    interventions: int
    affected_branches_total: int
    all_branches_affected: int
    first_divergence_sum: int
    hamming_distance_sum: int

    @property
    def mean_affected_branches(self) -> float:
        return self.affected_branches_total / self.interventions

    @property
    def all_branches_affected_rate(self) -> float:
        return self.all_branches_affected / self.interventions


def _initial_vector(
    oracle: ReducedOracle, candidate: int, bits: int, branch_count: int
) -> tuple[int, ...]:
    encoded = candidate.to_bytes(max(1, (candidate.bit_length() + 7) // 8), "big")
    return tuple(
        oracle.query("r15-vector-initial", bits, encoded, branch.to_bytes(2, "big"))
        for branch in range(branch_count)
    )


def _next_vector(
    oracle: ReducedOracle, vector: tuple[int, ...], bits: int
) -> tuple[int, ...]:
    encoded = b"".join(encode_integer(value, bits) for value in vector)
    return tuple(
        oracle.query("r15-vector-next", bits, encoded, branch.to_bytes(2, "big"))
        for branch in range(len(vector))
    )


def profile_deep_vector_dependency_v3(
    oracle: ReducedOracle,
    *,
    bits: int,
    branch_count: int,
    candidates: int,
) -> BranchDependencyResultV3:
    if not 1 <= bits <= 32:
        raise ValueError("bits must be in [1,32]")
    if not 2 <= branch_count <= 16:
        raise ValueError("branch_count must be in [2,16]")
    if candidates <= 0:
        raise ValueError("candidates must be positive")

    affected_total = 0
    all_affected = 0
    first_divergence_sum = 0
    hamming_sum = 0
    interventions = 0
    mask = (1 << bits) - 1

    for candidate in range(candidates):
        vector = _initial_vector(oracle, candidate, bits, branch_count)
        baseline = _next_vector(oracle, vector, bits)
        for source_branch in range(branch_count):
            mutated = list(vector)
            mutated[source_branch] = (mutated[source_branch] ^ 1) & mask
            changed = _next_vector(oracle, tuple(mutated), bits)
            affected = [
                index
                for index, (a, b) in enumerate(zip(baseline, changed, strict=True))
                if a != b
            ]
            interventions += 1
            affected_total += len(affected)
            all_affected += int(len(affected) == branch_count)
            first_divergence_sum += affected[0] if affected else branch_count
            hamming_sum += sum(
                (a ^ b).bit_count() for a, b in zip(baseline, changed, strict=True)
            )

    return BranchDependencyResultV3(
        candidates=candidates,
        branch_count=branch_count,
        interventions=interventions,
        affected_branches_total=affected_total,
        all_branches_affected=all_affected,
        first_divergence_sum=first_divergence_sum,
        hamming_distance_sum=hamming_sum,
    )


__all__ = ["BranchDependencyResultV3", "profile_deep_vector_dependency_v3"]
