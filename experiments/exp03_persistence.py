import math
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    master_seed = str(config["master_seed"])
    trials = int(config.get("trials", 4096))
    for n_value in config["widths"]:
        n = int(n_value)
        for segment_value in config["segments"]:
            segment = int(segment_value)
            for construction in ("simple", "reinjected"):
                label = f"EXP-03/{n}/{segment}/{construction}"
                rng = derived_random(master_seed, label)
                oracle = ReducedOracle(rng.randbytes(32))
                for trial in range(trials):
                    anchor = rng.getrandbits(n)
                    other_anchor = rng.getrandbits(n)
                    while other_anchor == anchor:
                        other_anchor = rng.getrandbits(n)
                    left = right = rng.getrandbits(n)
                    persisted = True
                    trial_bytes = trial.to_bytes(8, "big")
                    for index in range(segment):
                        common = (
                            trial_bytes,
                            index.to_bytes(8, "big"),
                            encode_integer(left, n),
                        )
                        if construction == "simple":
                            left = oracle.query("persist-simple", n, *common)
                            right = oracle.query("persist-simple", n, *common)
                        else:
                            left = oracle.query(
                                "persist-reinjected", n, encode_integer(anchor, n), *common
                            )
                            right = oracle.query(
                                "persist-reinjected",
                                n,
                                encode_integer(other_anchor, n),
                                index.to_bytes(8, "big"),
                                encode_integer(right, n),
                            )
                        persisted = persisted and left == right
                    records.append(
                        {
                            "construction": construction,
                            "expected_probability": 1.0
                            if construction == "simple"
                            else 2.0 ** (-segment * n),
                            "persisted": persisted,
                            "segment_length": segment,
                            "state_bits": n,
                            "trial": trial,
                        }
                    )
    return records


def _exact_binomial_p_value(successes: int, trials: int, probability: float) -> float:
    if probability == 0.0:
        return 1.0 if successes == 0 else 0.0
    if probability == 1.0:
        return 1.0 if successes == trials else 0.0

    def log_probability(value: int) -> float:
        return (
            math.lgamma(trials + 1)
            - math.lgamma(value + 1)
            - math.lgamma(trials - value + 1)
            + value * math.log(probability)
            + (trials - value) * math.log1p(-probability)
        )

    observed = log_probability(successes)
    return min(
        1.0,
        sum(
            math.exp(candidate)
            for value in range(trials + 1)
            if (candidate := log_probability(value)) <= observed + 1e-12
        ),
    )


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    for record in records:
        key = (
            str(record["construction"]),
            int(record["state_bits"]),
            int(record["segment_length"]),
        )
        grouped.setdefault(key, []).append(record)
    summaries = []
    z = 1.959963984540054
    for (construction, state_bits, segment_length), group in sorted(grouped.items()):
        trials = len(group)
        successes = sum(bool(record["persisted"]) for record in group)
        probability = successes / trials
        denominator = 1 + z * z / trials
        center = (probability + z * z / (2 * trials)) / denominator
        margin = (
            z
            * (probability * (1 - probability) / trials + z * z / (4 * trials * trials)) ** 0.5
            / denominator
        )
        expected = float(group[0]["expected_probability"])
        exact_p_value = _exact_binomial_p_value(successes, trials, expected)
        lower = max(0.0, center - margin)
        upper = min(1.0, center + margin)
        summaries.append(
            {
                "compatible_exact_5pct": exact_p_value >= 0.05,
                "construction": construction,
                "expected_probability": expected,
                "exact_binomial_p_value": exact_p_value,
                "observed_probability": probability,
                "segment_length": segment_length,
                "state_bits": state_bits,
                "successes": successes,
                "trials": trials,
                "wilson_high": upper,
                "wilson_low": lower,
            }
        )
    return summaries
