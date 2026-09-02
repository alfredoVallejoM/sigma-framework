import math
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer


def _run_legacy(config: dict[str, Any]) -> list[dict[str, Any]]:
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


def _controlled_transition(
    oracle: ReducedOracle,
    construction: str,
    n: int,
    anchor: int,
    index: int,
    state: int,
) -> int:
    parts = [encode_integer(state, n)]
    if construction in {"indexed", "anchored-indexed"}:
        parts.insert(0, index.to_bytes(8, "big"))
    if construction in {"anchored", "anchored-indexed"}:
        parts.insert(0, encode_integer(anchor, n))
    return oracle.query(f"persist-{construction}", n, *parts)


def _run_revised(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    trials = int(config.get("trials", 4096))
    constructions = [str(value) for value in config["constructions"]]
    relations = [str(value) for value in config.get("anchor_relations", ["same", "different"])]
    allowed = {"stationary", "indexed", "anchored", "anchored-indexed"}
    if not set(constructions) <= allowed:
        raise ValueError("unsupported EXP-03R construction")
    if not set(relations) <= {"same", "different"}:
        raise ValueError("unsupported anchor relation")
    for n_value in config["widths"]:
        n = int(n_value)
        for segment_value in config["segments"]:
            segment = int(segment_value)
            for construction in constructions:
                for relation in relations:
                    label = f"EXP-03R/{n}/{segment}/{construction}/{relation}"
                    for trial in range(trials):
                        rng = derived_random(str(config["master_seed"]), f"{label}/trial-{trial}")
                        oracle = ReducedOracle(rng.randbytes(32))
                        left_anchor = rng.getrandbits(n)
                        right_anchor = left_anchor
                        if relation == "different":
                            while right_anchor == left_anchor:
                                right_anchor = rng.getrandbits(n)
                        left = right = rng.getrandbits(n)
                        persisted = True
                        for index in range(segment):
                            left = _controlled_transition(
                                oracle, construction, n, left_anchor, index, left
                            )
                            right = _controlled_transition(
                                oracle, construction, n, right_anchor, index, right
                            )
                            persisted = persisted and left == right
                        depends_on_anchor = construction in {"anchored", "anchored-indexed"}
                        expected = (
                            2.0 ** (-segment * n)
                            if depends_on_anchor and relation == "different"
                            else 1.0
                        )
                        records.append(
                            {
                                "anchor_relation": relation,
                                "construction": construction,
                                "expected_probability": expected,
                                "persisted": persisted,
                                "segment_length": segment,
                                "state_bits": n,
                                "trial": trial,
                            }
                        )
    return records


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    return _run_revised(config) if "constructions" in config else _run_legacy(config)


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


def _binomial_log_likelihood(successes: int, trials: int, probability: float) -> float:
    failures = trials - successes
    if probability == 0.0:
        return 0.0 if successes == 0 else float("-inf")
    if probability == 1.0:
        return 0.0 if failures == 0 else float("-inf")
    return successes * math.log(probability) + failures * math.log1p(-probability)


def _clopper_pearson(successes: int, trials: int) -> tuple[float, float] | None:
    try:
        from scipy.stats import beta
    except ImportError:
        return None
    lower = 0.0 if successes == 0 else float(beta.ppf(0.025, successes, trials - successes + 1))
    upper = (
        1.0 if successes == trials else float(beta.ppf(0.975, successes + 1, trials - successes))
    )
    return lower, upper


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    revised = any("anchor_relation" in record for record in records)
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        key = tuple(
            [
                str(record["construction"]),
                int(record["state_bits"]),
                int(record["segment_length"]),
            ]
            + ([str(record["anchor_relation"])] if revised else [])
        )
        grouped.setdefault(key, []).append(record)
    summaries = []
    z = 1.959963984540054
    for key, group in sorted(grouped.items()):
        construction, state_bits, segment_length = key[:3]
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
        observed_log_likelihood = _binomial_log_likelihood(successes, trials, probability)
        theory_log_likelihood = _binomial_log_likelihood(successes, trials, expected)
        unity_log_likelihood = _binomial_log_likelihood(successes, trials, 1.0)
        exact_interval = _clopper_pearson(successes, trials) if revised else None
        lower = max(0.0, center - margin)
        upper = min(1.0, center + margin)
        summaries.append(
            {
                **({"anchor_relation": key[3]} if revised else {}),
                ("raw_compatible_exact_5pct" if revised else "compatible_exact_5pct"): exact_p_value
                >= 0.05,
                "construction": construction,
                "expected_probability": expected,
                "exact_binomial_p_value": exact_p_value,
                "log_likelihood_observed": observed_log_likelihood,
                "log_likelihood_theory": theory_log_likelihood,
                "log_likelihood_unity": (
                    unity_log_likelihood if math.isfinite(unity_log_likelihood) else None
                ),
                "log_lr_theory_vs_unity": (
                    theory_log_likelihood - unity_log_likelihood
                    if math.isfinite(unity_log_likelihood)
                    else None
                ),
                "unity_model_impossible": not math.isfinite(unity_log_likelihood),
                "saturated_deviance": 2 * (observed_log_likelihood - theory_log_likelihood),
                "observed_probability": probability,
                "segment_length": segment_length,
                "state_bits": state_bits,
                "successes": successes,
                "trials": trials,
                "wilson_high": upper,
                "wilson_low": lower,
                **(
                    {
                        "exact_95_high": exact_interval[1] if exact_interval else None,
                        "exact_95_low": exact_interval[0] if exact_interval else None,
                        "quality_control_passed": exact_interval is not None,
                    }
                    if revised
                    else {}
                ),
            }
        )
    tested = [item for item in summaries if 0.0 < float(item["expected_probability"]) < 1.0]
    ordered = sorted(tested, key=lambda item: float(item["exact_binomial_p_value"]))
    still_rejecting = True
    for rank, item in enumerate(ordered):
        threshold = 0.05 / (len(ordered) - rank)
        rejected = still_rejecting and float(item["exact_binomial_p_value"]) < threshold
        still_rejecting = rejected
        item["holm_threshold_5pct"] = threshold
        item["holm_reject_5pct"] = rejected
        item["compatible_holm_5pct"] = not rejected
        expected_events = float(item["expected_probability"]) * int(item["trials"])
        item["interpretation"] = "upper-bound-only" if expected_events < 5 else "point-estimate"
    for item in summaries:
        if item not in tested:
            item["holm_threshold_5pct"] = None
            item["holm_reject_5pct"] = False
            item["compatible_holm_5pct"] = True
            item["interpretation"] = "deterministic-control"
    return summaries
