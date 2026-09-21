import hashlib
import math
import re
import statistics
from typing import Any

from sigma.anchors import CrossWide
from sigma.presets import get_preset
from sigma.rounds import Deep, DeepVector, WideOnce
from sigma.spec.ids import RoundProfileId

from .common import derived_random


def _flip(data: bytes, bit: int) -> bytes:
    changed = bytearray(data)
    changed[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(changed)


def _primitive_outputs(message: bytes) -> dict[str, bytes]:
    return {
        "primitive-blake2b-512": hashlib.blake2b(message, digest_size=64).digest(),
        "primitive-sha3-512": hashlib.sha3_512(message).digest(),
        "primitive-sha512": hashlib.sha512(message).digest(),
        "primitive-shake256-512": hashlib.shake_256(message).digest(64),
    }


def _no_reinjection(message: bytes, target: int, state_count: int) -> bytes:
    state = hashlib.sha3_512(b"SIGMA-EXP07-NO-REINJECTION-v1" + message).digest()
    states = [state]
    for index in range(target + state_count - 1):
        state = hashlib.sha3_512(
            b"SIGMA-EXP07-NO-REINJECTION-ROUND-v1" + index.to_bytes(8, "big") + state
        ).digest()
        states.append(state)
    return b"".join(states[target : target + state_count])


def _outputs(message: bytes, context) -> dict[str, bytes]:
    evidence = CrossWide.compute(context, (message,))
    engine = {
        RoundProfileId.WIDE_ONCE: WideOnce,
        RoundProfileId.DEEP: Deep,
        RoundProfileId.DEEP_VECTOR: DeepVector,
    }[context.round_profile](context)
    digest, transcript = engine.evaluate(evidence)
    result = _primitive_outputs(message)
    result["anchor-roots"] = b"".join(evidence.roots)
    result["anchor-connections"] = b"".join(evidence.cross_roots)
    result["anchor-framed"] = evidence.to_bytes()
    result["initial-state"] = transcript.states[0]
    for index, state in enumerate(transcript.states[1:], 1):
        result[f"state-after-{index}-transitions"] = state
    result["digest-multistate"] = b"".join(digest.states)
    result["digest-no-reinjection"] = _no_reinjection(
        message, context.target_round, context.state_count
    )
    for level, row in zip(transcript.branch_output_indices, transcript.branch_outputs, strict=True):
        for position, value in enumerate(row):
            result[f"round-{level}-branch-{position}"] = value
    return result


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    samples = int(config.get("samples", 32))
    message_bytes = int(config.get("message_bytes", 2))
    stride = int(config.get("input_bit_stride", 1))
    family_alpha = float(config.get("family_alpha", 0.05))
    detectable_bias = float(config.get("detectable_bias", 0.05))
    parameters = {
        "target_round": int(config.get("target_round", 2)),
        "state_count": int(config.get("state_count", 2)),
    }
    context = get_preset(str(config["preset"]), **parameters)
    rng = derived_random(str(config["master_seed"]), "EXP-07/messages")
    for sample in range(samples):
        message = rng.randbytes(message_bytes)
        baseline = _outputs(message, context)
        for source_bit in range(0, message_bytes * 8, stride):
            changed = _outputs(_flip(message, source_bit), context)
            for layer, original in baseline.items():
                difference = bytes(
                    left ^ right for left, right in zip(original, changed[layer], strict=True)
                )
                records.append(
                    {
                        "changed_bits": sum(value.bit_count() for value in difference),
                        "difference_hex": difference.hex(),
                        "detectable_bias": detectable_bias,
                        "family_alpha": family_alpha,
                        "layer": layer,
                        "output_bits": len(difference) * 8,
                        "sample": sample,
                        "source_bit": source_bit,
                        "bic_output_stride": int(config.get("bic_output_stride", 8)),
                        **({"preset": config["preset"]} if "preset" in config else {}),
                    }
                )
    return records


def _two_sided_binomial_half(successes: int, trials: int) -> float:
    tail = min(successes, trials - successes)
    return min(1.0, 2 * sum(math.comb(trials, value) for value in range(tail + 1)) / 2**trials)


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    revised = any("preset" in record for record in records)
    layers: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for record in records:
        key = (str(record["layer"]), *((str(record["preset"]),) if revised else ()))
        layers.setdefault(key, []).append(record)
    summaries = []
    for key, group in sorted(layers.items()):
        layer = key[0]
        samples = len({int(item["sample"]) for item in group})
        source_bits = sorted({int(item["source_bit"]) for item in group})
        output_bits = int(group[0]["output_bits"])
        family_alpha = float(group[0]["family_alpha"])
        detectable_bias = float(group[0]["detectable_bias"])
        counts = {(source, output): 0 for source in source_bits for output in range(output_bits)}
        for item in group:
            source = int(item["source_bit"])
            difference = bytes.fromhex(str(item["difference_hex"]))
            for byte_index, value in enumerate(difference):
                for within_byte in range(8):
                    counts[(source, byte_index * 8 + within_byte)] += (
                        value >> (7 - within_byte)
                    ) & 1
        threshold = family_alpha / len(counts)
        required_samples = math.ceil(math.log(2 / threshold) / (2 * detectable_bias**2))
        probabilities = [count / samples for count in counts.values()]
        significant = sum(
            _two_sided_binomial_half(count, samples) < threshold for count in counts.values()
        )
        radius = math.sqrt(math.log(2 * len(counts) / family_alpha) / (2 * samples))
        pair_stride = max(1, int(group[0].get("bic_output_stride", 8)))
        selected_outputs = range(0, output_bits, pair_stride)
        observations: dict[tuple[int, int], list[int]] = {
            (source, output): [] for source in source_bits for output in selected_outputs
        }
        for item in group:
            source = int(item["source_bit"])
            difference = bytes.fromhex(str(item["difference_hex"]))
            for output in selected_outputs:
                observations[(source, output)].append(
                    (difference[output // 8] >> (7 - output % 8)) & 1
                )
        correlations: list[float] = []
        selected = list(selected_outputs)
        for source in source_bits:
            for left_index, left in enumerate(selected):
                xs = observations[(source, left)]
                mean_x = statistics.fmean(xs)
                variance_x = mean_x * (1 - mean_x)
                for right in selected[left_index + 1 :]:
                    ys = observations[(source, right)]
                    mean_y = statistics.fmean(ys)
                    variance_y = mean_y * (1 - mean_y)
                    if variance_x == 0 or variance_y == 0:
                        continue
                    covariance = statistics.fmean(
                        (x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)
                    )
                    correlations.append(covariance / math.sqrt(variance_x * variance_y))
        summaries.append(
            {
                "bonferroni_alpha": threshold,
                "cells": len(counts),
                "input_bits": len(source_bits),
                "layer": layer,
                "max_absolute_bias": max(abs(value - 0.5) for value in probabilities),
                "max_absolute_bic_correlation": max(map(abs, correlations), default=0.0),
                "mean_flip_probability": sum(probabilities) / len(probabilities),
                "output_bits": output_bits,
                "planned_detectable_bias": detectable_bias,
                "power_target_met": samples >= required_samples,
                "required_samples_per_input_bit": required_samples,
                "sample_requirement_met": samples >= required_samples,
                "samples_per_input_bit": samples,
                "significant_cells_bonferroni": significant,
                "structural_coverage": sum(value > 0 for value in counts.values()) / len(counts),
                "simultaneous_bias_radius": radius,
                **({"preset": key[1]} if revised else {}),
            }
        )
    round_pattern = re.compile(r"^round-(\d+)-branch-(\d+)$")
    diffusion_groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in summaries:
        match = round_pattern.match(str(item["layer"]))
        if match is None:
            item["diffusion_round"] = None
            item["diffusion_velocity"] = None
            continue
        round_index, branch = map(int, match.groups())
        item["diffusion_round"] = round_index
        diffusion_groups.setdefault((str(item.get("preset", "legacy")), branch), []).append(item)
    for group in diffusion_groups.values():
        ordered = sorted(group, key=lambda item: int(item["diffusion_round"]))
        previous = 0.0
        for item in ordered:
            probability = float(item["mean_flip_probability"])
            item["diffusion_velocity"] = probability - previous
            previous = probability
    return summaries
