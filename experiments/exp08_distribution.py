import hashlib
import math
from itertools import pairwise
from typing import Any

from sigma.presets import (
    lightweight_v2,
    lightweight_v2_2,
    paranoid_deep_v2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2,
    paranoid_wide_v2_2,
)
from sigma.v2 import hash_bytes


def _message(corpus: str, index: int, size: int) -> bytes:
    counter = index.to_bytes(8, "big")
    if size < len(counter):
        raise ValueError("EXP-08 message_bytes must be at least 8")
    if corpus == "counter":
        return bytes(size - len(counter)) + counter
    if corpus == "adversarial-zero-tail":
        return bytes(size - len(counter)) + counter
    if corpus == "adversarial-ff-tail":
        return b"\xff" * (size - len(counter)) + bytes(value ^ 0xFF for value in counter)
    if corpus == "adversarial-alternating":
        prefix = bytes(0xAA if offset % 2 == 0 else 0x55 for offset in range(size - 8))
        return prefix + counter
    raise ValueError(f"unsupported corpus: {corpus}")


def _output(construction: str, message: bytes, revised: bool = False) -> bytes:
    if construction == "sha256":
        return hashlib.sha256(message).digest()
    if construction == "sha512":
        return hashlib.sha512(message).digest()
    if construction == "sha3-512":
        return hashlib.sha3_512(message).digest()
    if construction == "blake2b-512":
        return hashlib.blake2b(message, digest_size=64).digest()
    if construction == "sigma-wide":
        return b"".join(
            hash_bytes(message, lightweight_v2_2() if revised else lightweight_v2()).states
        )
    if construction == "sigma-cross":
        return b"".join(
            hash_bytes(message, paranoid_wide_v2_2() if revised else paranoid_wide_v2()).states
        )
    if construction == "sigma-deep":
        return b"".join(
            hash_bytes(message, paranoid_deep_v2_2() if revised else paranoid_deep_v2()).states
        )
    if construction == "sigma-deep-vector" and revised:
        return b"".join(hash_bytes(message, paranoid_deep_vector_v2_2()).states)
    raise ValueError(f"unsupported construction: {construction}")


def _output_domains(construction: str, message: bytes, revised: bool) -> dict[str, bytes]:
    """Return streams which never concatenate independently framed state objects."""

    if not revised or not construction.startswith("sigma-"):
        return {"digest": _output(construction, message, revised)}
    context = {
        "sigma-wide": lightweight_v2_2,
        "sigma-cross": paranoid_wide_v2_2,
        "sigma-deep": paranoid_deep_v2_2,
        "sigma-deep-vector": paranoid_deep_vector_v2_2,
    }.get(construction)
    if context is None:
        raise ValueError(f"unsupported construction: {construction}")
    digest = hash_bytes(message, context())
    return {f"state-{index}": state for index, state in enumerate(digest.states)}


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    count = int(config.get("messages", 1024))
    size = int(config.get("message_bytes", 32))
    streams = int(config.get("streams", 1))
    if streams < 1:
        raise ValueError("EXP-08 streams must be positive")
    revised = config.get("suite_family") == "v2-2"
    records = []
    for corpus in config["corpora"]:
        for construction in config["constructions"]:
            for stream in range(streams):
                for index in range(count):
                    message = _message(str(corpus), stream * count + index, size)
                    outputs = _output_domains(str(construction), message, revised)
                    for domain, output in outputs.items():
                        records.append(
                            {
                                "construction": construction,
                                "corpus": corpus,
                                "domain": domain,
                                "index": index,
                                "message_sha256": hashlib.sha256(message).hexdigest(),
                                "output_hex": output.hex(),
                                **({"stream": stream} if streams > 1 else {}),
                            }
                        )
    return records


def _gammaincc(shape: float, value: float) -> float:
    """Regularized upper incomplete gamma for chi-square survival values."""

    if value < 0 or shape <= 0:
        raise ValueError("invalid gamma parameters")
    if value == 0:
        return 1.0
    epsilon = 1e-14
    tiny = 1e-300
    if value < shape + 1:
        term = total = 1.0 / shape
        current = shape
        for _ in range(10000):
            current += 1
            term *= value / current
            total += term
            if abs(term) < abs(total) * epsilon:
                break
        lower = total * math.exp(-value + shape * math.log(value) - math.lgamma(shape))
        return max(0.0, min(1.0, 1.0 - lower))
    b = value + 1 - shape
    c = 1 / tiny
    d = 1 / b
    fraction = d
    for index in range(1, 10000):
        coefficient = -index * (index - shape)
        b += 2
        d = coefficient * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + coefficient / c
        if abs(c) < tiny:
            c = tiny
        d = 1 / d
        delta = d * c
        fraction *= delta
        if abs(delta - 1) < epsilon:
            break
    return max(
        0.0,
        min(1.0, math.exp(-value + shape * math.log(value) - math.lgamma(shape)) * fraction),
    )


def _tests(stream: bytes) -> dict[str, float]:
    bit_count = len(stream) * 8
    ones = sum(value.bit_count() for value in stream)
    monobit_p = math.erfc(abs(2 * ones - bit_count) / math.sqrt(2 * bit_count))
    bits = [(value >> shift) & 1 for value in stream for shift in range(7, -1, -1)]
    proportion = ones / bit_count
    runs = 1 + sum(left != right for left, right in pairwise(bits))
    if abs(proportion - 0.5) >= 2 / math.sqrt(bit_count):
        runs_p = 0.0
    else:
        expected = 2 * bit_count * proportion * (1 - proportion)
        denominator = 2 * math.sqrt(2 * bit_count) * proportion * (1 - proportion)
        runs_p = math.erfc(abs(runs - expected) / denominator)
    mean = proportion
    numerator = sum((left - mean) * (right - mean) for left, right in pairwise(bits))
    denominator = sum((value - mean) ** 2 for value in bits)
    correlation = numerator / denominator if denominator else 0.0
    serial_p = math.erfc(abs(correlation * math.sqrt(bit_count - 1)) / math.sqrt(2))
    counts = [0] * 256
    for value in stream:
        counts[value] += 1
    expected_bytes = len(stream) / 256
    chi_square = sum((count - expected_bytes) ** 2 / expected_bytes for count in counts)
    byte_frequency_p = _gammaincc(255 / 2, chi_square / 2)
    return {
        "byte-frequency-chi-square": byte_frequency_p,
        "monobit": monobit_p,
        "runs": runs_p,
        "serial-correlation-lag1": serial_p,
    }


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    multiple_streams = any("stream" in record for record in records)
    multiple_domains = any("domain" in record for record in records)
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        key = (
            str(record["construction"]),
            str(record["corpus"]),
            *((str(record["domain"]),) if multiple_domains else ()),
            *((int(record["stream"]),) if multiple_streams else ()),
        )
        grouped.setdefault(key, []).append(record)
    total_tests = len(grouped) * 4
    threshold = 0.05 / total_tests
    summaries = []
    for key, group in sorted(grouped.items()):
        construction, corpus = key[:2]
        ordered = sorted(group, key=lambda item: int(item["index"]))
        stream = b"".join(bytes.fromhex(str(item["output_hex"])) for item in ordered)
        p_values = _tests(stream)
        summaries.append(
            {
                "bonferroni_alpha": threshold,
                "bytes": len(stream),
                "construction": construction,
                "corpus": corpus,
                "failures_bonferroni": sum(value < threshold for value in p_values.values()),
                "p_values": p_values,
                "unique_outputs": len({item["output_hex"] for item in group}),
                **({"domain": key[2]} if multiple_domains else {}),
                **({"stream": key[-1]} if multiple_streams else {}),
            }
        )
    calibration: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for item in summaries:
        key = (
            str(item["construction"]),
            str(item["corpus"]),
            *((str(item["domain"]),) if multiple_domains else ()),
        )
        calibration.setdefault(key, []).append(item)
    for group in calibration.values():
        values = sorted(float(value) for item in group for value in item["p_values"].values())
        count = len(values)
        ks = max(
            max((index + 1) / count - value, value - index / count)
            for index, value in enumerate(values)
        )
        qq_rmse = math.sqrt(
            sum((value - (index + 0.5) / count) ** 2 for index, value in enumerate(values))
            / count
        )
        common = {
            "p_value_count": count,
            "p_value_qq_rmse": qq_rmse,
            "rejection_rate_0_05": sum(value < 0.05 for value in values) / count,
            "stream_count": len(group),
            "uniformity_ks_statistic": ks,
        }
        for item in group:
            item.update(common)
    return summaries
