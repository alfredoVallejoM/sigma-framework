from collections import deque
from typing import Any

from sigma.anchors import AnchorEvidence, CrossWideEvidence
from sigma.outputs import SigmaDigestV2
from sigma.presets import get_preset
from sigma.spec.encoding import DecodeError
from sigma.v2 import _anchor_engine, _round_engine, hash_bytes, verify_full

from .common import derived_random


def _flip(value: bytes, bit: int) -> bytes:
    changed = bytearray(value)
    changed[bit // 8] ^= 1 << (bit % 8)
    return bytes(changed)


def _distance(left: tuple[bytes, ...], right: tuple[bytes, ...]) -> int:
    return sum(
        (a ^ b).bit_count()
        for x, y in zip(left, right, strict=True)
        for a, b in zip(x, y, strict=True)
    )


def _replace_roots(
    anchor: AnchorEvidence | CrossWideEvidence, roots: tuple[bytes, ...]
) -> AnchorEvidence | CrossWideEvidence:
    if isinstance(anchor, CrossWideEvidence):
        return CrossWideEvidence(
            anchor.algorithms, roots, anchor.cross_roots, anchor.message_length, anchor.suite_id
        )
    return AnchorEvidence(anchor.algorithms, roots, anchor.message_length, anchor.suite_id)


def _trajectory_fault(context, anchor, model: str, rng) -> tuple[SigmaDigestV2, int]:
    engine = _round_engine(context)
    state = engine._initial_state(anchor)
    selected = deque((state,), maxlen=context.state_count)
    last_index = context.target_round + context.state_count - 1
    fault_index = min(max(1, context.target_round // 2), max(0, last_index - 1))
    for index in range(last_index):
        used_index = index
        if index == fault_index and model == "incorrect-index":
            used_index = index + 1
        elif index == fault_index and model == "repeated-round":
            used_index = index - 1
        state = engine.next_state(anchor, used_index, state)
        if index == fault_index and model in {
            "fold-corruption",
            "state-corruption",
            "vector-corruption",
        }:
            state = _flip(state, rng.randrange(len(state) * 8))
        selected.append(state)
    return SigmaDigestV2(context, tuple(selected)), last_index - fault_index


def _record(
    records: list[dict[str, Any]],
    *,
    expected: SigmaDigestV2,
    changed: SigmaDigestV2 | None,
    detected: bool,
    fault_site: str,
    model: str,
    preset: str,
    propagation_levels: int,
    trial: int,
) -> None:
    records.append(
        {
            "detected": detected,
            "fault_site": fault_site,
            "model": model,
            "output_hamming": _distance(expected.states, changed.states) if changed else None,
            "preset": preset,
            "propagation_levels": propagation_levels,
            "trial": trial,
        }
    )


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    rng = derived_random(str(config["master_seed"]), "EXP-14/faults")
    records: list[dict[str, Any]] = []
    presets = [str(value) for value in config["presets"]]
    configured_faults = config.get("faults")
    faults = (
        [str(value) for value in configured_faults]
        if configured_faults is not None
        else ["message-bit-flip", "anchor-root-bit-flip", "published-state-bit-flip"]
    )
    if configured_faults is None:
        faults.extend(
            [
                "branch-omission",
                "branch-reorder",
                "incorrect-index",
                "repeated-round",
                "digest-truncation",
                "fold-or-vector-corruption",
            ]
        )
    for preset in presets:
        context = get_preset(
            preset,
            target_round=int(config.get("target_round", 2)),
            state_count=int(config.get("state_count", 2)),
        )
        for trial in range(int(config.get("trials", 128))):
            message = rng.randbytes(int(config.get("message_bytes", 64)))
            expected = hash_bytes(message, context)
            anchor_engine = _anchor_engine(context)
            anchor_engine.update(message)
            anchor = anchor_engine.finalize()
            last_index = context.target_round + context.state_count - 1
            for configured_fault in faults:
                fault = configured_fault
                changed: SigmaDigestV2 | None = None
                detected = False
                site = "round"
                propagation = max(1, last_index)
                if fault == "message-bit-flip":
                    bit = rng.randrange(len(message) * 8)
                    changed = hash_bytes(_flip(message, bit), context)
                    detected = changed.to_bytes() != expected.to_bytes()
                    site = "message"
                elif fault == "anchor-root-bit-flip":
                    roots = list(anchor.roots)
                    root_index = rng.randrange(len(roots))
                    roots[root_index] = _flip(
                        roots[root_index], rng.randrange(len(roots[root_index]) * 8)
                    )
                    changed = _round_engine(context).evaluate_digest(
                        _replace_roots(anchor, tuple(roots))
                    )
                    detected = changed.to_bytes() != expected.to_bytes()
                    site = "anchor-root"
                elif fault == "published-state-bit-flip":
                    states = list(expected.states)
                    state_index = rng.randrange(len(states))
                    states[state_index] = _flip(
                        states[state_index], rng.randrange(len(states[state_index]) * 8)
                    )
                    changed = SigmaDigestV2(context, tuple(states))
                    detected = not verify_full(message, changed)
                    site = "published-state"
                    propagation = 0
                elif fault == "branch-omission":
                    try:
                        _replace_roots(anchor, anchor.roots[:-1])
                    except (TypeError, ValueError):
                        detected = True
                    site = "anchor-branch"
                    propagation = 0
                elif fault == "branch-reorder":
                    changed = _round_engine(context).evaluate_digest(
                        _replace_roots(anchor, tuple(reversed(anchor.roots)))
                    )
                    detected = changed.to_bytes() != expected.to_bytes()
                    site = "anchor-branch"
                elif fault in {"incorrect-index", "repeated-round"}:
                    changed, propagation = _trajectory_fault(context, anchor, fault, rng)
                    detected = changed.to_bytes() != expected.to_bytes()
                elif fault == "digest-truncation":
                    try:
                        SigmaDigestV2.from_bytes(expected.to_bytes()[:-1])
                    except (DecodeError, TypeError, ValueError):
                        detected = True
                    site = "digest-codec"
                    propagation = 0
                elif fault == "fold-or-vector-corruption":
                    model = {
                        "DEEP_VECTOR": "vector-corruption",
                        "DEEP": "fold-corruption",
                    }.get(context.round_profile.name, "state-corruption")
                    changed, propagation = _trajectory_fault(context, anchor, model, rng)
                    detected = changed.to_bytes() != expected.to_bytes()
                    fault = model
                else:
                    raise ValueError(f"unsupported fault model: {fault}")
                _record(
                    records,
                    expected=expected,
                    changed=changed,
                    detected=detected,
                    fault_site=site,
                    model=fault,
                    preset=preset,
                    propagation_levels=propagation,
                    trial=trial,
                )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in records:
        key = (str(record["preset"]), str(record["fault_site"]), str(record["model"]))
        groups.setdefault(key, []).append(record)
    return [
        {
            "detection_rate": sum(bool(row["detected"]) for row in group) / len(group),
            "fault_site": site,
            "mean_output_hamming": (
                sum(
                    int(row["output_hamming"]) for row in group if row["output_hamming"] is not None
                )
                / sum(row["output_hamming"] is not None for row in group)
                if any(row["output_hamming"] is not None for row in group)
                else None
            ),
            "mean_propagation_levels": sum(int(row["propagation_levels"]) for row in group)
            / len(group),
            "model": model,
            "preset": preset,
            "quality_control_passed": all(bool(row["detected"]) for row in group),
            "trials": len(group),
        }
        for (preset, site, model), group in sorted(groups.items())
    ]
