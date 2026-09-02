from dataclasses import replace
from typing import Any

from sigma.anchors import CrossWide, CrossWideEvidence
from sigma.experimental import PsiKernel
from sigma.presets import get_preset, paranoid_wide_v2
from sigma.rounds import Deep, DeepVector, WideOnce
from sigma.spec.ids import RoundProfileId
from sigma.suites import get_suite

from .common import derived_random


def _flip(data: bytes, bit: int) -> bytes:
    changed = bytearray(data)
    changed[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(changed)


def _difference(
    perturbation: str,
    source_bit: int,
    component: str,
    original: bytes,
    changed: bytes,
    sample: int,
) -> dict[str, Any]:
    difference = bytes(left ^ right for left, right in zip(original, changed, strict=True))
    return {
        "changed_bits": sum(value.bit_count() for value in difference),
        "component": component,
        "difference_hex": difference.hex(),
        "output_bits": len(difference) * 8,
        "perturbation": perturbation,
        "sample": sample,
        "source_bit": source_bit,
    }


def _structural_difference(
    perturbation: str,
    component: str,
    original: bytes,
    changed: bytes,
    sample: int,
) -> dict[str, Any]:
    record = _difference(perturbation, 0, component, original, changed, sample)
    record["invariant_match"] = original != changed
    return record


def _engine(context):
    return {
        RoundProfileId.WIDE_ONCE: WideOnce,
        RoundProfileId.DEEP: Deep,
        RoundProfileId.DEEP_VECTOR: DeepVector,
    }[context.round_profile](context)


def _outputs(
    evidence: CrossWideEvidence, context, *, include_round_components: bool = False
) -> dict[str, bytes]:
    digest, transcript = _engine(context).evaluate(evidence)
    result = {f"root-{index}": value for index, value in enumerate(evidence.roots)}
    result.update({f"cross-{index}": value for index, value in enumerate(evidence.cross_roots)})
    result["anchor"] = evidence.to_bytes()
    result["initial-state"] = transcript.states[0]
    result["first-transition"] = transcript.states[1]
    result["digest"] = b"".join(digest.states)
    result["psi-experimental"] = PsiKernel.compute_anchor(*evidence.roots)
    if include_round_components:
        for level, row in zip(
            transcript.branch_output_indices, transcript.branch_outputs, strict=True
        ):
            for position, value in enumerate(row):
                result[f"round-{level}-branch-{position}"] = value
    return result


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    parameters = {
        "target_round": int(config.get("target_round", 2)),
        "state_count": int(config.get("state_count", 2)),
    }
    context = (
        get_preset(str(config["preset"]), **parameters)
        if "preset" in config
        else paranoid_wide_v2(**parameters)
    )
    include_round_components = bool(config.get("include_round_components", False))
    rng = derived_random(str(config["master_seed"]), "EXP-05/messages")
    message_bytes = int(config.get("message_bytes", 4))
    samples = int(config.get("samples", 1))
    input_stride = int(config.get("input_bit_stride", 1))
    component_stride = int(config.get("component_bit_stride", 64))
    for sample in range(samples):
        message = rng.randbytes(message_bytes)
        evidence = CrossWide.compute(context, (message,))
        baseline = _outputs(evidence, context, include_round_components=include_round_components)
        for bit in range(0, len(message) * 8, input_stride):
            changed = _outputs(
                CrossWide.compute(context, (_flip(message, bit),)),
                context,
                include_round_components=include_round_components,
            )
            for component in baseline:
                records.append(
                    _difference(
                        "message-bit",
                        bit,
                        component,
                        baseline[component],
                        changed[component],
                        sample,
                    )
                )

        all_components = evidence.roots + evidence.cross_roots
        for component_index, value in enumerate(all_components):
            for bit in range(0, len(value) * 8, component_stride):
                components = list(all_components)
                components[component_index] = _flip(value, bit)
                altered = CrossWideEvidence(
                    evidence.algorithms,
                    tuple(components[: len(evidence.roots)]),
                    tuple(components[len(evidence.roots) :]),
                    evidence.message_length,
                    evidence.suite_id,
                )
                altered_outputs = _outputs(
                    altered, context, include_round_components=include_round_components
                )
                source = (
                    f"root-{component_index}"
                    if component_index < len(evidence.roots)
                    else f"cross-{component_index - len(evidence.roots)}"
                )
                for target in ("initial-state", "first-transition", "digest"):
                    records.append(
                        _difference(
                            f"{source}-bit",
                            bit,
                            target,
                            baseline[target],
                            altered_outputs[target],
                            sample,
                        )
                    )

        engine = _engine(context)
        state = baseline["initial-state"]
        for bit in range(0, len(state) * 8, component_stride):
            records.append(
                _difference(
                    "state-bit",
                    bit,
                    "next-state",
                    engine.next_state(evidence, 0, state),
                    engine.next_state(evidence, 0, _flip(state, bit)),
                    sample,
                )
            )
        records.append(
            _difference(
                "round-index",
                0,
                "next-state",
                engine.next_state(evidence, 0, state),
                engine.next_state(evidence, 1, state),
                sample,
            )
        )
        if bool(config.get("structural_interventions", False)):
            altered_evidence = {
                "root-zero": CrossWideEvidence(
                    evidence.algorithms,
                    (bytes(len(evidence.roots[0])), *evidence.roots[1:]),
                    evidence.cross_roots,
                    evidence.message_length,
                    evidence.suite_id,
                ),
                "cross-zero": CrossWideEvidence(
                    evidence.algorithms,
                    evidence.roots,
                    (bytes(len(evidence.cross_roots[0])), *evidence.cross_roots[1:]),
                    evidence.message_length,
                    evidence.suite_id,
                ),
                "root-permutation": CrossWideEvidence(
                    evidence.algorithms,
                    tuple(reversed(evidence.roots)),
                    evidence.cross_roots,
                    evidence.message_length,
                    evidence.suite_id,
                ),
                "cross-permutation": CrossWideEvidence(
                    evidence.algorithms,
                    evidence.roots,
                    tuple(reversed(evidence.cross_roots)),
                    evidence.message_length,
                    evidence.suite_id,
                ),
                "message-length": CrossWideEvidence(
                    evidence.algorithms,
                    evidence.roots,
                    evidence.cross_roots,
                    evidence.message_length + 1,
                    evidence.suite_id,
                ),
            }
            for perturbation, changed_evidence in altered_evidence.items():
                structural_outputs = _outputs(
                    changed_evidence,
                    context,
                    include_round_components=include_round_components,
                )
                for target in ("initial-state", "first-transition", "digest"):
                    records.append(
                        _structural_difference(
                            perturbation,
                            target,
                            baseline[target],
                            structural_outputs[target],
                            sample,
                        )
                    )
            context_changes = {
                "context-salt": replace(context, salt=b"EXP-05-salt"),
                "context-challenge": replace(context, challenge=b"EXP-05-challenge"),
                "context-application": replace(context, application_context=b"EXP-05-application"),
                "context-target-round": replace(context, target_round=context.target_round + 1),
            }
            for perturbation, changed_context in context_changes.items():
                context_outputs = _outputs(
                    CrossWide.compute(changed_context, (message,)),
                    changed_context,
                    include_round_components=include_round_components,
                )
                records.append(
                    _structural_difference(
                        perturbation,
                        "digest",
                        baseline["digest"],
                        context_outputs["digest"],
                        sample,
                    )
                )
        for perturbation, branches in (
            ("branch-ablation", context.branches[:-1]),
            ("branch-permutation", tuple(reversed(context.branches))),
        ):
            rejected = False
            try:
                get_suite(context.suite_id).validate_context(replace(context, branches=branches))
            except ValueError:
                rejected = True
            records.append(
                {
                    "changed_bits": int(rejected),
                    "component": "suite-validation",
                    "difference_hex": "01" if rejected else "00",
                    "output_bits": 1,
                    "perturbation": perturbation,
                    "sample": sample,
                    "source_bit": 0,
                    **({"invariant_match": rejected} if "preset" in config else {}),
                }
            )
        modified_context = replace(context, application_context=b"EXP-05-context-change")
        modified = _outputs(
            CrossWide.compute(modified_context, (message,)),
            modified_context,
            include_round_components=include_round_components,
        )
        records.append(
            _difference(
                "context",
                0,
                "digest",
                baseline["digest"],
                modified["digest"],
                sample,
            )
        )
    if "preset" in config:
        for record in records:
            record["preset"] = config["preset"]
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    revised = any("preset" in record for record in records)
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for record in records:
        key = (
            str(record["perturbation"]),
            str(record["component"]),
            *((str(record["preset"]),) if revised else ()),
        )
        grouped.setdefault(key, []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        perturbation, component = key[:2]
        total_bits = sum(int(item["output_bits"]) for item in group)
        changed = sum(int(item["changed_bits"]) for item in group)
        covered_mask = 0
        for item in group:
            covered_mask |= int(str(item["difference_hex"]), 16)
        output_bits = int(group[0]["output_bits"])
        summaries.append(
            {
                "component": component,
                "coverage": sum(int(item["changed_bits"]) > 0 for item in group) / len(group),
                "mean_flip_probability": changed / total_bits,
                "observations": len(group),
                "output_bit_coverage": covered_mask.bit_count() / output_bits,
                "perturbation": perturbation,
                **({"preset": key[2]} if revised else {}),
                **(
                    {"quality_control_passed": 0.0 <= covered_mask.bit_count() / output_bits <= 1.0}
                    if revised
                    else {}
                ),
            }
        )
    return summaries
