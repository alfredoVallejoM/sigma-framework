from dataclasses import replace
from typing import Any

from sigma.anchors import CrossWide, CrossWideEvidence
from sigma.experimental import PsiKernel
from sigma.presets import paranoid_wide_v2
from sigma.rounds import WideOnce
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


def _outputs(evidence: CrossWideEvidence, context) -> dict[str, bytes]:
    digest, transcript = WideOnce(context).evaluate(evidence)
    result = {f"root-{index}": value for index, value in enumerate(evidence.roots)}
    result.update({f"cross-{index}": value for index, value in enumerate(evidence.cross_roots)})
    result["anchor"] = evidence.to_bytes()
    result["initial-state"] = transcript.states[0]
    result["first-transition"] = transcript.states[1]
    result["digest"] = b"".join(digest.states)
    result["psi-experimental"] = PsiKernel.compute_anchor(*evidence.roots)
    return result


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    context = paranoid_wide_v2(
        target_round=int(config.get("target_round", 2)),
        state_count=int(config.get("state_count", 2)),
    )
    rng = derived_random(str(config["master_seed"]), "EXP-05/messages")
    message_bytes = int(config.get("message_bytes", 4))
    samples = int(config.get("samples", 1))
    input_stride = int(config.get("input_bit_stride", 1))
    component_stride = int(config.get("component_bit_stride", 64))
    for sample in range(samples):
        message = rng.randbytes(message_bytes)
        evidence = CrossWide.compute(context, (message,))
        baseline = _outputs(evidence, context)
        for bit in range(0, len(message) * 8, input_stride):
            changed = _outputs(CrossWide.compute(context, (_flip(message, bit),)), context)
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
                )
                altered_outputs = _outputs(altered, context)
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

        engine = WideOnce(context)
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
                }
            )
        modified_context = replace(context, application_context=b"EXP-05-context-change")
        modified = _outputs(CrossWide.compute(modified_context, (message,)), modified_context)
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
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault((str(record["perturbation"]), str(record["component"])), []).append(
            record
        )
    summaries = []
    for (perturbation, component), group in sorted(grouped.items()):
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
            }
        )
    return summaries
