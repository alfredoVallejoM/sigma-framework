"""EXP-21R: deterministic domain-separation and canonical-framing audit."""

from itertools import combinations
from typing import Any

from sigma.presets import get_preset
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError, domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import CONTEXT_MAGIC, DomainId, SuiteId


def _context_mutations(encoded: bytes) -> dict[str, bytes]:
    prefix = len(CONTEXT_MAGIC) + 6
    body = encoded[prefix:]
    first_length = int.from_bytes(body[2:6], "big")
    first_end = 6 + first_length
    reordered = body[first_end:] + body[:first_end]
    unknown = body + encode_uint(0xFFFF, 2) + encode_uint(0, 4)
    downgraded = bytearray(encoded)
    suite_offset = prefix + 6
    downgraded[suite_offset : suite_offset + 2] = encode_uint(SuiteId.REFERENCE_STREAM_WIDE_V2, 2)
    return {
        "trailing-byte": encoded + b"\x00",
        "unsupported-version": encoded[: len(CONTEXT_MAGIC)]
        + b"\x00\x01"
        + encoded[len(CONTEXT_MAGIC) + 2 :],
        "unknown-field": encoded[: len(CONTEXT_MAGIC) + 2] + encode_uint(len(unknown), 4) + unknown,
        "reordered-fields": encoded[: len(CONTEXT_MAGIC) + 2]
        + encode_uint(len(reordered), 4)
        + reordered,
        "suite-downgrade": bytes(downgraded),
    }


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    payload = b"same-payload"
    domain_inputs = {domain.name: domain_tag(domain) + payload for domain in DomainId}
    for (left_name, left), (right_name, right) in combinations(domain_inputs.items(), 2):
        records.append(
            {
                "case": "registered-domain-pair",
                "invariant_match": left != right,
                "left": left_name,
                "left_hex": left.hex(),
                "right": right_name,
                "right_hex": right.hex(),
            }
        )

    ambiguous_left = encode_tlv(((1, b"a"), (2, b"bc")))
    ambiguous_right = encode_tlv(((1, b"ab"), (2, b"c")))
    records.append(
        {
            "case": "length-framing",
            "invariant_match": ambiguous_left != ambiguous_right,
            "left": "a|bc",
            "left_hex": ambiguous_left.hex(),
            "right": "ab|c",
            "right_hex": ambiguous_right.hex(),
        }
    )

    for preset in config["presets"]:
        context = get_preset(str(preset), target_round=2, state_count=2)
        encoded = context.to_bytes()
        records.append(
            {
                "case": "canonical-roundtrip",
                "invariant_match": SigmaContextV2.from_bytes(encoded).to_bytes() == encoded,
                "left": preset,
                "left_hex": encoded.hex(),
                "right": preset,
                "right_hex": encoded.hex(),
            }
        )
        for mutation, changed in _context_mutations(encoded).items():
            rejected = False
            parsed = None
            try:
                parsed = SigmaContextV2.from_bytes(changed)
            except (DecodeError, TypeError, ValueError):
                rejected = True
            # A suite-ID downgrade can be a canonical context of an older,
            # still-registered suite. It must remain a distinct context and is
            # rejected by an expected-context/application policy, not by the
            # generic syntax parser.
            protected = rejected or (
                mutation == "suite-downgrade"
                and parsed is not None
                and parsed.suite_id is not context.suite_id
            )
            records.append(
                {
                    "case": mutation,
                    "generic_parser_rejected": rejected,
                    "invariant_match": protected,
                    "left": preset,
                    "left_hex": encoded.hex(),
                    "right": mutation,
                    "right_hex": changed.hex(),
                }
            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(str(record["case"]), []).append(record)
    return [
        {
            "case": case,
            "checked": len(group),
            "violations": sum(item["invariant_match"] is False for item in group),
        }
        for case, group in sorted(grouped.items())
    ]
