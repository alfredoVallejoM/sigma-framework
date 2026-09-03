"""Generate the single normative Sigma v2.2 conformance corpus."""

import argparse
import json
from pathlib import Path

from sigma.anchors import AnchorEvidence, CrossWide, CrossWideEvidence, StreamWide, TreeWide
from sigma.applications.kdf_argon2id import Argon2idParameters, compose_argon2id_output
from sigma.applications.pow import PowParameters, PowPredicate, evaluate_nonce
from sigma.applications.signed import sign_ed25519
from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
    reference_v2_2,
    simultaneous_v2_2,
)
from sigma.rounds import Deep, DeepVector, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, RoundProfileId

MESSAGE = b"sigma-v2.2-conformance"
KDF_BASE_KEY = bytes(range(32))
KDF_SALT = b"sigma-v2.2-kdf-salt"
SIGNING_SEED = bytes(range(32))
SIGNING_KEY_ID = b"sigma-v2.2-vector-key"

ACTIVE_CONTEXTS = (
    ("reference-stream-wide-v2-2", reference_v2_2),
    ("lightweight-stream-wide-v2-2", lightweight_v2_2),
    ("simultaneous-tree-wide-v2-2", simultaneous_v2_2),
    ("paranoid-cross-wide-v2-2", paranoid_wide_v2_2),
    ("paranoid-deep-v2-2", paranoid_deep_v2_2),
    ("paranoid-deep-vector-v2-2", paranoid_deep_vector_v2_2),
)


def _suite_vector(name: str, context: SigmaContextV2) -> dict[str, object]:
    anchor: AnchorEvidence | CrossWideEvidence
    if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
        anchor = StreamWide.compute(context, (MESSAGE,))
    elif context.anchor_profile is AnchorProfileId.TREE_WIDE:
        anchor = TreeWide.compute(context, (MESSAGE,))
    else:
        anchor = CrossWide.compute(context, (MESSAGE,))
    if context.round_profile is RoundProfileId.WIDE_ONCE:
        digest, transcript = WideOnce(context).evaluate(anchor)
    elif context.round_profile is RoundProfileId.DEEP:
        digest, transcript = Deep(context).evaluate(anchor)  # type: ignore[arg-type]
    else:
        digest, transcript = DeepVector(context).evaluate(anchor)  # type: ignore[arg-type]
    return {
        "anchor_evidence_hex": anchor.to_bytes().hex(),
        "branch_outputs_hex": [
            [component.hex() for component in row] for row in transcript.branch_outputs
        ],
        "context_hex": context.to_bytes().hex(),
        "cross_roots_hex": [root.hex() for root in getattr(anchor, "cross_roots", ())],
        "digest_hex": digest.to_bytes().hex(),
        "message_hex": MESSAGE.hex(),
        "name": name,
        "roots_hex": [root.hex() for root in anchor.roots],
        "states_hex": [state.hex() for state in transcript.states],
    }


def generate() -> dict[str, object]:
    contexts = [(name, factory(target_round=2, state_count=3)) for name, factory in ACTIVE_CONTEXTS]
    pow_vectors = []
    for predicate in PowPredicate:
        state_count = 2 if predicate is PowPredicate.DUAL_STATE else 3
        parameters = PowParameters(b"vector-challenge", 2, state_count, predicate, 0)
        proof = evaluate_nonce(b"vector-payload", 7, parameters)
        pow_vectors.append(
            {
                "digest_hex": proof.digest.to_bytes().hex(),
                "nonce": proof.nonce,
                "parameters_hex": parameters.to_bytes().hex(),
                "payload_hex": b"vector-payload".hex(),
                "predicate": predicate.name,
            }
        )

    kdf_parameters = Argon2idParameters(19_456, 2, 1, len(KDF_BASE_KEY))
    kdf_vectors = []
    for preset in (
        "lightweight-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    ):
        result = compose_argon2id_output(KDF_BASE_KEY, KDF_SALT, kdf_parameters, preset=preset)
        kdf_vectors.append(
            {
                "base_key_hex": KDF_BASE_KEY.hex(),
                "final_key_hex": result.final_key.hex(),
                "parameters_hex": kdf_parameters.to_bytes().hex(),
                "password_record_hex": result.password_record().to_bytes().hex(),
                "preset": preset,
                "salt_hex": KDF_SALT.hex(),
                "sigma_digest_hex": result.sigma_digest.to_bytes().hex(),
            }
        )

    signed_vectors = []
    for name, factory in ACTIVE_CONTEXTS:
        commitment = sign_ed25519(
            MESSAGE,
            factory(target_round=2, state_count=2),
            SIGNING_SEED,
            SIGNING_KEY_ID,
        )
        signed_vectors.append(
            {
                "commitment_hex": commitment.to_bytes().hex(),
                "name": name,
                "public_key_id_hex": SIGNING_KEY_ID.hex(),
                "signing_seed_hex": SIGNING_SEED.hex(),
            }
        )

    suite_vectors = [_suite_vector(name, context) for name, context in contexts]
    canonical_samples = {
        "context": contexts[0][1].to_bytes(),
        "digest": bytes.fromhex(str(suite_vectors[0]["digest_hex"])),
        "evidence-wide": bytes.fromhex(str(suite_vectors[0]["anchor_evidence_hex"])),
        "evidence-cross": bytes.fromhex(str(suite_vectors[3]["anchor_evidence_hex"])),
        "pow": bytes.fromhex(str(pow_vectors[0]["parameters_hex"])),
        "kdf-parameters": kdf_parameters.to_bytes(),
        "kdf-record": bytes.fromhex(str(kdf_vectors[0]["password_record_hex"])),
        "signed": bytes.fromhex(str(signed_vectors[0]["commitment_hex"])),
    }
    negative_vectors: list[dict[str, str]] = []
    for codec, encoded in canonical_samples.items():
        negative_vectors.extend(
            (
                {"codec": codec, "encoded_hex": encoded[:-1].hex(), "mutation": "truncated"},
                {"codec": codec, "encoded_hex": (encoded + b"\x00").hex(), "mutation": "trailing"},
                {
                    "codec": codec,
                    "encoded_hex": (bytes((encoded[0] ^ 1,)) + encoded[1:]).hex(),
                    "mutation": "wrong-magic",
                },
            )
        )
    return {
        "applications": {
            "kdf": kdf_vectors,
            "pow": pow_vectors,
            "signed": signed_vectors,
        },
        "format": "sigma-conformance-v2",
        "negative": negative_vectors,
        "normative_suite_family": "v2-2",
        "suites": suite_vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite existing vector: {args.output}")
    args.output.write_text(
        json.dumps(generate(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
