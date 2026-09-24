"""IX0-D typed OCI referrers for frozen Sigma auxiliary wires.

These adapters do not create new cryptographic identities. ManifestV1 and
VerificationReceiptV1 reuse their existing canonical IDs. Tree proofs remain
identified by their exact OCI payload digest plus the TreeRoot embedded in the
proof wire.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from sigma.artifact import manifest_identity_v1
from sigma.trajectory import VerificationReceiptV1
from sigma.tree import InclusionProofV1, ManifestV1, RangeProofV1, TreeRoot

from .oci import (
    MAX_OCI_MANIFEST_BYTES,
    OCI_EMPTY_CONFIG_BYTES,
    OCI_EMPTY_CONFIG_DIGEST,
    OCI_EMPTY_CONFIG_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_WIRE_SHA256_ANNOTATION,
    OciDescriptorV1,
    OciManifestError,
    oci_sha256_digest_v1,
)

SIGMA_MANIFEST_MEDIA_TYPE = "application/vnd.sigma.manifest.v1"
SIGMA_MANIFEST_REFERRER_TYPE = "application/vnd.sigma.manifest.referrer.v1"
SIGMA_RECEIPT_MEDIA_TYPE = "application/vnd.sigma.verification-receipt.v1"
SIGMA_RECEIPT_REFERRER_TYPE = (
    "application/vnd.sigma.verification-receipt.referrer.v1"
)
SIGMA_INCLUSION_PROOF_MEDIA_TYPE = (
    "application/vnd.sigma.tree.inclusion-proof.v1"
)
SIGMA_INCLUSION_PROOF_REFERRER_TYPE = (
    "application/vnd.sigma.tree.inclusion-proof.referrer.v1"
)
SIGMA_RANGE_PROOF_MEDIA_TYPE = "application/vnd.sigma.tree.range-proof.v1"
SIGMA_RANGE_PROOF_REFERRER_TYPE = (
    "application/vnd.sigma.tree.range-proof.referrer.v1"
)

SIGMA_SIDECAR_KIND_ANNOTATION = "dev.sigma.sidecar.kind"
SIGMA_MANIFEST_ID_ANNOTATION = "dev.sigma.manifest.id"
SIGMA_RECEIPT_ID_ANNOTATION = "dev.sigma.receipt.id"
SIGMA_TREE_ROOT_WIRE_SHA256_ANNOTATION = (
    "dev.sigma.tree-root.wire.sha256"
)

_MAX_ANNOTATIONS = 128
_MAX_ANNOTATION_KEY_BYTES = 256
_MAX_ANNOTATION_VALUE_BYTES = 4096


class OciSigmaSidecarKindV1(str, Enum):
    MANIFEST = "manifest-v1"
    VERIFICATION_RECEIPT = "verification-receipt-v1"
    INCLUSION_PROOF = "tree-inclusion-proof-v1"
    RANGE_PROOF = "tree-range-proof-v1"


@dataclass(frozen=True)
class OciSigmaSidecarBindingV1:
    kind: OciSigmaSidecarKindV1
    subject: OciDescriptorV1
    payload_wire: bytes
    manifest_wire: bytes
    payload_descriptor: OciDescriptorV1
    manifest_descriptor: OciDescriptorV1
    semantic_id: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OciSigmaSidecarKindV1):
            raise TypeError("kind must be OciSigmaSidecarKindV1")
        if not isinstance(self.subject, OciDescriptorV1):
            raise TypeError("subject must be OciDescriptorV1")
        if not isinstance(self.payload_wire, bytes):
            raise TypeError("payload_wire must be bytes")
        if not isinstance(self.manifest_wire, bytes):
            raise TypeError("manifest_wire must be bytes")
        if not isinstance(self.payload_descriptor, OciDescriptorV1):
            raise TypeError(
                "payload_descriptor must be OciDescriptorV1"
            )
        if not isinstance(self.manifest_descriptor, OciDescriptorV1):
            raise TypeError(
                "manifest_descriptor must be OciDescriptorV1"
            )
        if self.semantic_id is not None and (
            not isinstance(self.semantic_id, bytes)
            or len(self.semantic_id) != 32
        ):
            raise ValueError(
                "semantic_id must contain exactly 32 bytes or be None"
            )


SigmaSidecarPayloadV1 = (
    ManifestV1
    | VerificationReceiptV1
    | InclusionProofV1
    | RangeProofV1
)


@dataclass(frozen=True)
class OciVerifiedSigmaSidecarV1:
    binding: OciSigmaSidecarBindingV1
    payload: SigmaSidecarPayloadV1

    def __post_init__(self) -> None:
        if not isinstance(self.binding, OciSigmaSidecarBindingV1):
            raise TypeError(
                "binding must be OciSigmaSidecarBindingV1"
            )
        if not isinstance(
            self.payload,
            (
                ManifestV1,
                VerificationReceiptV1,
                InclusionProofV1,
                RangeProofV1,
            ),
        ):
            raise TypeError("unsupported verified Sigma sidecar payload")


_KIND_PROFILE: dict[
    OciSigmaSidecarKindV1,
    tuple[str, str],
] = {
    OciSigmaSidecarKindV1.MANIFEST: (
        SIGMA_MANIFEST_MEDIA_TYPE,
        SIGMA_MANIFEST_REFERRER_TYPE,
    ),
    OciSigmaSidecarKindV1.VERIFICATION_RECEIPT: (
        SIGMA_RECEIPT_MEDIA_TYPE,
        SIGMA_RECEIPT_REFERRER_TYPE,
    ),
    OciSigmaSidecarKindV1.INCLUSION_PROOF: (
        SIGMA_INCLUSION_PROOF_MEDIA_TYPE,
        SIGMA_INCLUSION_PROOF_REFERRER_TYPE,
    ),
    OciSigmaSidecarKindV1.RANGE_PROOF: (
        SIGMA_RANGE_PROOF_MEDIA_TYPE,
        SIGMA_RANGE_PROOF_REFERRER_TYPE,
    ),
}
_ARTIFACT_TYPE_KIND = {
    artifact_type: kind
    for kind, (_payload_media_type, artifact_type) in _KIND_PROFILE.items()
}


def _strict_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise OciManifestError(
                "duplicate Sigma sidecar OCI JSON key"
            )
        out[key] = value
    return out


def _json_object(
    wire: bytes,
    *,
    what: str,
) -> dict[str, object]:
    try:
        value = json.loads(
            wire.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except OciManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OciManifestError(
            f"{what} is invalid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise OciManifestError(
            f"{what} must be a JSON object"
        )
    return value


def _canonical_annotations(
    values: Mapping[str, str] | tuple[tuple[str, str], ...] | None,
    *,
    reject_sigma_namespace: bool,
) -> tuple[tuple[str, str], ...]:
    if values is None:
        return ()
    items = (
        tuple(values.items())
        if isinstance(values, Mapping)
        else tuple(values)
    )
    if len(items) > _MAX_ANNOTATIONS:
        raise OciManifestError(
            "too many Sigma sidecar annotations"
        )
    seen: set[str] = set()
    output: list[tuple[str, str]] = []
    for key, value in items:
        if not isinstance(key, str) or not isinstance(value, str):
            raise OciManifestError(
                "Sigma sidecar annotations must be string pairs"
            )
        if not key or key in seen:
            raise OciManifestError(
                "Sigma sidecar annotation keys must be non-empty and unique"
            )
        if reject_sigma_namespace and key.startswith("dev.sigma."):
            raise OciManifestError(
                "dev.sigma.* annotations are reserved by IX0"
            )
        if len(key.encode("utf-8")) > _MAX_ANNOTATION_KEY_BYTES:
            raise OciManifestError(
                "Sigma sidecar annotation key exceeds limit"
            )
        if len(value.encode("utf-8")) > _MAX_ANNOTATION_VALUE_BYTES:
            raise OciManifestError(
                "Sigma sidecar annotation value exceeds limit"
            )
        seen.add(key)
        output.append((key, value))
    return tuple(sorted(output))


def _wire_sha256_hex(wire: bytes) -> str:
    return hashlib.sha256(wire).hexdigest()


def _root_wire_sha256_hex(root: TreeRoot) -> str:
    return hashlib.sha256(root.to_bytes()).hexdigest()


def _system_annotations(
    kind: OciSigmaSidecarKindV1,
    payload: SigmaSidecarPayloadV1,
    payload_wire: bytes,
) -> tuple[tuple[str, str], ...]:
    values: dict[str, str] = {
        SIGMA_SIDECAR_KIND_ANNOTATION: kind.value,
        SIGMA_WIRE_SHA256_ANNOTATION: _wire_sha256_hex(payload_wire),
    }
    if kind is OciSigmaSidecarKindV1.MANIFEST:
        if not isinstance(payload, ManifestV1):
            raise TypeError("manifest sidecar payload must be ManifestV1")
        values[SIGMA_MANIFEST_ID_ANNOTATION] = (
            manifest_identity_v1(payload).hex()
        )
    elif kind is OciSigmaSidecarKindV1.VERIFICATION_RECEIPT:
        if not isinstance(payload, VerificationReceiptV1):
            raise TypeError(
                "receipt sidecar payload must be VerificationReceiptV1"
            )
        values[SIGMA_RECEIPT_ID_ANNOTATION] = payload.receipt_id.hex()
    elif kind is OciSigmaSidecarKindV1.INCLUSION_PROOF:
        if not isinstance(payload, InclusionProofV1):
            raise TypeError(
                "inclusion sidecar payload must be InclusionProofV1"
            )
        values[SIGMA_TREE_ROOT_WIRE_SHA256_ANNOTATION] = (
            _root_wire_sha256_hex(payload.root)
        )
    elif kind is OciSigmaSidecarKindV1.RANGE_PROOF:
        if not isinstance(payload, RangeProofV1):
            raise TypeError(
                "range sidecar payload must be RangeProofV1"
            )
        values[SIGMA_TREE_ROOT_WIRE_SHA256_ANNOTATION] = (
            _root_wire_sha256_hex(payload.root)
        )
    else:  # pragma: no cover - closed enum
        raise AssertionError("unknown Sigma sidecar kind")
    return tuple(sorted(values.items()))


def _semantic_id(
    kind: OciSigmaSidecarKindV1,
    payload: SigmaSidecarPayloadV1,
) -> bytes | None:
    if kind is OciSigmaSidecarKindV1.MANIFEST:
        if not isinstance(payload, ManifestV1):
            raise TypeError("manifest sidecar payload must be ManifestV1")
        return manifest_identity_v1(payload)
    if kind is OciSigmaSidecarKindV1.VERIFICATION_RECEIPT:
        if not isinstance(payload, VerificationReceiptV1):
            raise TypeError(
                "receipt sidecar payload must be VerificationReceiptV1"
            )
        return payload.receipt_id
    return None


def _build_sidecar_referrer(
    kind: OciSigmaSidecarKindV1,
    payload: SigmaSidecarPayloadV1,
    *,
    subject: OciDescriptorV1,
    annotations: (
        Mapping[str, str] | tuple[tuple[str, str], ...] | None
    ) = None,
) -> OciSigmaSidecarBindingV1:
    if not isinstance(kind, OciSigmaSidecarKindV1):
        raise TypeError("kind must be OciSigmaSidecarKindV1")
    if not isinstance(subject, OciDescriptorV1):
        raise TypeError("subject must be OciDescriptorV1")
    payload_media_type, artifact_type = _KIND_PROFILE[kind]
    payload_wire = payload.to_bytes()
    system = _system_annotations(
        kind,
        payload,
        payload_wire,
    )
    user = _canonical_annotations(
        annotations,
        reject_sigma_namespace=True,
    )
    manifest_annotations = tuple(
        sorted((*system, *user))
    )

    payload_descriptor = OciDescriptorV1(
        media_type=payload_media_type,
        digest=oci_sha256_digest_v1(payload_wire),
        size=len(payload_wire),
        annotations=system,
    )
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "artifactType": artifact_type,
        "config": {
            "mediaType": OCI_EMPTY_CONFIG_MEDIA_TYPE,
            "digest": OCI_EMPTY_CONFIG_DIGEST,
            "size": len(OCI_EMPTY_CONFIG_BYTES),
        },
        "layers": [payload_descriptor.to_dict()],
        "subject": subject.to_dict(),
        "annotations": dict(manifest_annotations),
    }
    manifest_wire = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if len(manifest_wire) > MAX_OCI_MANIFEST_BYTES:
        raise OciManifestError(
            "Sigma sidecar OCI manifest exceeds IX0 size limit"
        )
    return OciSigmaSidecarBindingV1(
        kind=kind,
        subject=subject,
        payload_wire=payload_wire,
        manifest_wire=manifest_wire,
        payload_descriptor=payload_descriptor,
        manifest_descriptor=OciDescriptorV1(
            media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            digest=oci_sha256_digest_v1(manifest_wire),
            size=len(manifest_wire),
            artifact_type=artifact_type,
            annotations=manifest_annotations,
        ),
        semantic_id=_semantic_id(kind, payload),
    )


def build_sigma_manifest_referrer_v1(
    manifest: ManifestV1,
    *,
    subject: OciDescriptorV1,
    annotations: (
        Mapping[str, str] | tuple[tuple[str, str], ...] | None
    ) = None,
) -> OciSigmaSidecarBindingV1:
    if not isinstance(manifest, ManifestV1):
        raise TypeError("manifest must be ManifestV1")
    return _build_sidecar_referrer(
        OciSigmaSidecarKindV1.MANIFEST,
        manifest,
        subject=subject,
        annotations=annotations,
    )


def build_sigma_receipt_referrer_v1(
    receipt: VerificationReceiptV1,
    *,
    subject: OciDescriptorV1,
    annotations: (
        Mapping[str, str] | tuple[tuple[str, str], ...] | None
    ) = None,
) -> OciSigmaSidecarBindingV1:
    if not isinstance(receipt, VerificationReceiptV1):
        raise TypeError("receipt must be VerificationReceiptV1")
    return _build_sidecar_referrer(
        OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
        receipt,
        subject=subject,
        annotations=annotations,
    )


def build_sigma_inclusion_proof_referrer_v1(
    proof: InclusionProofV1,
    *,
    subject: OciDescriptorV1,
    annotations: (
        Mapping[str, str] | tuple[tuple[str, str], ...] | None
    ) = None,
) -> OciSigmaSidecarBindingV1:
    if not isinstance(proof, InclusionProofV1):
        raise TypeError("proof must be InclusionProofV1")
    return _build_sidecar_referrer(
        OciSigmaSidecarKindV1.INCLUSION_PROOF,
        proof,
        subject=subject,
        annotations=annotations,
    )


def build_sigma_range_proof_referrer_v1(
    proof: RangeProofV1,
    *,
    subject: OciDescriptorV1,
    annotations: (
        Mapping[str, str] | tuple[tuple[str, str], ...] | None
    ) = None,
) -> OciSigmaSidecarBindingV1:
    if not isinstance(proof, RangeProofV1):
        raise TypeError("proof must be RangeProofV1")
    return _build_sidecar_referrer(
        OciSigmaSidecarKindV1.RANGE_PROOF,
        proof,
        subject=subject,
        annotations=annotations,
    )


def _parse_payload(
    kind: OciSigmaSidecarKindV1,
    wire: bytes,
) -> SigmaSidecarPayloadV1:
    try:
        if kind is OciSigmaSidecarKindV1.MANIFEST:
            value: SigmaSidecarPayloadV1 = ManifestV1.from_bytes(wire)
        elif kind is OciSigmaSidecarKindV1.VERIFICATION_RECEIPT:
            value = VerificationReceiptV1.from_bytes(wire)
        elif kind is OciSigmaSidecarKindV1.INCLUSION_PROOF:
            value = InclusionProofV1.from_bytes(wire)
        elif kind is OciSigmaSidecarKindV1.RANGE_PROOF:
            value = RangeProofV1.from_bytes(wire)
        else:  # pragma: no cover - closed enum
            raise AssertionError("unknown Sigma sidecar kind")
    except (TypeError, ValueError) as exc:
        raise OciManifestError(
            "Sigma sidecar payload is not a valid canonical wire"
        ) from exc
    if value.to_bytes() != wire:
        raise OciManifestError(
            "Sigma sidecar payload is not byte-canonical"
        )
    return value


def verify_sigma_sidecar_referrer_v1(
    manifest_wire: bytes,
    payload_wire: bytes,
    *,
    expected_kind: OciSigmaSidecarKindV1 | None = None,
    expected_subject: OciDescriptorV1 | None = None,
    expected_semantic_id: bytes | None = None,
) -> OciVerifiedSigmaSidecarV1:
    if not isinstance(manifest_wire, bytes):
        raise TypeError("manifest_wire must be bytes")
    if not isinstance(payload_wire, bytes):
        raise TypeError("payload_wire must be bytes")
    if len(manifest_wire) > MAX_OCI_MANIFEST_BYTES:
        raise OciManifestError(
            "Sigma sidecar OCI manifest exceeds IX0 size limit"
        )
    if expected_kind is not None and not isinstance(
        expected_kind,
        OciSigmaSidecarKindV1,
    ):
        raise TypeError(
            "expected_kind must be OciSigmaSidecarKindV1 or None"
        )
    if expected_semantic_id is not None and (
        not isinstance(expected_semantic_id, bytes)
        or len(expected_semantic_id) != 32
    ):
        raise ValueError(
            "expected_semantic_id must contain exactly 32 bytes"
        )

    manifest = _json_object(
        manifest_wire,
        what="Sigma sidecar OCI manifest",
    )
    allowed = {
        "schemaVersion",
        "mediaType",
        "artifactType",
        "config",
        "layers",
        "subject",
        "annotations",
    }
    if set(manifest) - allowed:
        raise OciManifestError(
            "unsupported Sigma sidecar OCI manifest field"
        )
    artifact_type = manifest.get("artifactType")
    if not isinstance(artifact_type, str):
        raise OciManifestError(
            "Sigma sidecar artifactType must be str"
        )
    kind = _ARTIFACT_TYPE_KIND.get(artifact_type)
    if kind is None:
        raise OciManifestError(
            "unsupported Sigma sidecar artifactType"
        )
    if expected_kind is not None and kind is not expected_kind:
        raise OciManifestError(
            "Sigma sidecar kind differs from expected kind"
        )
    payload_media_type, expected_artifact_type = _KIND_PROFILE[kind]
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or artifact_type != expected_artifact_type
    ):
        raise OciManifestError(
            "Sigma sidecar OCI manifest profile mismatch"
        )
    if manifest.get("config") != {
        "mediaType": OCI_EMPTY_CONFIG_MEDIA_TYPE,
        "digest": OCI_EMPTY_CONFIG_DIGEST,
        "size": len(OCI_EMPTY_CONFIG_BYTES),
    }:
        raise OciManifestError(
            "Sigma sidecar config is not canonical empty config"
        )
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise OciManifestError(
            "Sigma sidecar must contain exactly one payload layer"
        )
    payload_descriptor = OciDescriptorV1.from_dict(layers[0])
    if payload_descriptor.media_type != payload_media_type:
        raise OciManifestError(
            "Sigma sidecar payload media type mismatch"
        )
    if (
        payload_descriptor.digest
        != oci_sha256_digest_v1(payload_wire)
        or payload_descriptor.size != len(payload_wire)
    ):
        raise OciManifestError(
            "Sigma sidecar payload descriptor does not match bytes"
        )

    subject = OciDescriptorV1.from_dict(
        manifest.get("subject")
    )
    if expected_subject is not None and subject != expected_subject:
        raise OciManifestError(
            "Sigma sidecar subject differs from expected subject"
        )
    payload = _parse_payload(kind, payload_wire)
    system = _system_annotations(
        kind,
        payload,
        payload_wire,
    )
    if payload_descriptor.annotations != system:
        raise OciManifestError(
            "Sigma sidecar payload annotations are not canonical"
        )

    raw_annotations = manifest.get("annotations")
    if not isinstance(raw_annotations, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in raw_annotations.items()
    ):
        raise OciManifestError(
            "Sigma sidecar manifest annotations must be a string map"
        )
    manifest_annotations = _canonical_annotations(
        raw_annotations,
        reject_sigma_namespace=False,
    )
    system_map = dict(system)
    manifest_map = dict(manifest_annotations)
    for key, value in system_map.items():
        if manifest_map.get(key) != value:
            raise OciManifestError(
                "Sigma sidecar system annotation mismatch"
            )
    unexpected_sigma = {
        key
        for key in manifest_map
        if key.startswith("dev.sigma.") and key not in system_map
    }
    if unexpected_sigma:
        raise OciManifestError(
            "Sigma sidecar contains unknown reserved system annotation"
        )

    semantic_id = _semantic_id(kind, payload)
    if (
        expected_semantic_id is not None
        and semantic_id != expected_semantic_id
    ):
        raise OciManifestError(
            "Sigma sidecar semantic identity differs from expected"
        )
    binding = OciSigmaSidecarBindingV1(
        kind=kind,
        subject=subject,
        payload_wire=payload_wire,
        manifest_wire=manifest_wire,
        payload_descriptor=payload_descriptor,
        manifest_descriptor=OciDescriptorV1(
            media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            digest=oci_sha256_digest_v1(manifest_wire),
            size=len(manifest_wire),
            artifact_type=artifact_type,
            annotations=manifest_annotations,
        ),
        semantic_id=semantic_id,
    )
    return OciVerifiedSigmaSidecarV1(
        binding=binding,
        payload=payload,
    )


def verify_sigma_manifest_referrer_v1(
    manifest_wire: bytes,
    payload_wire: bytes,
    *,
    expected_subject: OciDescriptorV1 | None = None,
    expected_manifest_id: bytes | None = None,
) -> OciVerifiedSigmaSidecarV1:
    return verify_sigma_sidecar_referrer_v1(
        manifest_wire,
        payload_wire,
        expected_kind=OciSigmaSidecarKindV1.MANIFEST,
        expected_subject=expected_subject,
        expected_semantic_id=expected_manifest_id,
    )


def verify_sigma_receipt_referrer_v1(
    manifest_wire: bytes,
    payload_wire: bytes,
    *,
    expected_subject: OciDescriptorV1 | None = None,
    expected_receipt_id: bytes | None = None,
) -> OciVerifiedSigmaSidecarV1:
    return verify_sigma_sidecar_referrer_v1(
        manifest_wire,
        payload_wire,
        expected_kind=OciSigmaSidecarKindV1.VERIFICATION_RECEIPT,
        expected_subject=expected_subject,
        expected_semantic_id=expected_receipt_id,
    )


def verify_sigma_inclusion_proof_referrer_v1(
    manifest_wire: bytes,
    payload_wire: bytes,
    *,
    expected_subject: OciDescriptorV1 | None = None,
    expected_root: TreeRoot | None = None,
) -> OciVerifiedSigmaSidecarV1:
    verified = verify_sigma_sidecar_referrer_v1(
        manifest_wire,
        payload_wire,
        expected_kind=OciSigmaSidecarKindV1.INCLUSION_PROOF,
        expected_subject=expected_subject,
    )
    if not isinstance(verified.payload, InclusionProofV1):
        raise AssertionError("inclusion proof verifier returned wrong type")
    if expected_root is not None and verified.payload.root != expected_root:
        raise OciManifestError(
            "Sigma inclusion proof root differs from expected root"
        )
    return verified


def verify_sigma_range_proof_referrer_v1(
    manifest_wire: bytes,
    payload_wire: bytes,
    *,
    expected_subject: OciDescriptorV1 | None = None,
    expected_root: TreeRoot | None = None,
) -> OciVerifiedSigmaSidecarV1:
    verified = verify_sigma_sidecar_referrer_v1(
        manifest_wire,
        payload_wire,
        expected_kind=OciSigmaSidecarKindV1.RANGE_PROOF,
        expected_subject=expected_subject,
    )
    if not isinstance(verified.payload, RangeProofV1):
        raise AssertionError("range proof verifier returned wrong type")
    if expected_root is not None and verified.payload.root != expected_root:
        raise OciManifestError(
            "Sigma range proof root differs from expected root"
        )
    return verified


def sidecar_artifact_type_v1(
    kind: OciSigmaSidecarKindV1,
) -> str:
    if not isinstance(kind, OciSigmaSidecarKindV1):
        raise TypeError("kind must be OciSigmaSidecarKindV1")
    return _KIND_PROFILE[kind][1]


__all__ = [
    "SIGMA_INCLUSION_PROOF_MEDIA_TYPE",
    "SIGMA_INCLUSION_PROOF_REFERRER_TYPE",
    "SIGMA_MANIFEST_ID_ANNOTATION",
    "SIGMA_MANIFEST_MEDIA_TYPE",
    "SIGMA_MANIFEST_REFERRER_TYPE",
    "SIGMA_RANGE_PROOF_MEDIA_TYPE",
    "SIGMA_RANGE_PROOF_REFERRER_TYPE",
    "SIGMA_RECEIPT_ID_ANNOTATION",
    "SIGMA_RECEIPT_MEDIA_TYPE",
    "SIGMA_RECEIPT_REFERRER_TYPE",
    "SIGMA_SIDECAR_KIND_ANNOTATION",
    "SIGMA_TREE_ROOT_WIRE_SHA256_ANNOTATION",
    "OciSigmaSidecarBindingV1",
    "OciSigmaSidecarKindV1",
    "OciVerifiedSigmaSidecarV1",
    "SigmaSidecarPayloadV1",
    "build_sigma_inclusion_proof_referrer_v1",
    "build_sigma_manifest_referrer_v1",
    "build_sigma_range_proof_referrer_v1",
    "build_sigma_receipt_referrer_v1",
    "sidecar_artifact_type_v1",
    "verify_sigma_inclusion_proof_referrer_v1",
    "verify_sigma_manifest_referrer_v1",
    "verify_sigma_range_proof_referrer_v1",
    "verify_sigma_receipt_referrer_v1",
    "verify_sigma_sidecar_referrer_v1",
]
