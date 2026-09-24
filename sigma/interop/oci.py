"""IX0 OCI/ORAS interoperability primitives.

This module maps canonical Sigma Artifact V1 bytes to OCI 1.1 referrer
manifests without conflating OCI content digests with Sigma ArtifactId.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping

from sigma.artifact import SigmaArtifactV1

OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
OCI_EMPTY_CONFIG_BYTES = b"{}"
OCI_EMPTY_CONFIG_DIGEST = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)

SIGMA_ARTIFACT_MEDIA_TYPE = "application/vnd.sigma.artifact.v1"
SIGMA_ARTIFACT_REFERRER_TYPE = "application/vnd.sigma.artifact.referrer.v1"
SIGMA_ARTIFACT_ID_ANNOTATION = "dev.sigma.artifact.id"
SIGMA_WIRE_SHA256_ANNOTATION = "dev.sigma.wire.sha256"

MAX_OCI_MANIFEST_BYTES = 1024 * 1024
MAX_OCI_ANNOTATIONS = 128
MAX_OCI_ANNOTATION_KEY_BYTES = 256
MAX_OCI_ANNOTATION_VALUE_BYTES = 4096

_DIGEST_RE = re.compile(
    r"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+$"
)


class OciInteropError(ValueError):
    """Base IX0 mapping/verification error."""


class OciManifestError(OciInteropError):
    """Raised for malformed or unsupported OCI manifest semantics."""


class OciArtifactBindingError(OciInteropError):
    """Raised when OCI metadata and Sigma identity disagree."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise OciManifestError("duplicate JSON object key")
        out[key] = value
    return out


def _load_json_object(data: bytes, *, what: str) -> dict[str, object]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except OciManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OciManifestError(f"{what} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise OciManifestError(f"{what} must be an object")
    return value


def _canonical_annotations(
    annotations: Mapping[str, str] | tuple[tuple[str, str], ...] | None,
) -> tuple[tuple[str, str], ...]:
    if annotations is None:
        return ()
    items = (
        tuple(annotations.items())
        if isinstance(annotations, Mapping)
        else tuple(annotations)
    )
    if len(items) > MAX_OCI_ANNOTATIONS:
        raise OciManifestError("too many OCI annotations")
    seen: set[str] = set()
    normalized: list[tuple[str, str]] = []
    for key, value in items:
        if not isinstance(key, str) or not isinstance(value, str):
            raise OciManifestError("OCI annotations must be string pairs")
        if not key or key in seen:
            raise OciManifestError(
                "OCI annotation keys must be non-empty and unique"
            )
        key_bytes = key.encode("utf-8", "strict")
        value_bytes = value.encode("utf-8", "strict")
        if len(key_bytes) > MAX_OCI_ANNOTATION_KEY_BYTES:
            raise OciManifestError("OCI annotation key exceeds IX0 limit")
        if len(value_bytes) > MAX_OCI_ANNOTATION_VALUE_BYTES:
            raise OciManifestError("OCI annotation value exceeds IX0 limit")
        seen.add(key)
        normalized.append((key, value))
    return tuple(sorted(normalized))


def _validate_digest(value: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise OciManifestError("invalid OCI digest")
    return value


def _validate_media_type(value: str) -> str:
    if not isinstance(value, str) or not value or "/" not in value:
        raise OciManifestError("invalid OCI media type")
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise OciManifestError("OCI media type must be ASCII") from exc
    return value


@dataclass(frozen=True)
class OciDescriptorV1:
    """Closed IX0 subset of the OCI descriptor used by subject/referrer flows."""

    media_type: str
    digest: str
    size: int
    artifact_type: str | None = None
    annotations: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _validate_media_type(self.media_type)
        _validate_digest(self.digest)
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 0
        ):
            raise OciManifestError(
                "OCI descriptor size must be a non-negative int"
            )
        if self.artifact_type is not None:
            _validate_media_type(self.artifact_type)
        object.__setattr__(
            self,
            "annotations",
            _canonical_annotations(self.annotations),
        )

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "mediaType": self.media_type,
            "digest": self.digest,
            "size": self.size,
        }
        if self.artifact_type is not None:
            out["artifactType"] = self.artifact_type
        if self.annotations:
            out["annotations"] = dict(self.annotations)
        return out

    @classmethod
    def from_dict(cls, value: object) -> "OciDescriptorV1":
        if not isinstance(value, dict):
            raise OciManifestError("OCI descriptor must be an object")
        allowed = {
            "mediaType",
            "digest",
            "size",
            "artifactType",
            "annotations",
        }
        if set(value) - allowed:
            raise OciManifestError("unsupported OCI descriptor field")

        media_type = value.get("mediaType")
        digest = value.get("digest")
        size = value.get("size")
        artifact_type = value.get("artifactType")
        annotations = value.get("annotations")

        if not isinstance(media_type, str):
            raise OciManifestError("OCI descriptor mediaType must be str")
        if not isinstance(digest, str):
            raise OciManifestError("OCI descriptor digest must be str")
        if isinstance(size, bool) or not isinstance(size, int):
            raise OciManifestError("OCI descriptor size must be int")
        if artifact_type is not None and not isinstance(artifact_type, str):
            raise OciManifestError(
                "OCI descriptor artifactType must be str"
            )
        if annotations is not None:
            if not isinstance(annotations, dict) or any(
                not isinstance(key, str) or not isinstance(item, str)
                for key, item in annotations.items()
            ):
                raise OciManifestError(
                    "OCI descriptor annotations must be a string map"
                )

        return cls(
            media_type=media_type,
            digest=digest,
            size=size,
            artifact_type=artifact_type,
            annotations=annotations,
        )


@dataclass(frozen=True)
class OciSigmaArtifactBindingV1:
    """An OCI subject/referrer binding plus its canonical Sigma payload."""

    subject: OciDescriptorV1
    artifact_id: bytes
    artifact_wire: bytes
    manifest_wire: bytes
    payload_descriptor: OciDescriptorV1
    manifest_descriptor: OciDescriptorV1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.artifact_id, bytes)
            or len(self.artifact_id) != 32
        ):
            raise OciArtifactBindingError(
                "artifact_id must contain exactly 32 bytes"
            )
        if not isinstance(self.artifact_wire, bytes):
            raise TypeError("artifact_wire must be bytes")
        if not isinstance(self.manifest_wire, bytes):
            raise TypeError("manifest_wire must be bytes")


def oci_sha256_digest_v1(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("OCI digest input must be bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sigma_artifact_payload_descriptor_v1(
    artifact: SigmaArtifactV1,
) -> OciDescriptorV1:
    if not isinstance(artifact, SigmaArtifactV1):
        raise TypeError("artifact must be SigmaArtifactV1")
    wire = artifact.to_bytes()
    return OciDescriptorV1(
        media_type=SIGMA_ARTIFACT_MEDIA_TYPE,
        digest=oci_sha256_digest_v1(wire),
        size=len(wire),
        annotations=(
            (SIGMA_ARTIFACT_ID_ANNOTATION, artifact.artifact_id.hex()),
            (
                SIGMA_WIRE_SHA256_ANNOTATION,
                hashlib.sha256(wire).hexdigest(),
            ),
        ),
    )


def build_sigma_artifact_referrer_v1(
    artifact: SigmaArtifactV1,
    *,
    subject: OciDescriptorV1,
    annotations: (
        Mapping[str, str] | tuple[tuple[str, str], ...] | None
    ) = None,
) -> OciSigmaArtifactBindingV1:
    """Build the OCI referrer manifest and payload descriptor for an artifact."""

    if not isinstance(artifact, SigmaArtifactV1):
        raise TypeError("artifact must be SigmaArtifactV1")
    if not isinstance(subject, OciDescriptorV1):
        raise TypeError("subject must be OciDescriptorV1")

    artifact_wire = artifact.to_bytes()
    payload = sigma_artifact_payload_descriptor_v1(artifact)
    manifest_annotations = dict(_canonical_annotations(annotations))
    if SIGMA_ARTIFACT_ID_ANNOTATION in manifest_annotations:
        raise OciManifestError(
            "dev.sigma.artifact.id is reserved by IX0"
        )
    manifest_annotations[SIGMA_ARTIFACT_ID_ANNOTATION] = (
        artifact.artifact_id.hex()
    )

    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "artifactType": SIGMA_ARTIFACT_REFERRER_TYPE,
        "config": {
            "mediaType": OCI_EMPTY_CONFIG_MEDIA_TYPE,
            "digest": OCI_EMPTY_CONFIG_DIGEST,
            "size": len(OCI_EMPTY_CONFIG_BYTES),
        },
        "layers": [payload.to_dict()],
        "subject": subject.to_dict(),
        "annotations": dict(sorted(manifest_annotations.items())),
    }
    manifest_wire = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if len(manifest_wire) > MAX_OCI_MANIFEST_BYTES:
        raise OciManifestError(
            "Sigma OCI referrer manifest exceeds IX0 size limit"
        )

    return OciSigmaArtifactBindingV1(
        subject=subject,
        artifact_id=artifact.artifact_id,
        artifact_wire=artifact_wire,
        manifest_wire=manifest_wire,
        payload_descriptor=payload,
        manifest_descriptor=OciDescriptorV1(
            media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            digest=oci_sha256_digest_v1(manifest_wire),
            size=len(manifest_wire),
            artifact_type=SIGMA_ARTIFACT_REFERRER_TYPE,
            annotations=(
                (
                    SIGMA_ARTIFACT_ID_ANNOTATION,
                    artifact.artifact_id.hex(),
                ),
            ),
        ),
    )


def verify_sigma_artifact_referrer_v1(
    manifest_wire: bytes,
    artifact_wire: bytes,
    *,
    expected_subject: OciDescriptorV1 | None = None,
    expected_artifact_id: bytes | None = None,
) -> OciSigmaArtifactBindingV1:
    """Verify an extracted referrer fully offline.

    OCI digest validation binds the extracted bytes; SigmaArtifactV1 parsing then
    recomputes and validates ArtifactId independently.
    """

    if not isinstance(manifest_wire, bytes) or not isinstance(
        artifact_wire,
        bytes,
    ):
        raise TypeError("manifest_wire and artifact_wire must be bytes")
    if len(manifest_wire) > MAX_OCI_MANIFEST_BYTES:
        raise OciManifestError("OCI manifest exceeds IX0 size limit")

    manifest = _load_json_object(
        manifest_wire,
        what="OCI manifest",
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
        raise OciManifestError("unsupported OCI manifest field")
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE
        or manifest.get("artifactType") != SIGMA_ARTIFACT_REFERRER_TYPE
    ):
        raise OciManifestError(
            "OCI manifest does not use Sigma IX0 artifact profile"
        )

    config = manifest.get("config")
    if config != {
        "mediaType": OCI_EMPTY_CONFIG_MEDIA_TYPE,
        "digest": OCI_EMPTY_CONFIG_DIGEST,
        "size": len(OCI_EMPTY_CONFIG_BYTES),
    }:
        raise OciManifestError(
            "Sigma IX0 manifest config is not canonical empty config"
        )

    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise OciManifestError(
            "Sigma IX0 manifest must contain exactly one payload layer"
        )
    payload = OciDescriptorV1.from_dict(layers[0])
    if payload.media_type != SIGMA_ARTIFACT_MEDIA_TYPE:
        raise OciManifestError(
            "Sigma IX0 payload media type mismatch"
        )

    subject = OciDescriptorV1.from_dict(manifest.get("subject"))
    if expected_subject is not None and subject != expected_subject:
        raise OciArtifactBindingError(
            "OCI subject differs from expected subject"
        )

    artifact = SigmaArtifactV1.from_bytes(artifact_wire)
    wire_digest = oci_sha256_digest_v1(artifact_wire)
    if (
        payload.digest != wire_digest
        or payload.size != len(artifact_wire)
    ):
        raise OciArtifactBindingError(
            "OCI payload descriptor does not match Sigma bytes"
        )

    payload_annotations = dict(payload.annotations)
    if payload_annotations.get(
        SIGMA_ARTIFACT_ID_ANNOTATION
    ) != artifact.artifact_id.hex():
        raise OciArtifactBindingError(
            "OCI payload annotation does not match ArtifactId"
        )
    if payload_annotations.get(
        SIGMA_WIRE_SHA256_ANNOTATION
    ) != hashlib.sha256(artifact_wire).hexdigest():
        raise OciArtifactBindingError(
            "OCI payload wire hash annotation mismatch"
        )

    manifest_annotations = manifest.get("annotations")
    if not isinstance(manifest_annotations, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in manifest_annotations.items()
    ):
        raise OciManifestError(
            "Sigma IX0 manifest annotations must be a string map"
        )
    canonical_manifest_annotations = dict(
        _canonical_annotations(manifest_annotations)
    )
    if canonical_manifest_annotations.get(
        SIGMA_ARTIFACT_ID_ANNOTATION
    ) != artifact.artifact_id.hex():
        raise OciArtifactBindingError(
            "OCI manifest annotation does not match ArtifactId"
        )

    if expected_artifact_id is not None:
        if (
            not isinstance(expected_artifact_id, bytes)
            or len(expected_artifact_id) != 32
        ):
            raise ValueError(
                "expected_artifact_id must contain exactly 32 bytes"
            )
        if expected_artifact_id != artifact.artifact_id:
            raise OciArtifactBindingError(
                "Sigma ArtifactId differs from expected identity"
            )

    return OciSigmaArtifactBindingV1(
        subject=subject,
        artifact_id=artifact.artifact_id,
        artifact_wire=artifact_wire,
        manifest_wire=manifest_wire,
        payload_descriptor=payload,
        manifest_descriptor=OciDescriptorV1(
            media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            digest=oci_sha256_digest_v1(manifest_wire),
            size=len(manifest_wire),
            artifact_type=SIGMA_ARTIFACT_REFERRER_TYPE,
            annotations=(
                (
                    SIGMA_ARTIFACT_ID_ANNOTATION,
                    artifact.artifact_id.hex(),
                ),
            ),
        ),
    )


def parse_sigma_referrers_index_v1(
    index_wire: bytes,
) -> tuple[OciDescriptorV1, ...]:
    """Extract Sigma IX0 descriptors from an OCI 1.1 referrers response."""

    if not isinstance(index_wire, bytes):
        raise TypeError("index_wire must be bytes")
    if len(index_wire) > MAX_OCI_MANIFEST_BYTES:
        raise OciManifestError(
            "OCI referrers index exceeds IX0 size limit"
        )

    payload = _load_json_object(
        index_wire,
        what="OCI referrers index",
    )
    allowed = {
        "schemaVersion",
        "mediaType",
        "manifests",
        "annotations",
    }
    if set(payload) - allowed:
        raise OciManifestError(
            "unsupported OCI referrers index field"
        )
    if (
        payload.get("schemaVersion") != 2
        or payload.get("mediaType") != OCI_IMAGE_INDEX_MEDIA_TYPE
    ):
        raise OciManifestError(
            "invalid OCI referrers index profile"
        )

    manifests = payload.get("manifests")
    if not isinstance(manifests, list):
        raise OciManifestError(
            "OCI referrers index manifests must be a list"
        )
    descriptors = tuple(
        OciDescriptorV1.from_dict(item)
        for item in manifests
    )
    return tuple(
        descriptor
        for descriptor in descriptors
        if descriptor.artifact_type == SIGMA_ARTIFACT_REFERRER_TYPE
    )


__all__ = [
    "MAX_OCI_MANIFEST_BYTES",
    "OCI_EMPTY_CONFIG_BYTES",
    "OCI_EMPTY_CONFIG_DIGEST",
    "OCI_EMPTY_CONFIG_MEDIA_TYPE",
    "OCI_IMAGE_INDEX_MEDIA_TYPE",
    "OCI_IMAGE_MANIFEST_MEDIA_TYPE",
    "SIGMA_ARTIFACT_ID_ANNOTATION",
    "SIGMA_ARTIFACT_MEDIA_TYPE",
    "SIGMA_ARTIFACT_REFERRER_TYPE",
    "SIGMA_WIRE_SHA256_ANNOTATION",
    "OciArtifactBindingError",
    "OciDescriptorV1",
    "OciInteropError",
    "OciManifestError",
    "OciSigmaArtifactBindingV1",
    "build_sigma_artifact_referrer_v1",
    "oci_sha256_digest_v1",
    "parse_sigma_referrers_index_v1",
    "sigma_artifact_payload_descriptor_v1",
    "verify_sigma_artifact_referrer_v1",
]
