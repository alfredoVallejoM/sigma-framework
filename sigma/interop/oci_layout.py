"""IX0-C OCI Image Layout export and offline verification."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sigma.artifact import SigmaArtifactV1

from .oci import (
    OCI_EMPTY_CONFIG_BYTES,
    OCI_EMPTY_CONFIG_DIGEST,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_ARTIFACT_ID_ANNOTATION,
    SIGMA_ARTIFACT_REFERRER_TYPE,
    OciDescriptorV1,
    OciSigmaArtifactBindingV1,
    build_sigma_artifact_referrer_v1,
    oci_sha256_digest_v1,
    verify_sigma_artifact_referrer_v1,
)

OCI_LAYOUT_VERSION = "1.0.0"
OCI_LAYOUT_FILE = "oci-layout"
OCI_LAYOUT_INDEX_FILE = "index.json"
OCI_REF_NAME_ANNOTATION = "org.opencontainers.image.ref.name"

DEFAULT_LAYOUT_MAX_BLOB_BYTES = 64 * 1024 * 1024
DEFAULT_LAYOUT_MAX_INDEX_BYTES = 4 * 1024 * 1024
DEFAULT_LAYOUT_MAX_ENTRIES = 10_000


class OciLayoutError(RuntimeError):
    """Base IX0-C OCI layout failure."""


class OciLayoutIntegrityError(OciLayoutError):
    """Layout bytes, descriptors, or topology are inconsistent."""


class OciLayoutResourceLimitError(OciLayoutError):
    """Configured layout resource ceiling was exceeded."""


@dataclass(frozen=True)
class OciLayoutLimitsV1:
    max_blob_bytes: int = DEFAULT_LAYOUT_MAX_BLOB_BYTES
    max_index_bytes: int = DEFAULT_LAYOUT_MAX_INDEX_BYTES
    max_entries: int = DEFAULT_LAYOUT_MAX_ENTRIES

    def __post_init__(self) -> None:
        for name, value in (
            ("max_blob_bytes", self.max_blob_bytes),
            ("max_index_bytes", self.max_index_bytes),
            ("max_entries", self.max_entries),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(f"{name} must be a positive int")


@dataclass(frozen=True)
class OciLayoutWriteResultV1:
    root: Path
    subject_descriptor: OciDescriptorV1
    binding: OciSigmaArtifactBindingV1
    index_descriptor_count: int


def _strict_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise OciLayoutIntegrityError(
                "duplicate OCI layout JSON key"
            )
        out[key] = value
    return out


def _load_json_object(
    wire: bytes,
    *,
    what: str,
) -> dict[str, object]:
    try:
        value = json.loads(
            wire.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except OciLayoutIntegrityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OciLayoutIntegrityError(
            f"{what} is invalid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise OciLayoutIntegrityError(
            f"{what} must be a JSON object"
        )
    return value


def _validate_subject_manifest(
    wire: bytes,
    *,
    media_type: str,
) -> None:
    value = _load_json_object(
        wire,
        what="OCI subject manifest",
    )
    if value.get("schemaVersion") != 2:
        raise OciLayoutIntegrityError(
            "OCI subject manifest schemaVersion must be 2"
        )
    declared = value.get("mediaType")
    if declared is not None:
        if not isinstance(declared, str):
            raise OciLayoutIntegrityError(
                "OCI subject manifest mediaType must be str"
            )
        if declared != media_type:
            raise OciLayoutIntegrityError(
                "OCI subject manifest mediaType differs from descriptor"
            )
    if not (
        ("config" in value and "layers" in value)
        or "manifests" in value
    ):
        raise OciLayoutIntegrityError(
            "OCI subject is not manifest/index shaped"
        )


def _atomic_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _sha256_blob_path(root: Path, digest: str) -> Path:
    prefix = "sha256:"
    if not isinstance(digest, str) or not digest.startswith(prefix):
        raise OciLayoutIntegrityError(
            "IX0-C layout supports sha256 blob descriptors only"
        )
    encoded = digest[len(prefix) :]
    if (
        len(encoded) != 64
        or any(char not in "0123456789abcdef" for char in encoded)
    ):
        raise OciLayoutIntegrityError(
            "invalid sha256 OCI layout digest"
        )
    return root / "blobs" / "sha256" / encoded


def _write_blob(
    root: Path,
    data: bytes,
    *,
    limits: OciLayoutLimitsV1,
) -> str:
    if len(data) > limits.max_blob_bytes:
        raise OciLayoutResourceLimitError(
            "OCI layout blob exceeds configured limit"
        )
    digest = oci_sha256_digest_v1(data)
    path = _sha256_blob_path(root, digest)
    if path.exists():
        if path.is_symlink():
            raise OciLayoutIntegrityError(
                "OCI layout blob path must not be symlink"
            )
        current = path.read_bytes()
        if current != data:
            raise OciLayoutIntegrityError(
                "existing OCI layout blob differs from digest content"
            )
        return digest
    _atomic_file(path, data)
    return digest


def _ensure_safe_root(root: Path) -> None:
    if root.is_symlink():
        raise OciLayoutIntegrityError(
            "OCI layout root must not be symlink"
        )
    for relative in (
        Path("blobs"),
        Path("blobs") / "sha256",
    ):
        candidate = root / relative
        if candidate.exists() and candidate.is_symlink():
            raise OciLayoutIntegrityError(
                "OCI layout directory must not be symlink"
            )


def _read_bounded_file(
    path: Path,
    *,
    max_bytes: int,
    what: str,
) -> bytes:
    if path.is_symlink():
        raise OciLayoutIntegrityError(
            f"{what} must not be symlink"
        )
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise OciLayoutIntegrityError(
            f"{what} is missing"
        ) from exc
    if size > max_bytes:
        raise OciLayoutResourceLimitError(
            f"{what} exceeds configured limit"
        )
    data = path.read_bytes()
    if len(data) != size:
        raise OciLayoutIntegrityError(
            f"{what} changed while reading"
        )
    return data


def _read_blob(
    root: Path,
    descriptor: OciDescriptorV1,
    *,
    limits: OciLayoutLimitsV1,
    what: str,
) -> bytes:
    if descriptor.size > limits.max_blob_bytes:
        raise OciLayoutResourceLimitError(
            f"{what} descriptor exceeds configured blob limit"
        )
    path = _sha256_blob_path(root, descriptor.digest)
    if path.parent.is_symlink() or path.parent.parent.is_symlink():
        raise OciLayoutIntegrityError(
            "OCI layout blob directory must not be symlink"
        )
    wire = _read_bounded_file(
        path,
        max_bytes=limits.max_blob_bytes,
        what=what,
    )
    if len(wire) != descriptor.size:
        raise OciLayoutIntegrityError(
            f"{what} size differs from descriptor"
        )
    if oci_sha256_digest_v1(wire) != descriptor.digest:
        raise OciLayoutIntegrityError(
            f"{what} digest differs from descriptor"
        )
    return wire


def _index_descriptor(
    descriptor: OciDescriptorV1,
    *,
    ref_name: str | None,
) -> OciDescriptorV1:
    if ref_name is None:
        return descriptor
    if not isinstance(ref_name, str) or not ref_name:
        raise ValueError("OCI layout ref name must be non-empty str")
    annotations = dict(descriptor.annotations)
    annotations[OCI_REF_NAME_ANNOTATION] = ref_name
    return OciDescriptorV1(
        media_type=descriptor.media_type,
        digest=descriptor.digest,
        size=descriptor.size,
        artifact_type=descriptor.artifact_type,
        annotations=tuple(sorted(annotations.items())),
        urls=descriptor.urls,
        data=descriptor.data,
        platform=descriptor.platform,
    )


def write_sigma_artifact_layout_v1(
    root: Path,
    artifact: SigmaArtifactV1,
    *,
    subject_wire: bytes,
    subject_media_type: str = OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    subject_ref_name: str | None = None,
    referrer_ref_name: str | None = None,
    annotations: dict[str, str] | None = None,
    limits: OciLayoutLimitsV1 | None = None,
) -> OciLayoutWriteResultV1:
    """Atomically publish a self-contained OCI layout with a Sigma referrer."""

    if not isinstance(root, Path):
        raise TypeError("root must be Path")
    if root.exists() or root.is_symlink():
        raise OciLayoutError(
            "OCI layout output path must not already exist"
        )
    if not isinstance(subject_wire, bytes):
        raise TypeError("subject_wire must be bytes")
    selected_limits = OciLayoutLimitsV1() if limits is None else limits
    if not isinstance(selected_limits, OciLayoutLimitsV1):
        raise TypeError("limits must be OciLayoutLimitsV1")
    if len(subject_wire) > selected_limits.max_blob_bytes:
        raise OciLayoutResourceLimitError(
            "OCI subject blob exceeds configured limit"
        )

    _validate_subject_manifest(
        subject_wire,
        media_type=subject_media_type,
    )
    subject = OciDescriptorV1(
        media_type=subject_media_type,
        digest=oci_sha256_digest_v1(subject_wire),
        size=len(subject_wire),
    )
    binding = build_sigma_artifact_referrer_v1(
        artifact,
        subject=subject,
        annotations=annotations,
    )

    root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{root.name}.",
            suffix=".tmp",
            dir=root.parent,
        )
    )
    try:
        _ensure_safe_root(temporary)
        (temporary / "blobs" / "sha256").mkdir(
            parents=True,
            exist_ok=True,
        )

        layout_wire = json.dumps(
            {"imageLayoutVersion": OCI_LAYOUT_VERSION},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        _atomic_file(
            temporary / OCI_LAYOUT_FILE,
            layout_wire,
        )

        _write_blob(
            temporary,
            OCI_EMPTY_CONFIG_BYTES,
            limits=selected_limits,
        )
        _write_blob(
            temporary,
            subject_wire,
            limits=selected_limits,
        )
        _write_blob(
            temporary,
            binding.artifact_wire,
            limits=selected_limits,
        )
        _write_blob(
            temporary,
            binding.manifest_wire,
            limits=selected_limits,
        )

        subject_index = _index_descriptor(
            subject,
            ref_name=subject_ref_name,
        )
        referrer_index = _index_descriptor(
            binding.manifest_descriptor,
            ref_name=referrer_ref_name,
        )
        index = {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [
                subject_index.to_dict(),
                referrer_index.to_dict(),
            ],
        }
        index_wire = json.dumps(
            index,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(index_wire) > selected_limits.max_index_bytes:
            raise OciLayoutResourceLimitError(
                "OCI layout index exceeds configured limit"
            )
        _atomic_file(
            temporary / OCI_LAYOUT_INDEX_FILE,
            index_wire,
        )

        os.replace(temporary, root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return OciLayoutWriteResultV1(
        root=root,
        subject_descriptor=subject,
        binding=binding,
        index_descriptor_count=2,
    )


def _layout_index(
    root: Path,
    *,
    limits: OciLayoutLimitsV1,
) -> tuple[OciDescriptorV1, ...]:
    layout_wire = _read_bounded_file(
        root / OCI_LAYOUT_FILE,
        max_bytes=64 * 1024,
        what="OCI layout header",
    )
    layout = _load_json_object(
        layout_wire,
        what="OCI layout header",
    )
    if layout.get("imageLayoutVersion") != OCI_LAYOUT_VERSION:
        raise OciLayoutIntegrityError(
            "unsupported OCI image layout version"
        )

    index_wire = _read_bounded_file(
        root / OCI_LAYOUT_INDEX_FILE,
        max_bytes=limits.max_index_bytes,
        what="OCI layout index",
    )
    index = _load_json_object(
        index_wire,
        what="OCI layout index",
    )
    if (
        index.get("schemaVersion") != 2
        or index.get("mediaType") != OCI_IMAGE_INDEX_MEDIA_TYPE
    ):
        raise OciLayoutIntegrityError(
            "OCI layout index profile mismatch"
        )
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise OciLayoutIntegrityError(
            "OCI layout index manifests must be a list"
        )
    if len(manifests) > limits.max_entries:
        raise OciLayoutResourceLimitError(
            "OCI layout index entry count exceeds configured limit"
        )
    try:
        return tuple(
            OciDescriptorV1.from_dict(item)
            for item in manifests
        )
    except ValueError as exc:
        raise OciLayoutIntegrityError(
            "OCI layout index descriptor is invalid"
        ) from exc


def _select_referrer(
    descriptors: tuple[OciDescriptorV1, ...],
    *,
    expected_artifact_id: bytes | None,
    referrer_digest: str | None,
    referrer_ref_name: str | None,
) -> OciDescriptorV1:
    sigma = tuple(
        item
        for item in descriptors
        if item.artifact_type == SIGMA_ARTIFACT_REFERRER_TYPE
    )
    if referrer_digest is not None:
        sigma = tuple(
            item
            for item in sigma
            if item.digest == referrer_digest
        )
    if referrer_ref_name is not None:
        if not isinstance(referrer_ref_name, str) or not referrer_ref_name:
            raise ValueError(
                "referrer_ref_name must be non-empty str or None"
            )
        sigma = tuple(
            item
            for item in sigma
            if dict(item.annotations).get(
                OCI_REF_NAME_ANNOTATION
            )
            == referrer_ref_name
        )
    if expected_artifact_id is not None:
        if (
            not isinstance(expected_artifact_id, bytes)
            or len(expected_artifact_id) != 32
        ):
            raise ValueError(
                "expected_artifact_id must contain exactly 32 bytes"
            )
        expected_hex = expected_artifact_id.hex()
        sigma = tuple(
            item
            for item in sigma
            if dict(item.annotations).get(
                SIGMA_ARTIFACT_ID_ANNOTATION
            )
            == expected_hex
        )
    if not sigma:
        raise OciLayoutIntegrityError(
            "no matching Sigma referrer in OCI layout index"
        )
    if len(sigma) != 1:
        raise OciLayoutIntegrityError(
            "ambiguous Sigma referrer selection in OCI layout index"
        )
    return sigma[0]


def verify_sigma_artifact_layout_v1(
    root: Path,
    *,
    expected_artifact_id: bytes | None = None,
    referrer_digest: str | None = None,
    referrer_ref_name: str | None = None,
    limits: OciLayoutLimitsV1 | None = None,
) -> OciSigmaArtifactBindingV1:
    """Verify a self-contained Sigma referrer from an OCI Image Layout."""

    if not isinstance(root, Path):
        raise TypeError("root must be Path")
    selected_limits = OciLayoutLimitsV1() if limits is None else limits
    if not isinstance(selected_limits, OciLayoutLimitsV1):
        raise TypeError("limits must be OciLayoutLimitsV1")
    if not root.is_dir() or root.is_symlink():
        raise OciLayoutIntegrityError(
            "OCI layout root must be a non-symlink directory"
        )
    _ensure_safe_root(root)

    descriptors = _layout_index(
        root,
        limits=selected_limits,
    )
    selected = _select_referrer(
        descriptors,
        expected_artifact_id=expected_artifact_id,
        referrer_digest=referrer_digest,
        referrer_ref_name=referrer_ref_name,
    )
    manifest_wire = _read_blob(
        root,
        selected,
        limits=selected_limits,
        what="Sigma OCI referrer manifest",
    )
    manifest = _load_json_object(
        manifest_wire,
        what="Sigma OCI referrer manifest",
    )
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise OciLayoutIntegrityError(
            "Sigma OCI referrer must contain exactly one layer"
        )
    try:
        payload_descriptor = OciDescriptorV1.from_dict(
            layers[0]
        )
        subject = OciDescriptorV1.from_dict(
            manifest.get("subject")
        )
    except ValueError as exc:
        raise OciLayoutIntegrityError(
            "Sigma OCI referrer descriptor is invalid"
        ) from exc

    artifact_wire = _read_blob(
        root,
        payload_descriptor,
        limits=selected_limits,
        what="Sigma artifact payload",
    )
    subject_wire = _read_blob(
        root,
        subject,
        limits=selected_limits,
        what="OCI subject",
    )
    _validate_subject_manifest(
        subject_wire,
        media_type=subject.media_type,
    )
    empty_descriptor = OciDescriptorV1(
        media_type="application/vnd.oci.empty.v1+json",
        digest=OCI_EMPTY_CONFIG_DIGEST,
        size=len(OCI_EMPTY_CONFIG_BYTES),
    )
    empty_wire = _read_blob(
        root,
        empty_descriptor,
        limits=selected_limits,
        what="OCI empty config",
    )
    if empty_wire != OCI_EMPTY_CONFIG_BYTES:
        raise OciLayoutIntegrityError(
            "OCI empty config bytes are non-canonical"
        )

    binding = verify_sigma_artifact_referrer_v1(
        manifest_wire,
        artifact_wire,
        expected_artifact_id=expected_artifact_id,
    )
    actual = binding.manifest_descriptor
    if (
        actual.media_type != selected.media_type
        or actual.digest != selected.digest
        or actual.size != selected.size
        or actual.artifact_type != selected.artifact_type
    ):
        raise OciLayoutIntegrityError(
            "OCI layout index referrer descriptor differs from manifest"
        )
    actual_annotations = dict(actual.annotations)
    selected_annotations = dict(selected.annotations)
    for key, value in actual_annotations.items():
        if selected_annotations.get(key) != value:
            raise OciLayoutIntegrityError(
                "OCI layout index referrer annotations differ from manifest"
            )
    extras = set(selected_annotations) - set(actual_annotations)
    if extras - {OCI_REF_NAME_ANNOTATION}:
        raise OciLayoutIntegrityError(
            "OCI layout index has unsupported extra referrer annotations"
        )
    return binding


__all__ = [
    "DEFAULT_LAYOUT_MAX_BLOB_BYTES",
    "DEFAULT_LAYOUT_MAX_ENTRIES",
    "DEFAULT_LAYOUT_MAX_INDEX_BYTES",
    "OCI_LAYOUT_FILE",
    "OCI_LAYOUT_INDEX_FILE",
    "OCI_LAYOUT_VERSION",
    "OCI_REF_NAME_ANNOTATION",
    "OciLayoutError",
    "OciLayoutIntegrityError",
    "OciLayoutLimitsV1",
    "OciLayoutResourceLimitError",
    "OciLayoutWriteResultV1",
    "verify_sigma_artifact_layout_v1",
    "write_sigma_artifact_layout_v1",
]
