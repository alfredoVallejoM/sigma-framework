"""Canonical Sigma Artifact V1 records and non-circular identity."""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from dataclasses import dataclass
from enum import IntEnum
from typing import Sequence

from sigma.outputs.digest_v3 import SigmaDigestV3
from sigma.spec.encoding import decode_uint, encode_uint
from sigma.trajectory.audit_v3 import TrajectoryAuditV3
from sigma.tree.manifest import ManifestV1
from sigma.tree.model import TreeRoot

from .codec import (
    ArtifactDecodeError,
    decode_id_sequence,
    encode_id_sequence,
    parse_record,
    record,
)
from .ids import (
    ARTIFACT_DESCRIPTOR_MAGIC,
    ARTIFACT_IDENTITY_MAGIC,
    ARTIFACT_ID_DOMAIN,
    ARTIFACT_MAGIC,
    MANIFEST_ID_DOMAIN,
    MAX_ARTIFACT_MEDIA_TYPE_BYTES,
    MAX_ARTIFACT_NAME_BYTES,
    MAX_ARTIFACT_PARENTS,
    ArtifactDescriptorProfileV1,
    ArtifactProfileV1,
)

_MEDIA_TYPE_RE = re.compile(
    rb"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*"
)


class _DescriptorField(IntEnum):
    PROFILE = 1
    LOGICAL_NAME = 2
    MEDIA_TYPE = 3


class _IdentityField(IntEnum):
    PROFILE = 1
    DESCRIPTOR = 2
    TREE_ROOT = 3
    TRAJECTORY_DIGEST = 4
    MANIFEST_ID = 5
    PARENTS = 6


class _ArtifactField(IntEnum):
    ARTIFACT_ID = 1
    IDENTITY = 2
    TRAJECTORY_AUDIT = 3


def _canonical_logical_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("logical_name must be str")
    if "\x00" in value:
        raise ValueError("logical_name must not contain NUL")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("logical_name must already be NFC-normalized")
    encoded = value.encode("utf-8", "strict")
    if len(encoded) > MAX_ARTIFACT_NAME_BYTES:
        raise ValueError("logical_name exceeds Artifact V1 limit")
    return value


def _canonical_media_type(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("media_type must be str")
    if not value:
        return value
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError("media_type must be ASCII") from exc
    if len(encoded) > MAX_ARTIFACT_MEDIA_TYPE_BYTES:
        raise ValueError("media_type exceeds Artifact V1 limit")
    if value.lower() != value or _MEDIA_TYPE_RE.fullmatch(encoded) is None:
        raise ValueError("media_type must be canonical lowercase type/subtype")
    return value


def _validate_optional_id(name: str, value: bytes | None) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must contain exactly 32 bytes")
    return value


def _validate_parent_ids(values: tuple[bytes, ...]) -> tuple[bytes, ...]:
    if not isinstance(values, tuple):
        raise TypeError("parent_artifact_ids must be tuple")
    if len(values) > MAX_ARTIFACT_PARENTS:
        raise ValueError("too many parent artifact IDs")
    if any(not isinstance(value, bytes) or len(value) != 32 for value in values):
        raise ValueError("parent artifact IDs must contain exactly 32 bytes")
    if tuple(sorted(set(values))) != values:
        raise ValueError("parent artifact IDs must be sorted and unique")
    return values


@dataclass(frozen=True)
class ArtifactDescriptorV1:
    logical_name: str = ""
    media_type: str = ""
    profile: ArtifactDescriptorProfileV1 = ArtifactDescriptorProfileV1.BASE_V1

    def __post_init__(self) -> None:
        if self.profile is not ArtifactDescriptorProfileV1.BASE_V1:
            raise ValueError("unsupported artifact descriptor profile")
        _canonical_logical_name(self.logical_name)
        _canonical_media_type(self.media_type)

    def to_bytes(self) -> bytes:
        return record(
            ARTIFACT_DESCRIPTOR_MAGIC,
            (
                (_DescriptorField.PROFILE, encode_uint(self.profile, 2)),
                (_DescriptorField.LOGICAL_NAME, self.logical_name.encode("utf-8")),
                (_DescriptorField.MEDIA_TYPE, self.media_type.encode("ascii")),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ArtifactDescriptorV1":
        fields = parse_record(
            data,
            magic=ARTIFACT_DESCRIPTOR_MAGIC,
            allowed=frozenset(int(field) for field in _DescriptorField),
        )
        try:
            profile = ArtifactDescriptorProfileV1(
                decode_uint(fields[_DescriptorField.PROFILE], 2)
            )
            logical_name = fields[_DescriptorField.LOGICAL_NAME].decode("utf-8")
            media_type = fields[_DescriptorField.MEDIA_TYPE].decode("ascii")
            return cls(logical_name=logical_name, media_type=media_type, profile=profile)
        except ArtifactDecodeError:
            raise
        except (KeyError, UnicodeDecodeError, TypeError, ValueError) as exc:
            raise ArtifactDecodeError("invalid ArtifactDescriptorV1") from exc


@dataclass(frozen=True)
class ArtifactIdentityV1:
    profile: ArtifactProfileV1
    descriptor: ArtifactDescriptorV1
    tree_root: TreeRoot | None = None
    trajectory_digest: SigmaDigestV3 | None = None
    manifest_id: bytes | None = None
    parent_artifact_ids: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.profile, ArtifactProfileV1):
            raise TypeError("artifact profile must be ArtifactProfileV1")
        if not isinstance(self.descriptor, ArtifactDescriptorV1):
            raise TypeError("descriptor must be ArtifactDescriptorV1")
        if self.tree_root is not None and not isinstance(self.tree_root, TreeRoot):
            raise TypeError("tree_root must be TreeRoot or None")
        if self.trajectory_digest is not None and not isinstance(
            self.trajectory_digest, SigmaDigestV3
        ):
            raise TypeError("trajectory_digest must be SigmaDigestV3 or None")
        _validate_optional_id("manifest_id", self.manifest_id)
        _validate_parent_ids(self.parent_artifact_ids)

        has_tree = self.tree_root is not None
        has_trajectory = self.trajectory_digest is not None
        expected = {
            ArtifactProfileV1.TREE: (True, False),
            ArtifactProfileV1.TRAJECTORY: (False, True),
            ArtifactProfileV1.DUAL: (True, True),
        }[self.profile]
        if (has_tree, has_trajectory) != expected:
            raise ValueError("artifact profile does not match exactly declared primary evidence")

        if (
            self.profile is ArtifactProfileV1.DUAL
            and self.tree_root is not None
            and self.trajectory_digest is not None
            and self.tree_root.byte_length
            != self.trajectory_digest.header.cardinality.byte_length
        ):
            raise ValueError("DUAL primary evidences commit different byte lengths")

    def to_bytes(self) -> bytes:
        return record(
            ARTIFACT_IDENTITY_MAGIC,
            (
                (_IdentityField.PROFILE, encode_uint(self.profile, 2)),
                (_IdentityField.DESCRIPTOR, self.descriptor.to_bytes()),
                (
                    _IdentityField.TREE_ROOT,
                    b"" if self.tree_root is None else self.tree_root.to_bytes(),
                ),
                (
                    _IdentityField.TRAJECTORY_DIGEST,
                    (
                        b""
                        if self.trajectory_digest is None
                        else self.trajectory_digest.to_bytes()
                    ),
                ),
                (_IdentityField.MANIFEST_ID, self.manifest_id or b""),
                (
                    _IdentityField.PARENTS,
                    encode_id_sequence(
                        self.parent_artifact_ids,
                        max_items=MAX_ARTIFACT_PARENTS,
                    ),
                ),
            ),
        )

    @property
    def artifact_id(self) -> bytes:
        return hashlib.sha256(ARTIFACT_ID_DOMAIN + self.to_bytes()).digest()

    @classmethod
    def from_bytes(cls, data: bytes) -> "ArtifactIdentityV1":
        fields = parse_record(
            data,
            magic=ARTIFACT_IDENTITY_MAGIC,
            allowed=frozenset(int(field) for field in _IdentityField),
        )
        try:
            profile = ArtifactProfileV1(
                decode_uint(fields[_IdentityField.PROFILE], 2)
            )
            tree_root = (
                None
                if not fields[_IdentityField.TREE_ROOT]
                else TreeRoot.from_bytes(fields[_IdentityField.TREE_ROOT])
            )
            trajectory_digest = (
                None
                if not fields[_IdentityField.TRAJECTORY_DIGEST]
                else SigmaDigestV3.from_bytes(
                    fields[_IdentityField.TRAJECTORY_DIGEST]
                )
            )
            manifest_id = (
                None
                if not fields[_IdentityField.MANIFEST_ID]
                else fields[_IdentityField.MANIFEST_ID]
            )
            return cls(
                profile=profile,
                descriptor=ArtifactDescriptorV1.from_bytes(
                    fields[_IdentityField.DESCRIPTOR]
                ),
                tree_root=tree_root,
                trajectory_digest=trajectory_digest,
                manifest_id=manifest_id,
                parent_artifact_ids=decode_id_sequence(
                    fields[_IdentityField.PARENTS],
                    max_items=MAX_ARTIFACT_PARENTS,
                ),
            )
        except ArtifactDecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ArtifactDecodeError("invalid ArtifactIdentityV1") from exc


@dataclass(frozen=True)
class SigmaArtifactV1:
    identity: ArtifactIdentityV1
    trajectory_audit: TrajectoryAuditV3 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ArtifactIdentityV1):
            raise TypeError("identity must be ArtifactIdentityV1")
        if self.trajectory_audit is not None:
            if not isinstance(self.trajectory_audit, TrajectoryAuditV3):
                raise TypeError("trajectory_audit must be TrajectoryAuditV3 or None")
            if self.identity.trajectory_digest is None:
                raise ValueError("TREE artifact must not carry trajectory audit")
            if not hmac.compare_digest(
                self.trajectory_audit.digest.to_bytes(),
                self.identity.trajectory_digest.to_bytes(),
            ):
                raise ValueError("trajectory audit projects a different SigmaDigestV3")

    @property
    def artifact_id(self) -> bytes:
        return self.identity.artifact_id

    @property
    def profile(self) -> ArtifactProfileV1:
        return self.identity.profile

    @property
    def descriptor(self) -> ArtifactDescriptorV1:
        return self.identity.descriptor

    @property
    def tree_root(self) -> TreeRoot | None:
        return self.identity.tree_root

    @property
    def trajectory_digest(self) -> SigmaDigestV3 | None:
        return self.identity.trajectory_digest

    @property
    def manifest_id(self) -> bytes | None:
        return self.identity.manifest_id

    @property
    def parent_artifact_ids(self) -> tuple[bytes, ...]:
        return self.identity.parent_artifact_ids

    def to_bytes(self) -> bytes:
        return record(
            ARTIFACT_MAGIC,
            (
                (_ArtifactField.ARTIFACT_ID, self.artifact_id),
                (_ArtifactField.IDENTITY, self.identity.to_bytes()),
                (
                    _ArtifactField.TRAJECTORY_AUDIT,
                    (
                        b""
                        if self.trajectory_audit is None
                        else self.trajectory_audit.to_bytes()
                    ),
                ),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaArtifactV1":
        fields = parse_record(
            data,
            magic=ARTIFACT_MAGIC,
            allowed=frozenset(int(field) for field in _ArtifactField),
        )
        try:
            artifact_id = fields[_ArtifactField.ARTIFACT_ID]
            if len(artifact_id) != 32:
                raise ValueError("ArtifactId must contain exactly 32 bytes")
            identity = ArtifactIdentityV1.from_bytes(fields[_ArtifactField.IDENTITY])
            if not hmac.compare_digest(artifact_id, identity.artifact_id):
                raise ValueError("stored ArtifactId does not match canonical identity")
            audit = (
                None
                if not fields[_ArtifactField.TRAJECTORY_AUDIT]
                else TrajectoryAuditV3.from_bytes(
                    fields[_ArtifactField.TRAJECTORY_AUDIT]
                )
            )
            return cls(identity=identity, trajectory_audit=audit)
        except ArtifactDecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ArtifactDecodeError("invalid SigmaArtifactV1") from exc


def manifest_identity_v1(manifest: ManifestV1) -> bytes:
    if not isinstance(manifest, ManifestV1):
        raise TypeError("manifest must be ManifestV1")
    return hashlib.sha256(MANIFEST_ID_DOMAIN + manifest.to_bytes()).digest()


def create_artifact_v1(
    profile: ArtifactProfileV1,
    *,
    descriptor: ArtifactDescriptorV1 | None = None,
    tree_root: TreeRoot | None = None,
    trajectory_digest: SigmaDigestV3 | None = None,
    trajectory_audit: TrajectoryAuditV3 | None = None,
    manifest: ManifestV1 | None = None,
    manifest_id: bytes | None = None,
    parent_artifact_ids: Sequence[bytes] = (),
) -> SigmaArtifactV1:
    if manifest is not None and manifest_id is not None:
        raise ValueError("supply manifest or manifest_id, not both")
    if manifest is not None:
        manifest_id = manifest_identity_v1(manifest)
    parents = tuple(sorted(set(parent_artifact_ids)))
    identity = ArtifactIdentityV1(
        profile=profile,
        descriptor=descriptor if descriptor is not None else ArtifactDescriptorV1(),
        tree_root=tree_root,
        trajectory_digest=trajectory_digest,
        manifest_id=manifest_id,
        parent_artifact_ids=parents,
    )
    return SigmaArtifactV1(identity, trajectory_audit)


__all__ = [
    "ArtifactDescriptorV1",
    "ArtifactIdentityV1",
    "SigmaArtifactV1",
    "create_artifact_v1",
    "manifest_identity_v1",
]
