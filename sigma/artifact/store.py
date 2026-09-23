"""PX1 local content-addressed store for canonical Sigma artifacts.

The filesystem blobs are the byte authority. SQLite is a transactional metadata
index only; changing or rebuilding it must never change a Sigma wire identity.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import sqlite3
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from sigma.tree.manifest import ManifestV1
from sigma.tree.persistent import TreePersistentIndexV1

from .record import SigmaArtifactV1, manifest_identity_v1

STORE_SCHEMA_VERSION = 1
MAX_STORE_LIST_ITEMS = 10_000
_EVIDENCE_KIND_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,127}\Z")
_EVIDENCE_ID_DOMAIN = b"SIGMA-PX1-EVIDENCE-ID-V1\x00"
_TREE_CACHE_ID_DOMAIN = b"SIGMA-PX1-TREE-CACHE-ID-V1\x00"


class ArtifactStoreError(RuntimeError):
    """Base exception for PX1 local-store failures."""


class ArtifactStoreNotFound(ArtifactStoreError):
    """Requested object is not visible in the store metadata."""


class ArtifactStoreIdentityError(ArtifactStoreError):
    """Canonical bytes do not match the requested content-addressed key."""


class ArtifactStoreConflictError(ArtifactStoreError):
    """A content-addressed key is already bound to different canonical bytes."""


class ArtifactStoreCorruptionError(ArtifactStoreError):
    """Store metadata or filesystem bytes violate a PX1 invariant."""


@dataclass(frozen=True)
class StorePutResultV1:
    object_id: bytes
    created: bool

    def __post_init__(self) -> None:
        if not isinstance(self.object_id, bytes) or len(self.object_id) != 32:
            raise ValueError("store object ID must contain exactly 32 bytes")
        if not isinstance(self.created, bool):
            raise TypeError("created must be bool")


@dataclass(frozen=True)
class StoreGCResultV1:
    declared_roots: int
    reachable_artifacts: int
    removed_artifacts: int
    removed_manifests: int
    removed_tree_indexes: int
    removed_evidence: int
    reclaimed_payload_bytes: int


FailureInjector = Callable[[str], None]


def _validate_id(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must contain exactly 32 bytes")
    return value


def _artifact_committed_bytes(artifact: SigmaArtifactV1) -> int:
    if artifact.tree_root is not None:
        return artifact.tree_root.byte_length
    assert artifact.trajectory_digest is not None
    return artifact.trajectory_digest.header.cardinality.byte_length


def _evidence_id(artifact_id: bytes, kind: str, payload: bytes) -> bytes:
    kind_wire = kind.encode("ascii")
    return hashlib.sha256(
        _EVIDENCE_ID_DOMAIN
        + artifact_id
        + len(kind_wire).to_bytes(2, "big")
        + kind_wire
        + len(payload).to_bytes(8, "big")
        + payload
    ).digest()


def _tree_cache_id(root_wire: bytes) -> bytes:
    return hashlib.sha256(_TREE_CACHE_ID_DOMAIN + root_wire).digest()


class LocalArtifactStoreV1:
    """Filesystem CAS plus SQLite metadata/index for PX1.

    All public visibility is driven by committed SQLite metadata. A blob left
    behind by an interrupted publication is an orphan and is not returned by
    has/get operations. A later identical put safely adopts that orphan.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        sqlite_timeout: float = 30.0,
        _failure_injector: FailureInjector | None = None,
    ) -> None:
        if isinstance(sqlite_timeout, bool) or sqlite_timeout <= 0:
            raise ValueError("sqlite_timeout must be positive")
        self.root = Path(root)
        self.sqlite_timeout = float(sqlite_timeout)
        self._failure_injector = _failure_injector
        self.database_path = self.root / "metadata.sqlite3"
        self._artifact_dir = self.root / "objects" / "artifacts"
        self._manifest_dir = self.root / "objects" / "manifests"
        self._index_dir = self.root / "cache" / "tree-indexes"
        self._evidence_dir = self.root / "evidence"
        self._initialize()

    def _hit(self, point: str) -> None:
        if self._failure_injector is not None:
            self._failure_injector(point)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.sqlite_timeout,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA busy_timeout={int(self.sqlite_timeout * 1000)}")
        return connection

    def _initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for directory in (
            self._artifact_dir,
            self._manifest_dir,
            self._index_dir,
            self._evidence_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(
            self.database_path,
            timeout=self.sqlite_timeout,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, STORE_SCHEMA_VERSION):
                raise ArtifactStoreError(
                    f"unsupported local-store schema version: {version}"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id BLOB PRIMARY KEY NOT NULL,
                    profile INTEGER NOT NULL,
                    manifest_id BLOB,
                    tree_root_wire BLOB,
                    committed_bytes INTEGER NOT NULL CHECK(committed_bytes >= 0),
                    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
                    created_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifact_parents (
                    child_id BLOB NOT NULL,
                    parent_id BLOB NOT NULL,
                    PRIMARY KEY(child_id, parent_id),
                    FOREIGN KEY(child_id) REFERENCES artifacts(artifact_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS artifact_parents_by_parent
                    ON artifact_parents(parent_id, child_id);

                CREATE TABLE IF NOT EXISTS manifests (
                    manifest_id BLOB PRIMARY KEY NOT NULL,
                    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
                    created_ns INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tree_indexes (
                    cache_id BLOB PRIMARY KEY NOT NULL,
                    root_wire BLOB UNIQUE NOT NULL,
                    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
                    created_ns INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id BLOB PRIMARY KEY NOT NULL,
                    artifact_id BLOB NOT NULL,
                    kind TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
                    created_ns INTEGER NOT NULL,
                    FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS evidence_by_artifact
                    ON evidence(artifact_id, evidence_id);
                """
            )
            if version == 0:
                connection.execute(f"PRAGMA user_version={STORE_SCHEMA_VERSION}")
        finally:
            connection.close()

    @staticmethod
    def _sharded_path(directory: Path, object_id: bytes, suffix: str) -> Path:
        hex_id = object_id.hex()
        return directory / hex_id[:2] / f"{hex_id[2:]}{suffix}"

    def _artifact_path(self, artifact_id: bytes) -> Path:
        return self._sharded_path(self._artifact_dir, artifact_id, ".sigart")

    def _manifest_path(self, manifest_id: bytes) -> Path:
        return self._sharded_path(self._manifest_dir, manifest_id, ".sigmanifest")

    def _index_path(self, cache_id: bytes) -> Path:
        return self._sharded_path(self._index_dir, cache_id, ".sigtidx")

    def _evidence_path(self, artifact_id: bytes, evidence_id: bytes) -> Path:
        return self._evidence_dir / artifact_id.hex() / f"{evidence_id.hex()}.evidence"

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        try:
            directory_fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            with contextlib.suppress(OSError):
                os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _atomic_publish(self, destination: Path, payload: bytes, *, point: str) -> bool:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            existing = destination.read_bytes()
            if existing == payload:
                return False
            raise ArtifactStoreConflictError(
                f"content-addressed path already contains different bytes: {destination}"
            )

        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            self._hit(f"{point}:before_replace")
            os.replace(temporary, destination)
            self._fsync_directory(destination.parent)
            self._hit(f"{point}:after_replace")
            return True
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def put_artifact(
        self,
        artifact: SigmaArtifactV1,
        *,
        expected_artifact_id: bytes | None = None,
    ) -> StorePutResultV1:
        if not isinstance(artifact, SigmaArtifactV1):
            raise TypeError("artifact must be SigmaArtifactV1")
        return self.put_artifact_bytes(
            artifact.to_bytes(),
            expected_artifact_id=expected_artifact_id,
        )

    def put_artifact_bytes(
        self,
        payload: bytes,
        *,
        expected_artifact_id: bytes | None = None,
    ) -> StorePutResultV1:
        if not isinstance(payload, bytes):
            raise TypeError("artifact payload must be bytes")
        artifact = SigmaArtifactV1.from_bytes(payload)
        if artifact.to_bytes() != payload:
            raise ArtifactStoreIdentityError("artifact payload is not canonical")
        if artifact.trajectory_audit is not None:
            raise ArtifactStoreIdentityError(
                "ArtifactId does not bind TrajectoryAudit bytes; store the canonical "
                "base artifact and attach trajectory audit as auxiliary evidence"
            )
        artifact_id = artifact.artifact_id
        if expected_artifact_id is not None:
            _validate_id("expected_artifact_id", expected_artifact_id)
            if expected_artifact_id != artifact_id:
                raise ArtifactStoreIdentityError(
                    "expected ArtifactId differs from canonical artifact identity"
                )

        destination = self._artifact_path(artifact_id)
        connection = self._connect()
        try:
            self._begin(connection)
            row = connection.execute(
                "SELECT payload_bytes FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if row is not None:
                try:
                    existing = destination.read_bytes()
                except FileNotFoundError as exc:
                    raise ArtifactStoreCorruptionError(
                        "artifact metadata is visible but CAS blob is missing"
                    ) from exc
                if int(row[0]) != len(existing):
                    raise ArtifactStoreCorruptionError(
                        "artifact metadata payload length differs from CAS bytes"
                    )
                if existing != payload:
                    raise ArtifactStoreConflictError(
                        "ArtifactId is already stored with a different envelope; "
                        "attach auxiliary evidence instead of replacing it"
                    )
                connection.commit()
                return StorePutResultV1(artifact_id, False)

            self._atomic_publish(
                destination,
                payload,
                point="artifact_publish",
            )
            self._hit("artifact_publish:before_metadata")
            connection.execute(
                """
                INSERT INTO artifacts(
                    artifact_id, profile, manifest_id, tree_root_wire,
                    committed_bytes, payload_bytes, created_ns
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    int(artifact.profile),
                    artifact.manifest_id,
                    None if artifact.tree_root is None else artifact.tree_root.to_bytes(),
                    _artifact_committed_bytes(artifact),
                    len(payload),
                    time.time_ns(),
                ),
            )
            connection.executemany(
                "INSERT INTO artifact_parents(child_id, parent_id) VALUES(?, ?)",
                tuple((artifact_id, parent) for parent in artifact.parent_artifact_ids),
            )
            self._hit("artifact_publish:before_commit")
            connection.commit()
            return StorePutResultV1(artifact_id, True)
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
            raise
        finally:
            connection.close()

    def has_artifact(self, artifact_id: bytes) -> bool:
        _validate_id("artifact_id", artifact_id)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
        finally:
            connection.close()
        return row is not None and self._artifact_path(artifact_id).is_file()

    def get_artifact_bytes(self, artifact_id: bytes) -> bytes:
        _validate_id("artifact_id", artifact_id)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT profile, manifest_id, tree_root_wire, committed_bytes, payload_bytes
                FROM artifacts WHERE artifact_id=?
                """,
                (artifact_id,),
            ).fetchone()
            parents = tuple(
                item[0]
                for item in connection.execute(
                    """
                    SELECT parent_id FROM artifact_parents
                    WHERE child_id=? ORDER BY parent_id
                    """,
                    (artifact_id,),
                ).fetchall()
            )
        finally:
            connection.close()
        if row is None:
            raise ArtifactStoreNotFound(f"artifact not found: {artifact_id.hex()}")
        try:
            payload = self._artifact_path(artifact_id).read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactStoreCorruptionError(
                "artifact metadata is visible but CAS blob is missing"
            ) from exc
        if len(payload) != int(row[4]):
            raise ArtifactStoreCorruptionError("artifact CAS length differs from metadata")
        try:
            artifact = SigmaArtifactV1.from_bytes(payload)
        except (TypeError, ValueError) as exc:
            raise ArtifactStoreCorruptionError("stored artifact wire is invalid") from exc
        if artifact.artifact_id != artifact_id or artifact.to_bytes() != payload:
            raise ArtifactStoreCorruptionError("stored artifact identity is non-canonical")
        expected_tree = None if artifact.tree_root is None else artifact.tree_root.to_bytes()
        if (
            int(row[0]) != int(artifact.profile)
            or row[1] != artifact.manifest_id
            or row[2] != expected_tree
            or int(row[3]) != _artifact_committed_bytes(artifact)
            or parents != artifact.parent_artifact_ids
        ):
            raise ArtifactStoreCorruptionError("artifact metadata differs from canonical wire")
        return payload

    def get_artifact(self, artifact_id: bytes) -> SigmaArtifactV1:
        return SigmaArtifactV1.from_bytes(self.get_artifact_bytes(artifact_id))

    def verify_artifact(self, artifact_id: bytes) -> bool:
        try:
            self.get_artifact_bytes(artifact_id)
        except (ArtifactStoreError, TypeError, ValueError):
            return False
        return True

    def list_artifact_ids(
        self,
        *,
        limit: int = 1000,
        after: bytes | None = None,
    ) -> tuple[bytes, ...]:
        if isinstance(limit, bool) or not 1 <= limit <= MAX_STORE_LIST_ITEMS:
            raise ValueError(
                f"limit must be between 1 and {MAX_STORE_LIST_ITEMS}"
            )
        if after is not None:
            _validate_id("after", after)
        connection = self._connect()
        try:
            if after is None:
                rows = connection.execute(
                    "SELECT artifact_id FROM artifacts ORDER BY artifact_id LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT artifact_id FROM artifacts
                    WHERE artifact_id > ?
                    ORDER BY artifact_id LIMIT ?
                    """,
                    (after, limit),
                ).fetchall()
        finally:
            connection.close()
        return tuple(row[0] for row in rows)

    def parents(self, artifact_id: bytes) -> tuple[bytes, ...]:
        _validate_id("artifact_id", artifact_id)
        connection = self._connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if exists is None:
                raise ArtifactStoreNotFound(f"artifact not found: {artifact_id.hex()}")
            rows = connection.execute(
                """
                SELECT parent_id FROM artifact_parents
                WHERE child_id=? ORDER BY parent_id
                """,
                (artifact_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(row[0] for row in rows)

    def children(self, artifact_id: bytes) -> tuple[bytes, ...]:
        _validate_id("artifact_id", artifact_id)
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT child_id FROM artifact_parents
                WHERE parent_id=? ORDER BY child_id
                """,
                (artifact_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(row[0] for row in rows)

    def delete_artifact(self, artifact_id: bytes, *, force: bool = False) -> bool:
        _validate_id("artifact_id", artifact_id)
        if not isinstance(force, bool):
            raise TypeError("force must be bool")
        connection = self._connect()
        evidence_ids: tuple[bytes, ...] = ()
        try:
            self._begin(connection)
            exists = connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            if exists is None:
                connection.commit()
                return False
            if not force:
                child = connection.execute(
                    "SELECT child_id FROM artifact_parents WHERE parent_id=? LIMIT 1",
                    (artifact_id,),
                ).fetchone()
                if child is not None:
                    raise ArtifactStoreConflictError(
                        "artifact is referenced by a stored child; use force=True "
                        "or garbage collection from declared roots"
                    )
            evidence_ids = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT evidence_id FROM evidence WHERE artifact_id=?",
                    (artifact_id,),
                ).fetchall()
            )
            connection.execute("DELETE FROM artifacts WHERE artifact_id=?", (artifact_id,))
            self._hit("artifact_delete:before_commit")
            connection.commit()
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
            raise
        finally:
            connection.close()

        with contextlib.suppress(OSError):
            self._artifact_path(artifact_id).unlink(missing_ok=True)
        for evidence_id in evidence_ids:
            with contextlib.suppress(OSError):
                self._evidence_path(artifact_id, evidence_id).unlink(missing_ok=True)
        return True

    def put_manifest(self, manifest: ManifestV1) -> StorePutResultV1:
        if not isinstance(manifest, ManifestV1):
            raise TypeError("manifest must be ManifestV1")
        return self.put_manifest_bytes(manifest.to_bytes())

    def put_manifest_bytes(
        self,
        payload: bytes,
        *,
        expected_manifest_id: bytes | None = None,
    ) -> StorePutResultV1:
        if not isinstance(payload, bytes):
            raise TypeError("manifest payload must be bytes")
        manifest = ManifestV1.from_bytes(payload)
        if manifest.to_bytes() != payload:
            raise ArtifactStoreIdentityError("manifest payload is not canonical")
        manifest_id = manifest_identity_v1(manifest)
        if expected_manifest_id is not None:
            _validate_id("expected_manifest_id", expected_manifest_id)
            if expected_manifest_id != manifest_id:
                raise ArtifactStoreIdentityError(
                    "expected ManifestId differs from canonical manifest identity"
                )
        destination = self._manifest_path(manifest_id)
        connection = self._connect()
        try:
            self._begin(connection)
            row = connection.execute(
                "SELECT payload_bytes FROM manifests WHERE manifest_id=?",
                (manifest_id,),
            ).fetchone()
            if row is not None:
                if int(row[0]) != len(payload) or destination.read_bytes() != payload:
                    raise ArtifactStoreConflictError(
                        "ManifestId is already stored with different bytes"
                    )
                connection.commit()
                return StorePutResultV1(manifest_id, False)
            self._atomic_publish(destination, payload, point="manifest_publish")
            connection.execute(
                """
                INSERT INTO manifests(manifest_id, payload_bytes, created_ns)
                VALUES(?, ?, ?)
                """,
                (manifest_id, len(payload), time.time_ns()),
            )
            self._hit("manifest_publish:before_commit")
            connection.commit()
            return StorePutResultV1(manifest_id, True)
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
            raise
        finally:
            connection.close()

    def get_manifest(self, manifest_id: bytes) -> ManifestV1:
        _validate_id("manifest_id", manifest_id)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT payload_bytes FROM manifests WHERE manifest_id=?",
                (manifest_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ArtifactStoreNotFound(f"manifest not found: {manifest_id.hex()}")
        try:
            payload = self._manifest_path(manifest_id).read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactStoreCorruptionError(
                "manifest metadata is visible but CAS blob is missing"
            ) from exc
        if len(payload) != int(row[0]):
            raise ArtifactStoreCorruptionError("manifest CAS length differs from metadata")
        try:
            manifest = ManifestV1.from_bytes(payload)
        except (TypeError, ValueError) as exc:
            raise ArtifactStoreCorruptionError("stored manifest wire is invalid") from exc
        if manifest.to_bytes() != payload or manifest_identity_v1(manifest) != manifest_id:
            raise ArtifactStoreCorruptionError("stored ManifestId does not match bytes")
        return manifest

    def put_tree_index(self, index: TreePersistentIndexV1) -> StorePutResultV1:
        if not isinstance(index, TreePersistentIndexV1):
            raise TypeError("index must be TreePersistentIndexV1")
        canonical = TreePersistentIndexV1(
            index.root,
            index.nodes,
            None,
            index.profile,
        )
        payload = canonical.to_bytes()
        root_wire = canonical.root.to_bytes()
        cache_id = _tree_cache_id(root_wire)
        destination = self._index_path(cache_id)
        connection = self._connect()
        try:
            self._begin(connection)
            row = connection.execute(
                "SELECT root_wire, payload_bytes FROM tree_indexes WHERE cache_id=?",
                (cache_id,),
            ).fetchone()
            if row is not None:
                if (
                    row[0] != root_wire
                    or int(row[1]) != len(payload)
                    or destination.read_bytes() != payload
                ):
                    raise ArtifactStoreConflictError(
                        "TreeRoot cache key is already stored with different bytes"
                    )
                connection.commit()
                return StorePutResultV1(cache_id, False)
            self._atomic_publish(destination, payload, point="tree_index_publish")
            connection.execute(
                """
                INSERT INTO tree_indexes(cache_id, root_wire, payload_bytes, created_ns)
                VALUES(?, ?, ?, ?)
                """,
                (cache_id, root_wire, len(payload), time.time_ns()),
            )
            self._hit("tree_index_publish:before_commit")
            connection.commit()
            return StorePutResultV1(cache_id, True)
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
            raise
        finally:
            connection.close()

    def get_tree_index(self, root_wire: bytes) -> TreePersistentIndexV1:
        if not isinstance(root_wire, bytes):
            raise TypeError("root_wire must be bytes")
        cache_id = _tree_cache_id(root_wire)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT root_wire, payload_bytes FROM tree_indexes WHERE cache_id=?",
                (cache_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ArtifactStoreNotFound("TreeRoot derived cache is not stored")
        if row[0] != root_wire:
            raise ArtifactStoreCorruptionError("tree-index cache key/root mismatch")
        try:
            payload = self._index_path(cache_id).read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactStoreCorruptionError(
                "tree-index metadata is visible but cache blob is missing"
            ) from exc
        if len(payload) != int(row[1]):
            raise ArtifactStoreCorruptionError("tree-index cache length differs from metadata")
        try:
            index = TreePersistentIndexV1.from_bytes(payload)
        except (TypeError, ValueError) as exc:
            raise ArtifactStoreCorruptionError("stored tree index is invalid") from exc
        if index.source_hint is not None or index.root.to_bytes() != root_wire:
            raise ArtifactStoreCorruptionError("stored tree index is not canonical PX1 cache")
        return index

    def attach_evidence(
        self,
        artifact_id: bytes,
        kind: str,
        payload: bytes,
    ) -> StorePutResultV1:
        _validate_id("artifact_id", artifact_id)
        if not isinstance(kind, str) or _EVIDENCE_KIND_RE.fullmatch(kind) is None:
            raise ValueError("evidence kind must be canonical lowercase ASCII token")
        if not isinstance(payload, bytes):
            raise TypeError("evidence payload must be bytes")
        evidence_id = _evidence_id(artifact_id, kind, payload)
        destination = self._evidence_path(artifact_id, evidence_id)
        connection = self._connect()
        try:
            self._begin(connection)
            if connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone() is None:
                raise ArtifactStoreNotFound(
                    f"artifact not found: {artifact_id.hex()}"
                )
            row = connection.execute(
                """
                SELECT kind, payload_bytes FROM evidence
                WHERE evidence_id=? AND artifact_id=?
                """,
                (evidence_id, artifact_id),
            ).fetchone()
            if row is not None:
                if (
                    row[0] != kind
                    or int(row[1]) != len(payload)
                    or destination.read_bytes() != payload
                ):
                    raise ArtifactStoreConflictError(
                        "evidence ID is already stored with different bytes"
                    )
                connection.commit()
                return StorePutResultV1(evidence_id, False)
            self._atomic_publish(destination, payload, point="evidence_publish")
            connection.execute(
                """
                INSERT INTO evidence(
                    evidence_id, artifact_id, kind, payload_bytes, created_ns
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (evidence_id, artifact_id, kind, len(payload), time.time_ns()),
            )
            self._hit("evidence_publish:before_commit")
            connection.commit()
            return StorePutResultV1(evidence_id, True)
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
            raise
        finally:
            connection.close()

    def list_evidence(
        self,
        artifact_id: bytes,
    ) -> tuple[tuple[bytes, str], ...]:
        _validate_id("artifact_id", artifact_id)
        connection = self._connect()
        try:
            if connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone() is None:
                raise ArtifactStoreNotFound(f"artifact not found: {artifact_id.hex()}")
            rows = connection.execute(
                """
                SELECT evidence_id, kind FROM evidence
                WHERE artifact_id=? ORDER BY evidence_id
                """,
                (artifact_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple((row[0], str(row[1])) for row in rows)

    def get_evidence(self, artifact_id: bytes, evidence_id: bytes) -> bytes:
        _validate_id("artifact_id", artifact_id)
        _validate_id("evidence_id", evidence_id)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT payload_bytes FROM evidence
                WHERE artifact_id=? AND evidence_id=?
                """,
                (artifact_id, evidence_id),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ArtifactStoreNotFound("evidence is not stored for artifact")
        try:
            payload = self._evidence_path(artifact_id, evidence_id).read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactStoreCorruptionError(
                "evidence metadata is visible but payload is missing"
            ) from exc
        if len(payload) != int(row[0]):
            raise ArtifactStoreCorruptionError("evidence payload length differs from metadata")
        return payload

    def garbage_collect(
        self,
        roots: Iterable[bytes],
        *,
        max_artifacts: int = 100_000,
        max_edges: int = 1_000_000,
        max_auxiliary_items: int = 1_000_000,
    ) -> StoreGCResultV1:
        roots_tuple = tuple(dict.fromkeys(roots))
        if not roots_tuple:
            raise ValueError("garbage collection requires at least one declared root")
        for root in roots_tuple:
            _validate_id("root ArtifactId", root)
        if (
            isinstance(max_artifacts, bool)
            or not isinstance(max_artifacts, int)
            or max_artifacts < 1
        ):
            raise ValueError("max_artifacts must be a positive integer")
        if isinstance(max_edges, bool) or not isinstance(max_edges, int) or max_edges < 0:
            raise ValueError("max_edges must be a non-negative integer")
        if (
            isinstance(max_auxiliary_items, bool)
            or not isinstance(max_auxiliary_items, int)
            or max_auxiliary_items < 0
        ):
            raise ValueError("max_auxiliary_items must be a non-negative integer")

        connection = self._connect()
        artifact_files: list[bytes] = []
        manifest_files: list[bytes] = []
        index_files: list[bytes] = []
        evidence_files: list[tuple[bytes, bytes]] = []
        reclaimed = 0
        reachable: set[bytes] = set()
        try:
            self._begin(connection)
            artifact_count = int(
                connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
            )
            if artifact_count > max_artifacts:
                raise ArtifactStoreError(
                    "garbage collection exceeds max_artifacts resource bound"
                )
            edge_count = int(
                connection.execute("SELECT COUNT(*) FROM artifact_parents").fetchone()[0]
            )
            if edge_count > max_edges:
                raise ArtifactStoreError(
                    "garbage collection exceeds max_edges resource bound"
                )
            auxiliary_count = sum(
                int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("evidence", "manifests", "tree_indexes")
            )
            if auxiliary_count > max_auxiliary_items:
                raise ArtifactStoreError(
                    "garbage collection exceeds max_auxiliary_items resource bound"
                )

            artifact_rows = connection.execute(
                """
                SELECT artifact_id, manifest_id, tree_root_wire, payload_bytes
                FROM artifacts
                """
            ).fetchall()
            stored = {row[0] for row in artifact_rows}
            missing_roots = tuple(root for root in roots_tuple if root not in stored)
            if missing_roots:
                raise ArtifactStoreNotFound(
                    f"declared GC root is not stored: {missing_roots[0].hex()}"
                )

            edge_rows = connection.execute(
                "SELECT child_id, parent_id FROM artifact_parents"
            ).fetchall()
            parents_by_child: dict[bytes, list[bytes]] = {}
            for child, parent in edge_rows:
                parents_by_child.setdefault(child, []).append(parent)

            queue: deque[bytes] = deque(roots_tuple)
            reachable.update(roots_tuple)
            while queue:
                child = queue.popleft()
                for parent in parents_by_child.get(child, ()):
                    if parent in stored and parent not in reachable:
                        reachable.add(parent)
                        queue.append(parent)

            unreachable_rows = [
                row for row in artifact_rows if row[0] not in reachable
            ]
            artifact_files = [row[0] for row in unreachable_rows]
            reclaimed += sum(int(row[3]) for row in unreachable_rows)

            evidence_rows = connection.execute(
                "SELECT artifact_id, evidence_id, payload_bytes FROM evidence"
            ).fetchall()
            evidence_files = [
                (artifact_id, evidence_id)
                for artifact_id, evidence_id, _ in evidence_rows
                if artifact_id not in reachable
            ]
            reclaimed += sum(
                int(payload_bytes)
                for artifact_id, _, payload_bytes in evidence_rows
                if artifact_id not in reachable
            )

            reachable_manifest_ids = {
                row[1]
                for row in artifact_rows
                if row[0] in reachable and row[1] is not None
            }
            manifest_rows = connection.execute(
                "SELECT manifest_id, payload_bytes FROM manifests"
            ).fetchall()
            removed_manifest_rows = [
                row for row in manifest_rows if row[0] not in reachable_manifest_ids
            ]
            manifest_files = [row[0] for row in removed_manifest_rows]
            reclaimed += sum(int(row[1]) for row in removed_manifest_rows)

            reachable_tree_roots = {
                row[2]
                for row in artifact_rows
                if row[0] in reachable and row[2] is not None
            }
            index_rows = connection.execute(
                "SELECT cache_id, root_wire, payload_bytes FROM tree_indexes"
            ).fetchall()
            removed_index_rows = [
                row for row in index_rows if row[1] not in reachable_tree_roots
            ]
            index_files = [row[0] for row in removed_index_rows]
            reclaimed += sum(int(row[2]) for row in removed_index_rows)

            connection.executemany(
                "DELETE FROM artifacts WHERE artifact_id=?",
                tuple((artifact_id,) for artifact_id in artifact_files),
            )
            connection.executemany(
                "DELETE FROM manifests WHERE manifest_id=?",
                tuple((manifest_id,) for manifest_id in manifest_files),
            )
            connection.executemany(
                "DELETE FROM tree_indexes WHERE cache_id=?",
                tuple((cache_id,) for cache_id in index_files),
            )
            self._hit("garbage_collect:before_commit")
            connection.commit()
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
            raise
        finally:
            connection.close()

        for artifact_id in artifact_files:
            with contextlib.suppress(OSError):
                self._artifact_path(artifact_id).unlink(missing_ok=True)
        for artifact_id, evidence_id in evidence_files:
            with contextlib.suppress(OSError):
                self._evidence_path(artifact_id, evidence_id).unlink(missing_ok=True)
        for manifest_id in manifest_files:
            with contextlib.suppress(OSError):
                self._manifest_path(manifest_id).unlink(missing_ok=True)
        for cache_id in index_files:
            with contextlib.suppress(OSError):
                self._index_path(cache_id).unlink(missing_ok=True)

        return StoreGCResultV1(
            declared_roots=len(roots_tuple),
            reachable_artifacts=len(reachable),
            removed_artifacts=len(artifact_files),
            removed_manifests=len(manifest_files),
            removed_tree_indexes=len(index_files),
            removed_evidence=len(evidence_files),
            reclaimed_payload_bytes=reclaimed,
        )


__all__ = [
    "ArtifactStoreConflictError",
    "ArtifactStoreCorruptionError",
    "ArtifactStoreError",
    "ArtifactStoreIdentityError",
    "ArtifactStoreNotFound",
    "LocalArtifactStoreV1",
    "MAX_STORE_LIST_ITEMS",
    "STORE_SCHEMA_VERSION",
    "StoreGCResultV1",
    "StorePutResultV1",
]
