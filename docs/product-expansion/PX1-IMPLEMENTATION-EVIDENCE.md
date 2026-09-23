# PX1 — Artifact CAS / Local Store Implementation Evidence

Status: **IMPLEMENTED — EXECUTED CLOSURE GATE PENDING**  
Date: 2026-09-24

PX1 is implemented on the active product-closure branch. It is intentionally not
marked COMPLETE until the repository-native unit/quality suite and the bounded
PX1 closure gate have actually executed. No GitHub Actions run was started for
this implementation round.

## 1. Scope

Implementation:

- sigma/artifact/store.py
- additive public exports in sigma.artifact
- tests/unit/test_artifact_store_px1.py
- scripts/product_closure/px1_gate.py

Backend:

- canonical blobs on the local filesystem;
- SQLite metadata/index;
- WAL journal mode;
- synchronous=FULL;
- BEGIN IMMEDIATE for serialised writers.

The filesystem bytes plus canonical Sigma parser/recomputation are the content
authority. SQLite is transactional visibility, lineage metadata and lookup
state. SQLite fields never participate in ArtifactId, ManifestId or TreeRoot.

## 2. Accepted CAS identity surface

ArtifactId V1 deliberately excludes TrajectoryAudit.

Therefore this relation is valid under SA0:

    ArtifactId(base)
      =
    ArtifactId(base + COMPACT audit)
      =
    ArtifactId(base + FULL audit)

while the three SigmaArtifactV1 envelope byte strings differ.

A store keyed only by ArtifactId must not choose one of those three byte strings
by last-writer-wins or first-writer-wins policy. That would make the value of a
content-addressed key depend on store history.

PX1 resolves this by accepting as the ArtifactId-addressed CAS value only the
canonical base SigmaArtifactV1 envelope with no TrajectoryAudit attached.

If an input envelope carries TrajectoryAudit, put rejects it with
ArtifactStoreIdentityError and directs the caller to the evidence surface.

TrajectoryAudit bytes are stored through:

    attach_evidence(artifact_id, "trajectory-audit-v3", payload)

This preserves both:
- SA0 identity semantics;
- PX1 byte-exact ArtifactId -> canonical SigmaArtifactV1 storage.

Evidence attachment never rewrites the ArtifactId-addressed blob.

## 3. Artifact publication

put_artifact / put_artifact_bytes perform, in order:

1. parse SigmaArtifactV1;
2. require canonical reserialization byte equality;
3. reject an auxiliary TrajectoryAudit envelope;
4. recompute canonical ArtifactId;
5. compare any caller-supplied expected ArtifactId;
6. acquire the SQLite writer transaction;
7. detect a committed duplicate or a recoverable orphan blob;
8. write a same-directory temporary file;
9. flush and fsync the file;
10. atomic os.replace;
11. best-effort directory fsync;
12. insert artifact metadata and identity-bound parent edges;
13. commit SQLite metadata.

The blob is not visible through store get/has until metadata commits.

A crash after blob replace but before metadata commit can therefore leave only an
invisible orphan. A later identical put adopts that orphan and completes metadata
publication.

A conflicting orphan or externally corrupted content-addressed path fails closed.

## 4. Idempotency and concurrency

Repeated put of the same canonical artifact returns the same ArtifactId and does
not create a second logical object.

SQLite BEGIN IMMEDIATE serialises writers across store connections. The PX1 gate
contains a concurrent identical-put campaign with eight workers and 64 puts. Its
closure condition is exactly one metadata creation and 64 identical ArtifactIds.

This is a correctness contract, not a throughput claim.

## 5. Manifest CAS

PX1 stores canonical ManifestV1 bytes under canonical ManifestId.

Before publication it:
- parses;
- canonical-reserializes;
- recomputes ManifestId;
- compares an optional expected ID.

Manifest storage is independent of ArtifactId. Artifacts retain their existing
identity-bound manifest_id field.

## 6. Persistent Tree index cache

PX0 TreePersistentIndexV1 is stored only as a derived cache.

TreeSourceHintV1 is stripped before cache publication because it is an
operational filesystem observation and is not root identity.

The local cache key is internal to PX1 and is derived from TreeRoot wire. It is
not a new public cryptographic identity and does not enter ArtifactId.

On retrieval PX1 reparses the index and requires:
- no source hint;
- exact TreeRoot wire;
- canonical PX0 index decoding.

## 7. Auxiliary evidence

Generic auxiliary evidence is addressed internally by a domain-separated digest
over:
- ArtifactId;
- canonical evidence-kind token;
- payload length;
- payload bytes.

This internal evidence key is storage machinery, not a new Sigma security claim.

Evidence requires the target artifact to be visible first. Deleting an artifact
also deletes evidence metadata; physical evidence bytes are then removed
best-effort.

## 8. Lineage queries

PX1 materializes the parent ArtifactIds already frozen into ArtifactIdentityV1.

Operations:

    parents(id)
    children(id)

The parent set remains authoritative in the canonical artifact wire. SQLite only
indexes it.

A parent may be unresolved/not locally stored. This preserves the existing SA0
identity instead of rewriting it to satisfy local-store state.

Normal delete refuses a stored artifact referenced by a stored child.
force=True can remove the local parent object while retaining the child's
identity-bound unresolved parent edge.

PX2 remains responsible for first-class DAG policy and transitive graph APIs.

## 9. Garbage collection

GC accepts one or more declared stored ArtifactId roots.

Reachability direction is:

    child -> identity-bound parents

Thus every stored ancestor required by a declared root is preserved.

GC also preserves:
- manifests referenced by reachable artifacts;
- PX0 tree indexes whose TreeRoot belongs to a reachable artifact;
- evidence attached to reachable artifacts.

Unreachable metadata is committed as deleted before physical unlink. A crash
during unlink may leak unreachable bytes but cannot resurrect deleted logical
objects.

An empty root set is rejected to prevent accidental whole-store destruction.

## 10. Fail-closed resource bounds

GC pre-counts before materializing rows.

Defaults:

    max_artifacts       = 100,000
    max_edges           = 1,000,000
    max_auxiliary_items = 1,000,000

Auxiliary items are evidence + manifests + tree indexes.

If any count exceeds policy, GC aborts before loading the corresponding graph
snapshot.

This repairs an adversarial-review finding in the first implementation draft,
where the bound was checked after fetchall and therefore did not actually bound
peak memory.

## 11. Listing bound

Artifact listing is keyset-paginated by ArtifactId.

Default:

    1,000 items

Hard per-call maximum:

    10,000 items

No unbounded list-all API is exposed in PX1.

## 12. Failure-injection surface

The executable gate covers three publication interruption classes:

- after write/fsync but before replace;
- os.replace failure;
- after blob publication but before SQLite commit.

Required result in every case:

    object is not visible

followed by:

    identical put recovers safely

## 13. PX1 closure gate

scripts/product_closure/px1_gate.py is bounded and deterministic.

Minimum campaign:

    store round-trips        300
    idempotent reuses        200
    wrong expected IDs       200
    crash/failure cases       90
    random GC DAGs           120
    concurrent same-ID puts   64

The gate additionally checks:
- canonical auxiliary-audit rejection;
- COMPACT and FULL audit evidence attachment;
- exact artifact byte round-trip;
- parent-closure GC against an independent in-gate graph traversal;
- surviving artifact byte equality;
- derived-cache/non-identity boundaries.

No result numbers are frozen here because this gate has not yet executed on the
repository checkout.

## 14. Adversarial review findings resolved

### AR-PX1-01 — ArtifactId / auxiliary envelope ambiguity

Finding:
ArtifactId does not hash TrajectoryAudit, so treating arbitrary SigmaArtifactV1
envelopes as a one-value CAS under ArtifactId is not well-defined.

Resolution:
CAS accepts only the no-audit canonical base envelope. Audit bytes use evidence.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX1-02 — GC resource check too late

Finding:
checking len(fetchall()) after row materialization did not protect peak memory.

Resolution:
COUNT(*) is checked under the writer snapshot before row materialization.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX1-03 — Empty-root destructive GC

Finding:
an empty declared root set would make every object unreachable.

Resolution:
empty roots fail closed.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX1-04 — crash between filesystem and metadata commit

Finding:
filesystem and SQLite cannot share one atomic commit.

Resolution:
metadata is the visibility boundary. A pre-commit blob is an invisible,
recoverable orphan.

Status: RESOLVED BY PROTOCOL; executable failure injection pending.

### AR-PX1-05 — PX0 source hints in derived cache

Finding:
two sidecars for the same root may differ only because of source path/stat hints.

Resolution:
PX1 strips source hints before root-addressed cache storage.

Status: RESOLVED IN IMPLEMENTATION.

## 15. Threat / claim boundary

PX1 does not claim:
- distributed transactions;
- Byzantine storage;
- authenticity against a hostile local administrator;
- remote-store semantics;
- signature/provenance semantics;
- confidentiality;
- a new cryptographic primitive.

A hostile process with filesystem/database write access can delete or corrupt
local state. PX1 detects canonical-artifact inconsistencies when reading/verifying
but does not turn a local filesystem into an authenticated remote store.

PX3 owns remote backend semantics.

## 16. Validation status

Performed during this implementation round:
- Python syntax/AST compilation of the new source/test/gate snapshots: PASS;
- design-time SQLite/atomicity/concurrency/GC mechanics simulation: PASS;
- adversarial identity/resource review: PASS after remediation.

Not executed in this environment:
- repository-native pytest;
- Ruff;
- Mypy;
- scripts/product_closure/px1_gate.py.

Therefore PX1 is ACTIVE / implemented but not COMPLETE.

## 17. Closure command set

Run locally on the exact active branch:

    python -m pytest -q tests/unit/test_artifact_store_px1.py
    python -m pytest -q tests/unit/test_artifact_sa0.py tests/unit/test_persistent_tree_index_px0.py
    python -m ruff check sigma/artifact/store.py sigma/artifact/__init__.py tests/unit/test_artifact_store_px1.py scripts/product_closure/px1_gate.py
    python -m mypy sigma/artifact/store.py
    python scripts/product_closure/px1_gate.py --report docs/product-expansion/PX1-GATE-REPORT.json

Only after all of those are green should PX1-O01..O04 and the stage registry move
to COMPLETE.
