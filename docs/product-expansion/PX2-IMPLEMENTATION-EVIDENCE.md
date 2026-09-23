# PX2 — Artifact Lineage Graph Implementation Evidence

Status: **ACTIVE — IMPLEMENTED, EXECUTED CLOSURE GATE PENDING**  
Date: 2026-09-24  
Branch: campaign/sigma-dual-integrity-product-closure

PX2 turns the parent ArtifactIds already frozen by SA0 into a first-class,
deterministic DAG API. It does not introduce a second lineage identity or mutable
edge authority.

No GitHub Actions run was started in this implementation round. PX2 remains
ACTIVE until the repository-native quality suite and px2_gate.py execute.

## 1. Product authority

The authoritative relation is exactly:

    SigmaArtifactV1.identity.parent_artifact_ids

SQLite artifact_parents is only an index maintained by PX1.

PX2 store snapshots:
1. enter one BEGIN IMMEDIATE transaction;
2. pre-check artifact and edge cardinality limits;
3. read artifact metadata and parent-index rows from the same SQLite snapshot;
4. read each canonical ArtifactId-addressed blob;
5. parse/recompute the artifact identity;
6. require SQLite parent metadata to equal the canonical parent tuple exactly;
7. build PX2 from the parsed SigmaArtifactV1 objects.

Therefore graph metadata cannot rewrite, add, reorder or silently remove identity
parents.

A corrupted parent index fails closed instead of becoming lineage truth.

## 2. Main implementation

Runtime:

    sigma/artifact/lineage.py

PX1 integration:

    LocalArtifactStoreV1._lineage_snapshot_artifacts(...)

Independent oracle:

    reference/lineage_v1.py

Tests:

    tests/unit/test_artifact_lineage_px2.py

Closure gate:

    scripts/product_closure/px2_gate.py

Public exports are additive under sigma.artifact.

## 3. Identity projection

LineageNodeV1 contains only:

    artifact_id
    parent_artifact_ids

LineageNodeV1.from_artifact(...) copies those values directly from
SigmaArtifactV1.

Direct LineageNodeV1 construction remains available for:
- adapter validation;
- malformed/cyclic graph analysis;
- adversarial tests.

Product-authoritative store construction always derives nodes from validated
canonical artifacts.

## 4. Parent resolution policies

Every graph build must choose ParentResolutionPolicyV1 explicitly.

### STRICT

Every identity-bound parent must be present in the local artifact set.

Any missing parent raises LineageParentResolutionError and reports the exact
sorted missing IDs.

### EXTERNAL

Every missing parent must be explicitly declared through external_parent_ids.

The declaration must be exact:
- an undeclared missing parent rejects;
- a declared ID that is stored or not referenced rejects.

Accepted external parents remain explicit graph-boundary nodes with status:

    EXTERNAL

They are never synthesized as stored artifacts.

### UNRESOLVED

Missing parents are accepted as an explicit boundary.

external_parent_ids may identify a subset as known external. Every remaining
missing parent receives status:

    UNRESOLVED

The canonical child parent tuple is unchanged.

Thus PX2 never converts:

    child -> missing parent

into:

    child -> ()

## 5. Boundary IDs remain queryable

For EXTERNAL and UNRESOLVED boundaries:

    parents(boundary) = ()

because no local canonical artifact is available to disclose further ancestry.

But reverse identity information remains available:

    children(boundary)

returns every local artifact that names that boundary ID.

descendants(boundary) can therefore explain local derivation downstream from a
known external/unresolved source.

## 6. Roots versus local entrypoints

PX2 distinguishes two concepts.

### roots()

A root is a stored artifact whose canonical identity contains no parent IDs.

This is a semantic property of ArtifactIdentityV1.

### local_entrypoints()

A local entrypoint is a stored artifact with no *stored* parent.

It may still have external or unresolved identity parents.

This distinction prevents an incomplete local mirror from relabelling an
externally-derived artifact as a true lineage root.

## 7. Cycle semantics

Accepted ArtifactLineageGraphV1 values are always acyclic over stored artifacts.

LineageCyclePolicyV1:

    REJECT
    REPORT

REJECT raises LineageCycleError with a deterministic closed cycle witness.

REPORT returns:

    accepted = false
    graph = None
    inspection.cycle_path = ...

It never returns a cyclic ArtifactLineageGraphV1.

Cycles are primarily an adapter/corruption adversarial surface: ordinary
content-addressed ArtifactIds make self-referential canonical artifacts
non-trivial to construct, but PX2 must still validate imported/synthetic graph
records explicitly.

## 8. Linear cycle admission

Cycle admission is intentionally separated from public topological ordering.

First pass:
- Kahn elimination with a FIFO queue;
- no heap;
- O(A + E).

If a remainder exists, every remaining node has a remaining local parent.
PX2 follows the first parent in each already-canonical parent tuple until a node
repeats, then converts the closed walk to parent->child direction and rotates it
to a canonical witness.

This reconstruction is iterative and does not depend on Python recursion depth.

The unit suite includes a 2,000-node cycle specifically to enforce that property.

## 9. Deterministic topological order

Only after the graph passes the linear cycle gate does PX2 compute the public
topological order.

Properties:
- every stored parent precedes every stored child;
- external/unresolved boundaries are not emitted as stored nodes;
- ties use lexicographic ArtifactId ordering;
- input node order cannot change the result.

A heap is used here deliberately for deterministic tie breaking.

Thus:
- cycle admission remains O(A+E);
- deterministic topological ordering has the additional ordering cost documented
  in the complexity audit.

## 10. Query surface

ArtifactLineageGraphV1 implements:

    parents(id)
    children(id)
    ancestors(id)
    descendants(id)
    roots()
    local_entrypoints()
    topological_order()
    explain_path(ancestor, descendant)
    status(id)

parents(id) returns the exact canonical parent tuple for stored artifacts.

children(id) is derived once from the canonical parent relation and returned in
lexicographic order.

ancestors/descendants return sorted deterministic ID tuples.

explain_path returns the deterministic shortest parent->child path. Breadth-first
search visits already-sorted children, so equal-length path selection is stable.

Unknown IDs fail explicitly with LineageUnknownArtifactError.

## 11. Traversal resource policy

LineageResourceLimitsV1 defaults:

    max_artifacts                 = 100,000
    max_edges                     = 1,000,000
    max_total_artifact_wire_bytes = 512 MiB
    max_traversal_nodes           = 100,000

A per-query max_nodes may tighten the traversal bound but cannot increase it
past the graph-level limit.

Ancestor, descendant and path search raise LineageResourceLimitError instead of
returning a silently truncated answer.

There is no implicit unbounded transitive-closure materialization.

## 12. Pre-materialization limits

The initial implementation draft converted arbitrary node/artifact iterables to
tuples before checking max_artifacts.

Adversarial review rejected that design because the supposed resource limit did
not bound input materialization.

Current implementation consumes the iterable incrementally and raises as soon as:

    len(nodes) > max_artifacts

Likewise external parent declarations are consumed under a bound derived from
max_edges.

## 13. Store snapshot consistency

PX2 does not build one lineage graph through multiple independent page/read
transactions.

LocalArtifactStoreV1 creates one metadata-consistent snapshot under:

    BEGIN IMMEDIATE

This blocks concurrent PX1 writers for the duration of snapshot validation.

Before row materialization:

    COUNT(artifacts)        <= max_artifacts
    COUNT(artifact_parents) <= max_edges

Each blob then contributes to:

    total artifact wire bytes <= max_total_artifact_wire_bytes

The implementation additionally checks that fetched row cardinalities still
match the counted cardinalities inside the same transaction.

This V1 design favors unambiguous semantics over maximum concurrent writer
throughput.

## 14. Memory refinement

The first store-snapshot draft retained every canonical wire and parsed the whole
set again in PX2.

That was removed.

The store now:
- reads one blob;
- validates it once;
- retains the resulting SigmaArtifactV1 object;
- releases the full payload before moving to the next artifact.

The wire-byte budget still accounts for all input bytes read, but PX2 no longer
keeps a second complete wire corpus in memory or performs a duplicate parse.

## 15. Independent differential oracle

reference/lineage_v1.py is stdlib-only and implements independently:

    roots
    topological_order
    ancestors
    descendants
    explain_path
    missing_parents

The PX2 gate compares runtime results against this oracle across randomized DAGs.

The oracle does not import sigma.artifact.lineage.

## 16. Closure-gate plan

scripts/product_closure/px2_gate.py freezes minimum campaigns:

    random DAGs                 300
    query cases               1,000
    boundary-policy cases       300
    cycle cases                 200
    local-store graph cases      80

The gate also checks:
- every runtime parent tuple equals the input identity projection;
- deterministic roots/topology;
- ancestor/descendant/path differential;
- STRICT missing-parent rejection;
- exact EXTERNAL declarations;
- UNRESOLVED preservation;
- deterministic cycle witnesses under permuted input;
- REJECT and REPORT cycle policies;
- store reconstruction from canonical artifacts;
- traversal resource rejection.

No gate-result hashes or pass counts are frozen here because the gate has not yet
been executed.

## 17. Obligation mapping

### PX2-O01 — graph reflects identity-bound parent IDs exactly

Implemented by:
- LineageNodeV1.from_artifact;
- store canonical-blob validation;
- parent index/canonical-wire equality check;
- runtime/oracle differential gate.

Status: IMPLEMENTED / GATE PENDING.

### PX2-O02 — cycles and cycle policy explicit

Implemented by:
- linear cycle admission;
- deterministic witness;
- REJECT;
- REPORT with graph=None.

Status: IMPLEMENTED / GATE PENDING.

### PX2-O03 — deterministic graph queries

Implemented for:
- parents;
- children;
- roots;
- local entrypoints;
- ancestors;
- descendants;
- topological order;
- explain_path.

Status: IMPLEMENTED / GATE PENDING.

### PX2-O04 — unresolved external parents explicit

Implemented by distinct STRICT / EXTERNAL / UNRESOLVED semantics and
LineageIdStatusV1.

Status: IMPLEMENTED / GATE PENDING.

## 18. Adversarial review findings

### AR-PX2-01 — SQL parent index could become a second authority

Resolution:
store snapshot parses canonical artifact bytes and requires index equality.

### AR-PX2-02 — ambiguous meaning of external versus unresolved

Resolution:
EXTERNAL requires exact explicit declarations; UNRESOLVED admits undeclared
missing boundaries without dropping them.

### AR-PX2-03 — incomplete mirror could create false roots

Resolution:
roots() and local_entrypoints() are distinct APIs.

### AR-PX2-04 — resource limit checked after input materialization

Resolution:
bounded incremental input consumption.

### AR-PX2-05 — recursive cycle witness can overflow Python recursion

Resolution:
iterative Kahn remainder walk.

### AR-PX2-06 — cycle detection and deterministic topology shared a heap cost

Resolution:
linear cycle admission and deterministic heap topology are separate phases.

### AR-PX2-07 — multi-transaction store scan could mix graph generations

Resolution:
one BEGIN IMMEDIATE snapshot spans cardinality checks, metadata and canonical
blob validation.

### AR-PX2-08 — duplicate wire retention during store snapshot

Resolution:
validated SigmaArtifactV1 objects are retained directly; full wires are not
retained as a second corpus.

All findings are resolved in implementation. Execution evidence remains pending.

## 19. Claim boundary

PX2 is not:
- a blockchain;
- a distributed consensus protocol;
- a transparency log;
- a causal graph inferred from data;
- proof that declared lineage is semantically truthful;
- authorization to trust an external parent.

PX2 proves only that the local lineage view faithfully projects the parent IDs
bound into accepted Sigma artifacts and applies explicit graph policies to that
relation.

Typed semantic edges remain a later extension; V1 edge meaning is simply:

    child ArtifactIdentityV1 names parent ArtifactId

## 20. Current disposition

Implementation: COMPLETE for the planned PX2 V1 scope.

Adversarial design review: PASS after remediation.

Independent oracle: IMPLEMENTED.

Unit/property-style coverage: IMPLEMENTED, NOT EXECUTED HERE.

Closure gate: IMPLEMENTED, NOT EXECUTED HERE.

Stage status:

    PX2 ACTIVE

Promotion to COMPLETE requires the real repository-native quality/gate run and
promotion of PX2-O01..O04.
