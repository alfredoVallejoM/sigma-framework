# PX2 — Resource Complexity Audit

Status: **IMPLEMENTATION CONTRACT FROZEN; EMPIRICAL GATE PENDING**  
Date: 2026-09-24

PX2 must not turn lineage convenience into hidden transitive-closure or graph
enumeration costs.

## 1. Parameters

    A  number of stored/local artifacts in one snapshot
    E  total identity-bound parent edges from those artifacts
    U  unique external/unresolved boundary parent IDs
    B  total canonical artifact wire bytes read when building from PX1
    d_p parent degree of one artifact
    d_c local child degree of one ID
    V_q nodes visited by one transitive query
    E_q edges inspected by one transitive query
    L_q number of IDs returned by one transitive query

Default admission bounds:

    A <= 100,000
    E <= 1,000,000
    B <= 512 MiB
    V_q <= 100,000

Callers may lower these values.

## 2. Direct graph build

Input is consumed incrementally.

Artifact/node admission:

    O(A)

Parent-edge accounting:

    O(E)

Memory after admission:

    O(A + E + U)

The implementation raises while consuming as soon as A or E exceeds policy.
It does not first materialize an unbounded iterable.

## 3. Boundary resolution

Missing-parent discovery:

    O(A + E)

using a hash set of stored IDs.

STRICT:
- O(U) report construction in the failure case.

EXTERNAL:
- O(U) set comparison against explicit declarations.

UNRESOLVED:
- O(U) partition into declared-external and unresolved.

External declarations are themselves bounded by max_edges before full
materialization.

## 4. Cycle admission

PX2 cycle admission uses Kahn elimination with a FIFO queue.

Time:

    O(A + E)

Auxiliary memory:

    O(A + E)

If a cycle remains, deterministic witness reconstruction:
- choose minimum ID in the remainder: O(A);
- follow one remaining canonical parent per visited node: O(A + E) worst case;
- canonical rotate the discovered cycle.

The walk is iterative.

No recursion depth grows with A.

## 5. Deterministic topological order

Topological order is computed only after linear cycle admission succeeds.

A heap provides stable lexicographic tie breaking.

Time:

    O((A + E) log A)

as a conservative bound.

Memory:

    O(A + E)

This logarithmic ordering cost is deliberately not misreported as part of the
linear cycle-detection obligation.

## 6. Reverse child index

The graph materializes parent -> children adjacency once.

Construction:
- scan E edges;
- sort child lists for deterministic query/path behavior.

Conservative time:

    O(E + sum d_c log d_c)

Memory:

    O(E)

This is paid once during accepted graph construction.

## 7. Direct queries

parents(id):

    lookup O(1) average
    output O(d_p)

children(id):

    lookup O(1) average
    output O(d_c)

status(id):

    O(1) average

roots():

    O(A log A)

in the current implementation because stored IDs are returned in canonical
lexicographic order.

local_entrypoints():

    O(A log A + E)

in the current implementation.

topological_order():

    O(A)

to return/reference the already materialized immutable tuple; topology itself was
paid during graph build.

## 8. Ancestors / descendants

No global transitive closure is precomputed.

For one query:

    time O(V_q + E_q + L_q log L_q)
    memory O(V_q)

The final sort provides deterministic return order.

If visited nodes exceed max_traversal_nodes or the tighter per-query max_nodes,
the query raises LineageResourceLimitError.

No partial/truncated result is returned.

## 9. explain_path

Breadth-first search over already-sorted child adjacency.

Worst bounded query:

    time O(V_q + E_q)
    memory O(V_q)

The first path discovered is:
- shortest in edge count;
- deterministic under canonical child ordering.

No all-path enumeration occurs.

## 10. Store-backed snapshot build

PX2 asks PX1 for one canonical snapshot under BEGIN IMMEDIATE.

Before row materialization:

    COUNT(artifacts) <= A_limit
    COUNT(parent edges) <= E_limit

Then each canonical artifact blob is read and parsed exactly once.

Time:

    O(B + A + E)

excluding filesystem/SQLite constant factors.

Peak retained graph/object memory:

    O(A + E + parsed artifact state)

The complete B-byte wire corpus is not retained.

Each individual payload exists transiently while it is validated.

## 11. Writer concurrency cost

BEGIN IMMEDIATE prevents concurrent PX1 writers during the store-backed snapshot.

This makes snapshot semantics unambiguous but can increase write latency for
large B/A snapshots.

PX2 V1 therefore claims correctness, not scalable concurrent snapshot throughput.

Potential future optimization:
- store generation number;
- copy-on-write metadata snapshot;
- read-only generation pinning.

Any optimization must preserve the exact identity-parent semantics and cannot
silently weaken snapshot consistency.

## 12. Parent-index integrity check

PX1 captures:
- artifact metadata rows;
- parent index rows;
- canonical artifact blobs

inside the same writer-blocking snapshot.

Each artifact compares:

    SQLite indexed parents
      ==
    SigmaArtifactV1.parent_artifact_ids

This is O(E) aggregate.

The comparison prevents a fast mutable index from becoming an alternative
lineage authority.

## 13. Long-cycle behavior

Cycle witness construction is iterative.

For a cycle of length C:

    time O(C)
    witness memory O(C)

subject to the global A/E bounds.

The unit suite includes C=2,000 specifically to guard against reintroducing
recursive DFS.

## 14. No hidden expensive layers

PX2 does not:
- enumerate all paths;
- enumerate all ancestor/descendant pairs;
- precompute transitive closure;
- perform graph isomorphism;
- solve maximum-flow/min-cut;
- infer typed/semantic lineage;
- duplicate artifact payload storage.

The only whole-graph phases are:
- snapshot validation;
- boundary classification;
- cycle admission;
- deterministic topology;
- adjacency construction.

## 15. Complexity closure

Structural targets:

    cycle admission                O(A + E)
    accepted graph storage         O(A + E + U)
    direct parent/child query      O(degree)
    bounded transitive traversal   O(V_q + E_q)
    explain shortest path          O(V_q + E_q)

Deterministic ordering costs are accounted separately and explicitly.

No empirical latency/throughput values are asserted until the PX2 gate and
benchmarking are executed on the real checkout.
