# PX1 — Resource Complexity Audit

Status: **IMPLEMENTATION CONTRACT FROZEN; EMPIRICAL LEDGER PENDING**

This audit applies the expansion invariant EXP-INV-007 before PX1 is allowed to
close.

## Parameters

    B_a  canonical SigmaArtifactV1 bytes handled by one operation
    B_m  canonical ManifestV1 bytes
    B_e  auxiliary evidence bytes
    B_i  PX0 persistent-index bytes
    A    stored artifacts
    E    stored parent edges
    M    stored manifests
    X    stored evidence attachments
    I    stored persistent Tree indexes
    d_p  parent count of one artifact
    d_c  number of local children of one ArtifactId
    R    number of declared GC roots
    U    total bytes of objects physically removed by GC

SQLite index costs below are stated as logarithmic lookup plus returned rows;
exact constants depend on the SQLite B-tree/page layout and local filesystem.

## put artifact

Canonical parse + ArtifactId validation:

    CPU  O(B_a)
    RAM  O(B_a)

Filesystem publication:

    I/O  O(B_a)
    temporary disk  O(B_a)

Metadata:

    O(log A + d_p log E)

The caller already supplies an in-memory bytes object or SigmaArtifactV1 wire.
PX1 does not make a second full persistent copy in Python beyond normal parser
objects and the temporary filesystem write.

Writer concurrency is serialized by SQLite BEGIN IMMEDIATE.

## get / verify stored artifact

Lookup:

    O(log A)

Read + canonical parse/recompute:

    CPU/I/O  O(B_a)
    RAM      O(B_a)

Parent metadata consistency:

    O(d_p + log E)

This is store-integrity verification, not source re-evaluation under SA1.

## has

    O(log A)

plus one filesystem existence check.

It intentionally does not parse/hash the artifact payload.

## list

Keyset page:

    O(log A + L)

where:

    1 <= L <= 10,000

There is no unbounded list-all result allocation.

## parents / children

Parents:

    O(log E + d_p)

Children:

    O(log E + d_c)

The parent index is materialized in SQLite. PX2 may add bounded transitive
queries; PX1 does not.

## manifest put/get

    CPU/I/O/RAM  O(B_m)
    metadata     O(log M)

ManifestId is recomputed before publication.

## evidence attachment

Internal evidence-key derivation and write:

    CPU/I/O  O(B_e)
    RAM      O(B_e)
    metadata O(log X)

Evidence size is caller-controlled in PX1. There is no empirical claim that very
large evidence payloads are cheap; future streaming evidence ingestion may be
added without changing ArtifactId.

## persistent Tree index cache

PX1 normalizes away TreeSourceHintV1 and serializes the PX0 node set.

    CPU/RAM/I/O  O(B_i)

PX0 already establishes that its canonical node count is O(N) in Tree leaves.

This cache is derived and may be discarded by GC.

## garbage collection

Before graph materialization PX1 executes scalar COUNT(*) checks and rejects if:

    A > 100,000
    E > 1,000,000
    M + X + I > 1,000,000

unless the caller deliberately supplies different explicit limits.

After admission:

    graph traversal CPU  O(A + E)
    graph RAM            O(A + E)
    auxiliary scan       O(M + X + I)
    physical unlink I/O  O(number of removed files)
    reclaimed bytes      U

No reachable artifact payload is rehashed merely to decide graph reachability.
Reachability uses the already identity-bound parent metadata and cross-checks
artifact bytes on ordinary get/verification paths.

GC preserves parents reachable from roots. It does not compute arbitrary PX2
descendant/ancestor products.

## Crash behaviour and write amplification

Artifact publication writes the payload once to a same-directory temporary file,
then atomically renames it.

Worst normal artifact payload write volume is therefore approximately:

    O(B_a)

plus filesystem/journal metadata.

SQLite WAL/synchronous FULL adds metadata write amplification that is deliberately
not assigned a universal byte multiplier. That multiplier is filesystem, SQLite
page-size and workload dependent and belongs in the empirical ledger.

A crash after rename but before SQLite commit can temporarily consume an extra:

    O(B_a)

as an invisible orphan. An identical later put adopts it.

## Concurrency

Correctness model:
- many readers;
- serialized metadata writers;
- one filesystem store shared by SQLite-coordinated processes.

PX1 does not claim lock-free or linearly scalable write throughput.

Large object publication currently occurs while the writer transaction is held.
This favors simple crash semantics over maximum concurrent ingestion. If
empirical profiling shows that this is a bottleneck, a future staged-intent
protocol may reduce lock duration without changing the CAS identity boundary.

## Storage growth

Logical payload storage:

    O(sum artifact bytes
      + sum manifest bytes
      + sum evidence bytes
      + sum cached PX0 index bytes)

Metadata:

    O(A + E + M + X + I)

Directory sharding keeps artifact/manifest/index leaf directories from containing
all IDs in one directory.

## Resource-closure verdict

PX1 adds no hidden exponential enumeration.

Potentially global work is isolated to garbage collection and is:
- explicitly O(A+E+M+X+I);
- fail-closed behind pre-materialization cardinality limits;
- user-triggered rather than performed implicitly by put/get.

The next required evidence is empirical, not asymptotic:
- throughput/latency across representative artifact sizes;
- SQLite writer contention;
- WAL/database growth;
- orphan recovery;
- GC wall time and peak RSS near configured bounds.

Those measurements must be recorded only after local execution; none are invented
in this implementation document.
