# PX0 — Persistent Tree Index Implementation Evidence

Status: **COMPLETE — PERSISTENT/EPHEMERAL DIFFERENTIAL + CORRUPTION/STALE/ATOMIC GATES PASSED**  
Executed baseline: `bcb1a0d19a0104d14b898425a81c86467ae46c2e`  
GitHub Actions run: `35799646274`  
Date: 2026-09-23

## 1. Scope

PX0 persists the derived Sigma Tree summary geometry needed by repeated proof and
incremental-update workflows.

Product additions:

- `sigma/tree/persistent.py`;
- additive `TreeDeltaIndex.from_precomputed_state`;
- additive exports in `sigma.tree`;
- `PERSISTENT_TREE_INDEX_FORMAT_VERSION = 1`.

Independent oracle:

- `reference/persistent_tree_index_v1.py`.

Tests/gates:

- `tests/unit/test_persistent_tree_index_px0.py`;
- `tests/differential/test_persistent_tree_index_reference_px0.py`;
- `scripts/product_closure/px0_gate.py`;
- `scripts/product_closure/px0_benchmark.py`.

PX0 does not change TreeRoot V1 or ArtifactId V1.

## 2. Sidecar format

Magic:

    SIGTIDX1

Independent format version:

    1

Canonical payload:

    magic
    format_version
    TreeProfileV1 wire
    TreeRoot wire
    optional TreeSourceHintV1 wire
    node_count
    canonical TreeNode wires sorted by (start_leaf, leaf_count)
    corruption checksum

Checksum:

    SHA256(
      "SIGMA-PERSISTENT-TREE-INDEX-V1\0"
      || payload_without_checksum
    ).

The checksum detects accidental/casual sidecar corruption. It is not a signature,
MAC, source identity, or authenticity claim.

## 3. Canonical node set

For a non-empty Tree with N leaves, PX0 persists exactly:

    2*N - 1

canonical recursive TreeNode summaries.

For empty Tree:

    nodes = ().

The parser requires:
- exact canonical node-key coverage;
- sorted unique keys;
- canonical leaf geometry;
- every internal node to recompute exactly from its children;
- the canonical root node to reproduce the stored TreeRoot.

A node mutation with a freshly recomputed sidecar checksum therefore still fails
structural validation.

## 4. Source trust boundary

TreeSourceHintV1 remains operational metadata only.

Executed report freezes:

    source_hint_security_evidence = false.

Binding modes:

### FULL

    index.bind_source(data, validation=FULL)

performs:

    build_tree(data) == index.root

before returning a trusted source session.

This is O(B) once per bound source snapshot.

### LENGTH_ONLY

Only byte length is checked.

The returned session has:

    source_verified = false

and cannot perform trusted:
- range proof generation;
- delta;
- append.

Those operations raise PersistentIndexSourceUnverified until full verification
succeeds.

Therefore PX0 never upgrades a filesystem/stat hint into cryptographic evidence.

## 5. Detached operations

Inclusion proof generation needs only:
- TreeRoot;
- sibling TreeNode summaries.

Therefore:

    TreePersistentIndexV1.prove_leaf(...)

is source-independent and can operate detached from the original bytes.

The proof remains a proof under the indexed TreeRoot, not a statement about an
unverified current filesystem object.

## 6. Source-dependent range proofs

RangeProof V1 requires exact first/last edge complements from source bytes.

Therefore range generation is available only on a FULL-bound source session.

Executed differential corpus requires:

    persistent range proof wire
      ==
    TreeProofIndex range proof wire.

## 7. Delta/append reuse

PX0 adds an additive ST4 constructor:

    TreeDeltaIndex.from_precomputed_state(...)

It restores:
- current TreeRoot;
- leaf summaries;
- canonical subtree summaries;

without rehashing unchanged leaves/internal nodes.

The bound persistent session then delegates update semantics to the existing ST4
TreeDeltaIndex.

After update:
- materialized bytes come from ST4;
- canonical updated TreeRoot is preserved;
- a fresh persistent index is derived from the updated ST4 summary state.

No second incremental algorithm is introduced.

## 8. Atomic persistence

API:

    write_persistent_index_atomic(path,index)

uses:
1. same-directory temporary file;
2. write + flush + fsync;
3. os.replace;
4. best-effort directory fsync;
5. temporary cleanup.

Failure injection before replace preserves the previous sidecar byte-for-byte.

Executed gate:

    atomic_publication_failure_preserves_old_index = true.

## 9. mmap reader

API:

    read_persistent_index(path,use_mmap=True)

hashes the mapped buffer directly instead of first materializing the entire raw
sidecar bytes object.

Product semantics are identical to normal reads:

    mmap_parity = true.

Current V1 parser still materializes Python TreeNode objects for the canonical
node set. PX0 does not claim zero-copy node objects or full demand-paged query
execution.

## 10. Identity boundary

The sidecar is a derived cache.

It is absent from:
- TreeRoot;
- SigmaArtifactV1 identity;
- ArtifactId;
- ManifestId.

Executed gate:

    artifact_identity_cases = 500
    persistent_index_part_of_tree_or_artifact_identity = false.

Every case reproduced byte-identical SigmaArtifactV1 identity/wire before and
after index construction.

## 11. Independent sidecar oracle

`reference/persistent_tree_index_v1.py` is stdlib-only and imports only the
independent ST0 Tree reference.

It independently derives:
- canonical leaf/internal nodes;
- TreeRoot wire;
- sidecar framing;
- corruption checksum.

Executed:

    index_differential_cases = 500
    zero divergence.

Frozen wire stream:

    f4ce101f5e633c1f129afa7c442523dd79cfb815533ddedb0b4c661d1da8edf8

## 12. Proof differential

Executed:

    proof_differential_cases = 500.

Each case compares:
- detached inclusion;
- FULL-bound range proof

against TreeProofIndex.

Frozen proof stream:

    8d2b71dbf4fa57b866f508581c8677ef4eb4cdd85f587c2e4d8ac045f44f2484

## 13. Delta differential

Executed:

    delta_differential_cases = 300.

Each case requires equality with:
- TreeDeltaIndex;
- materialized ST4 bytes;
- full Tree rebuild;
- independent regenerated persistent sidecar.

Frozen delta stream:

    e9649db9d4cf47f6ea5072bf1d7958e66487d4e2997a13d70ccfd979caeb9eec

## 14. Append differential

Executed:

    append_differential_cases = 300.

Each case requires equality with:
- TreeDeltaIndex append;
- full Tree rebuild;
- independent persistent sidecar oracle.

Frozen append stream:

    2516166643f37ed27363aa0db913da5ff69220122391e7c7a48de2dc6a1922ce

## 15. Corruption/stale-source campaign

Checksum corruption:

    mutations = 5,000
    rejected = 5,000.

Structural node corruption with checksum recomputed:

    200
    rejected = 200.

Same-length source mutation under FULL binding:

    stale_source_cases = 200
    rejected = 200.

Thus checksum and structural validation protect different failure classes.

## 16. Runtime quality result

GitHub Actions run:

    35799646274

Result:

    compile PASS
    Ruff PASS
    Mypy PASS
    pytest 110 passed
    PX0 gate PASS
    PX0 benchmark PASS.

The regression suite includes ST2 proofs, ST4 delta, ST5 scale and SA0 artifact
identity tests.

The run also exposed a pre-existing ST5 facade defect:
`prove_leaf_streaming` / `prove_range_streaming` were implemented but not
exported from `sigma.tree`. PX0 fixed the public facade additively; ST5
semantics were unchanged.

## 17. Frozen gate report

File:

    PX0-GATE-REPORT.json

SHA-256:

    594816f55c16d4cec283a880452ab8f427ad827161aec765b9c18dc158725d0c

Result:

    passed = true
    closure_eligible = true.

## 18. Resource ledger

File:

    PX0-PERFORMANCE-LEDGER.json

SHA-256:

    1e912460ce7d2399999dbdbd16fb175c4fa66007eea477c2fda9041aa5e486bf

Largest executed row:

    source             = 32 MiB
    leaves             = 512
    canonical nodes    = 1,023
    sidecar            = 358,536 bytes
    sidecar/source     = 1.0685%
    sidecar/leaf       = 700.27 bytes

Asymptotically observed sidecar density converges near:

    ~700 bytes / 64 KiB leaf
    ~1.07% of source bytes.

This number is format/profile-specific and EMPIRICAL-PERFORMANCE evidence.

## 19. Complexity contract

Index construction:

    O(B).

Persistent storage:

    O(N * TreeNodeSummary).

Structural decode validation:

    O(N)

internal-node composition work.

Detached inclusion generation:

    O(log N).

Trusted source binding:

    O(B)

full Tree validation once per source snapshot.

Subsequent delta/append:

    existing ST4 local-update semantics

after precomputed-state restoration.

## 20. mmap/resource interpretation

At 512 leaves / 32 MiB:

normal decode:
- ~303.8 ms local;
- ~1.09 MiB tracemalloc peak.

mmap decode:
- ~301.1 ms local;
- ~0.79 MiB tracemalloc peak.

This supports semantic/memory usefulness of the mmap path but is not a universal
performance guarantee.

The parser still materializes all TreeNode objects. A future packed/native index
can reduce this further without changing PX0 format/identity contracts if it
preserves canonical semantics.

## 21. Obligation disposition

### PX0-O01 — Persistent index never changes TreeRoot or ArtifactId

**PASS.**

500 independent build/identity cases, zero divergence.

### PX0-O02 — Persistent proof/delta/append equals existing references

**PASS.**

500 proof + 300 delta + 300 append differential cases, zero divergence.

### PX0-O03 — Stale/corrupt sidecar detected before trusted use

**PASS.**

5,000 checksum mutations + 200 structural corruptions + 200 stale sources all
rejected in their corresponding trust path.

### PX0-O04 — Atomic/resource-bounded index publication

**PASS.**

Atomic failure injection preserves old sidecar; parser node/sidecar limits,
normal/mmap parity and scale ledger are frozen.

## 22. Known V1 boundaries

PX0 intentionally does not yet provide:
- a file-backed transactional delta that edits source + sidecar atomically;
- OS/filesystem generation-number authentication;
- authenticated source hints;
- packed zero-copy native TreeNode views;
- remote sidecar storage;
- sidecar participation in Artifact identity.

Those belong to PX1/PX3/NR0 rather than weakening PX0 boundaries.

## 23. Final disposition

Independent sidecar oracle:

    PASS

Proof/delta/append differential:

    PASS

Corruption/stale-source gates:

    PASS

Atomic persistence:

    PASS

Resource ledger:

    PASS

Manual post-execution review:

    PASS

Final status:

    PX0 COMPLETE
