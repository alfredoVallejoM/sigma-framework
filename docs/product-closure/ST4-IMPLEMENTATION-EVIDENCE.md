# ST4 — Delta / Append Implementation Evidence

Status: **ADVERSARIAL REVIEW PASSED — READY FOR COMPLETE**  
Reviewed implementation baseline: `b936aa412f269e596a28b93d8777554724d2e17a`  
ST3 baseline: `9c53b1b19f91160c0682356465758451e323bc74`  
Date: 2026-09-22

## 1. Scope

ST4 adds two incremental operations over frozen Sigma Tree V1 semantics:

- same-length replacement;
- append.

Implemented:
- `sigma/tree/delta.py`;
- `reference/tree_delta_v1.py`;
- `scripts/product_closure/st4_gate.py`;
- `scripts/product_closure/st4_benchmark.py`;
- `scripts/product_closure/generate_st4_vectors.py`;
- frozen ST4 vectors;
- unit/property/differential/vector tests.

No ST0/ST2/ST3 wire or cryptographic function is modified.

## 2. Incremental index

`TreeDeltaIndex` is ephemeral and in-memory.

Initial construction:
- materializes leaf bytes;
- computes leaf nodes;
- caches canonical subtrees;
- stores current TreeRoot.

Index construction is O(mB) and is excluded from per-update incremental claims.

Persistent serialization/layout is explicitly deferred to ST5/SA3.

## 3. Same-length replacement

Supported edit condition:

    delete_length == len(data)

Otherwise:

    RebuildRequired

No interior insertion/deletion is silently processed incrementally.

Edits are normalized independently of input ordering:
- sort;
- validate bounds;
- merge adjacent intervals;
- merge overlapping intervals only if overlap bytes agree;
- reject conflicting overlaps.

During review, an accidental O(k^2) pattern was found: every affected leaf was
initially compared against every normalized edit.

Remediation:
- normalized edits are partitioned to leaves in one pass;
- each affected leaf sees only its local segments.

This restores the intended cost model.

## 4. Exact dependency closure

For affected leaves A, ST4 computes the exact canonical ancestor closure Anc(A)
using ST0's largest-power split geometry.

The update recomputes exactly:

    A union Anc_internal(A)

and reuses every disjoint canonical subtree.

The independent reference implementation separately computes:
- affected leaves;
- ancestor closure;
- full-rebuild expected root.

Differential evidence reports zero root/closure divergence.

## 5. Transactionality

All leaf hashing and internal recomposition happen before publication.

The final commit maintains a rollback journal for:
- touched leaf bytes;
- touched leaf nodes;
- invalidated/recomputed node cache entries;
- root;
- byte length for append.

Two failure classes are tested:

1. failure during combine before publication;
2. failure inside cache publication after state mutation has begun.

Both delta and append restore the complete prior state.

Scope:
- this is in-memory transactionality of TreeDeltaIndex;
- persistent on-disk index transactionality is not claimed in ST4.

## 6. Append

Append reuses previous full-prefix subtrees.

If old data ends on a chunk boundary:
- no old leaf is rehashed.

If old data has a partial tail:
- only that old tail leaf may be rehashed.

A prior cached node is reused only when:
1. its key existed;
2. the key was canonical in the immediately previous whole-tree geometry;
3. its interval is fully inside the unchanged full-leaf prefix.

This prevents accidental reuse of stale historical geometry after repeated
append/delta cycles.

## 7. Correctness execution

An isolated ST0/ST4 semantic mirror using the exact ST0 framing/hash rules was
executed because the active environment cannot resolve github.com for a checkout.

Main cumulative campaign:

- delta cases: **5,000**
- append cases: **1,000**
- fresh independent differential cases: **500**

Sampled direct rebuilds were performed throughout cumulative delta/append runs.

Observed:
- maximum recomputed nodes for small random deltas: **12**
- maximum rehashed leaf payload for small deltas: **131,072 bytes**
- append frontier reuse events: **3,496**
- one-leaf locality tree: **128 leaves**
- one-leaf recomputed nodes: **8**
- one-leaf payload rehashed: **65,536 bytes**
- unaffected 64-leaf subtree preserved by object identity

Execution streams:

delta:

    2c039f135ba2667166aaf4575d698e2436f50f1dcaa4ac9224de146a685fa511

append:

    4bdf145f39d4dd0fa31a6ae00b63fd7a8f43a8c9c68f97d7c793000981a02c20

independent differential:

    a284023f7d3d083b7078cb2e94eabd15e48e18517e8b3868823734bb2d108b61

No semantic divergence was found.

## 8. Frozen ST4 vectors

Corpus:

    specification/test-vectors/sigma-tree-v1-st4.json

SHA-256:

    ed94e768dd52c71039b938eec9eafdd8330465a974b4636c3a2a975129178999

Cases:
- one-byte delta;
- cross-chunk delta;
- consistent overlap normalization;
- full-file same-length replacement;
- append onto short tail;
- append chunk + tail.

The vector generator compares product roots to the independent full-rebuild
reference before rendering.

## 9. Performance / resource evidence

Large local sweep:

    N = 1,000 leaves
    B = 65,536,000 bytes

so one leaf is exactly 0.1%.

Observed with ST0-exact hashing and rollback-journal overhead modelled:

| regime | affected leaves | payload rehashed | recomputed nodes | speedup vs rebuild |
|---|---:|---:|---:|---:|
| one leaf | 1 | 65,536 | 11 | ~342x |
| 0.1% | 1 | 65,536 | 11 | ~369x |
| 1% | 10 | 655,360 | 85 | ~49x |
| 10% | 100 | 6,553,600 | 524 | ~6.0x |
| 100% | 1,000 | 65,536,000 | 1,999 | ~0.71x |

Approximate per-update Python allocation peaks in that run:

- 1 leaf: ~0.27 MiB
- 1%: ~0.84 MiB
- 10%: ~6.8 MiB
- 100%: ~64.7 MiB

The 100% slowdown is retained as a valid negative result.

Append engineering sweep on the same large state:

| suffix | reused frontier nodes | speedup vs rebuild |
|---|---:|---:|
| 1 byte | 6 | ~2,224x |
| 1 chunk | 6 | ~757x |
| 4 chunks + 17 bytes | 7 | ~187x |

These are local engineering measurements, not cross-host publication claims.

## 10. Complexity contract

After index construction:

    T_delta =
      O(B_delta
        + affected_leaf_payload
        + m |Anc(A)|)

with conservative upper bound:

    O(B_delta + m k log N)

for k affected leaves.

Append:

    O(old_tail + appended_bytes + m * bridge_nodes)

with no O(B_old) prefix-rehash term.

## 11. Obligation review

### ST4-O01 — Delta equals full rebuild

PASS.

Random/deterministic differential tests and frozen vectors reproduce the exact
full-rebuild TreeRoot.

### ST4-O02 — All affected leaves recomputed

PASS.

Affected leaves are derived from the normalized edit intervals and every such
leaf appears in recomputed node telemetry.

### ST4-O03 — Unaffected subtrees preserved

PASS.

Disjoint canonical subtrees are returned from cache without hashing; tests
preserve an unaffected subtree by object identity.

### ST4-O04 — Ancestor invalidation exact

PASS.

Product invalidated/recomputed keys equal independent ancestor closure.

### ST4-O05 — Overlapping ranges normalized canonically

PASS.

Permutation invariance is tested. Compatible overlaps merge; conflicts reject.

### ST4-O06 — Transactionality

PASS.

Failure injection before commit and during partially-started publication restores
old bytes/cache/root for both delta and append.

### ST4-O07 — Boundary-shifting edits request rebuild

PASS.

Any delete/insert length mismatch raises RebuildRequired before incremental work.

### ST4-O08 — Append equals full rebuild

PASS.

Empty, byte, chunk, multi-chunk, tail and randomized append cases agree exactly.

### ST4-O09 — Append reuses previous frontier/subtrees

PASS.

Telemetry demonstrates prior canonical full-prefix node reuse; local append cost
tracks tail+suffix/bridge work rather than B_old.

## 12. Adversarial findings

Finding A — fragmented edit O(k^2) accidental cost  
Status: **FIXED**

Finding B — transactionality initially relied on all commit assignments succeeding  
Status: **FIXED** with rollback journals

Finding C — misleading expectation that incremental must win at 100%  
Status: **RESOLVED BY CONTRACT**; 100% slowdown is documented

Finding D — temptation to serialize a persistent index inside ST4  
Status: **REJECTED BY SCOPE**; persistent layout belongs to ST5/SA3

No unresolved blocking ST4 finding remains.

## 13. Isolation review

Diff from ST3 baseline contains:
- new delta module;
- independent delta oracle;
- ST4 gate/benchmark/vector generator;
- ST4 tests/vectors;
- additive API exports;
- ST4 docs/ledgers.

Not modified:
- `sigma/tree/core.py`;
- `sigma/tree/model.py`;
- `sigma/tree/proofs.py`;
- `sigma/tree/checkpoint.py`;
- Sigma v3/IAP sources;
- R15 sources/design.

Therefore ST4 does not alter prior TreeRoot/proof/checkpoint semantics.

## 14. Execution limitation

The active environment still lacks a complete Git checkout because outbound DNS
to github.com is unavailable.

Therefore this stage does not claim full-repository pytest/ruff/mypy or clean-wheel
execution; those remain REL2 concerns.

ST4 closure evidence instead consists of:
- branch-source review;
- exact ST0 hashing/framing semantic mirror;
- independent full-rebuild reference;
- cumulative/differential campaigns;
- performance/work ledgers;
- frozen vectors;
- adversarial review.

## 15. Disposition

Adversarial review:

    PASS

ST4-O01..O09 may be marked COMPLETE.

ST5 remains a separate PLANNED optimization/scale stage.
