# ST3 — Portable Tree Resume Evidence

Status: **ADVERSARIAL REVIEW PASSED — READY FOR COMPLETE**  
Reviewed implementation baseline: `1daf625d2d44b8ac23f1ddb069e37be15ce912af`  
ST2 baseline: `360ea2bad8916228da012225aed00e4275dd0ea7`  
Date: 2026-09-22

## 1. Scope

ST3 adds portable checkpoint/resume to the frozen Sigma Tree V1 construction.

Implemented:

- `sigma/tree/checkpoint.py`
- additive `TreeBuilder.checkpoint_state()`
- additive `TreeBuilder.from_checkpoint_state()`
- `reference/tree_checkpoint_v1.py`
- `scripts/product_closure/st3_gate.py`
- `scripts/product_closure/st3_benchmark.py`
- `scripts/product_closure/generate_st3_vectors.py`
- `specification/test-vectors/sigma-tree-v1-st3.json`
- unit/property/differential/vector tests
- provisional `sigma checkpoint-tree` / `sigma resume-tree` CLI

No hashlib object/state is serialized.

The checkpoint contains only:

    profile
    completed byte/leaf counters
    canonical full-leaf frontier
    raw tail < 65,536 bytes
    optional operational source hint

## 2. Canonical checkpoint law

For a builder that has consumed prefix P:

    checkpoint(P).frontier.byte_length
      = checkpoint(P).completed_leaf_count * 65,536

and:

    checkpoint(P).completed_bytes
      = checkpoint(P).frontier.byte_length
        + len(checkpoint(P).tail)

with:

    0 <= len(tail) < 65,536.

The checkpoint frontier is stricter than a general ST0 TreeFrontier: every
checkpoint frontier node must be byte-full.

A rightmost short TreeNode may be valid in a finalized ST0 frontier/root context,
but is rejected as resumable checkpoint state.

## 3. Resume law

For every covered split:

    X = P || S

the required law is:

    resume_tree(checkpoint(P), S)
      = build_tree(X)

byte-for-byte at TreeRoot V1 wire level.

The same law is stable under repeated cycles:

    checkpoint
      -> restore
      -> update
      -> checkpoint
      -> restore
      -> ...

No prefix bytes are needed again after the checkpoint has been created.

## 4. Independent oracle

`reference/tree_checkpoint_v1.py` imports no code from `sigma`.

It independently:

- parses the checkpoint TLV record;
- parses and validates the canonical full-leaf frontier;
- validates completed byte/leaf counters;
- validates tail bounds;
- parses source hints but does not treat them as evidence;
- continues binary frontier carries;
- hashes only newly completed/final tail leaves;
- reconstructs the final root wire.

Product and reference checkpoint wires are required to be byte-identical when
the optional source hint is absent.

## 5. Closure-scale execution

The ST3 closure logic was executed on an isolated exact-wire ST0+ST3 mirror.

Main campaign:

- random split/resume cases: **100,000**
- directed boundary splits: **13**
- independent differential cases: **500**
- repeated checkpoint/restore cycles: **1,000**
- checkpoint bit mutations: **20,000**
- structural top-level TLV mutations: **14**

Result:

    PASS

Mutation disposition:

- malformed/rejected: **8,503**
- accepted but reconstructing a different root: **11,497**
- altered semantic checkpoint still reconstructing original root: **0**

Execution time for the full logical closure campaign:

    ~15.85 s

Campaign hashes:

split stream:

    c2c4a71ef974e409e2c152adb5981bb509ebe4a33244bfe9b0875aa117b25787

independent differential stream:

    5bc96789df2b68d77d2ad6cfe3aae7daa29ecdb247ebe0c32ba9407c87831f38

repeated-cycle stream:

    640780401d57d755f5618008397448117a2beed6ce45fb1277b3bfed054815c4

mutation stream:

    5314999f5cf6ba3b6d4fc7a2d01cf07e98bfa1ca2ef467683985305022d46674

expected direct TreeRoot wire SHA-256:

    0fc0697e078c61df690bddec3a8e5bd01085c52bb1d46815d803745df38d42bc

## 6. Why the 100k split campaign is not artificial rehash work

The campaign object is:

    4 full chunks + 4 KiB final tail.

The 100,000 random split points are sampled inside that final 4 KiB band.

Therefore every case:

- restores a non-empty/non-trivial frontier;
- has completed_leaf_count = 4;
- varies the exact raw tail split;
- hashes the complete final partial leaf after continuation;
- checks the final root against the same frozen direct root.

Thirteen additional directed offsets cover:

- empty prefix;
- one byte;
- chunk-1;
- exact chunk;
- chunk+1;
- second/third/fourth chunk boundaries;
- final byte;
- full input.

No closure threshold was reduced.

## 7. Transactional persistence evidence

Persistence algorithm:

1. serialize checkpoint;
2. create a temporary file in the destination directory;
3. write full payload;
4. flush + fsync temporary;
5. atomic `os.replace`;
6. attempt directory fsync;
7. remove residual temporary file.

Failure injection replaces `os.replace` with an exception.

Observed invariant:

    old checkpoint before failed write
      == checkpoint after failed write

and:

    leaked temporary files = 0.

This claim is scoped to failure before successful replace. It is not presented
as a universal filesystem/power-loss durability theorem across all filesystems.

## 8. Source hint boundary

`TreeSourceHintV1` stores:

- size;
- mtime_ns;
- inode;
- device.

It is an operational heuristic only.

The campaign explicitly constructs two checkpoints with identical structural
state and different hints and verifies:

    resume(checkpoint_hint_A, suffix)
      == resume(checkpoint_hint_B, suffix).

Therefore source hints do not influence TreeRoot semantics.

The CLI exposes:

    source_hint_match
    source_hint_security_evidence = false

and `--require-hint-match` is only a defensive UX option.

A matching hint is never claimed to prove current-prefix equality.

## 9. KAT freeze

Corpus:

    specification/test-vectors/sigma-tree-v1-st3.json

Corpus SHA-256:

    c46ad683e2c295aa251873c3de6b08eff8b78055f7bf3e5d80a4b308b9499e62

Cases:

1. empty checkpoint resumed with `abc`;
2. one-byte prefix;
3. exact 65,536-byte boundary;
4. one full chunk + 19-byte tail;
5. three full chunks + 123-byte tail.

Each case freezes:

- prefix/suffix hashes;
- completed leaf count;
- frontier node count;
- tail length;
- checkpoint wire length/hash;
- final resumed root wire hash.

The generator requires product checkpoint wire == independent checkpoint wire
and product resume root == independent resume root before rendering the corpus.

## 10. Complexity evidence

Restore never rehashes the completed prefix.

Let:

- N = completed leaf count;
- m = 4 branches;
- f = number of frontier nodes;
- t = tail length.

Then:

    f <= O(log N)
    t < 65,536

and:

    checkpoint wire = O(m f + t)
    decode          = O(m f + t)
    restore         = O(m f + t).

Synthetic canonical-frontier sweep:

    f = 1,2,4,8,16,24,32,40.

Observed checkpoint wire sizes:

| frontier nodes | wire bytes |
|---:|---:|
| 1 | 663 |
| 2 | 1,013 |
| 4 | 1,713 |
| 8 | 3,113 |
| 16 | 5,913 |
| 24 | 8,713 |
| 32 | 11,513 |
| 40 | 14,313 |

Exact wire growth:

    350 bytes / frontier node

plus fixed checkpoint/profile/tail overhead.

This is consistent with O(m log N + tail). Because tail is bounded by the fixed
V1 chunk size, restore is O(m log N) as a function of tree size.

## 11. Adversarial obligation review

### ST3-O01 — Resume equals direct build

PASS.

100,000 random split/resume cases, 13 directed boundary cases, independent
differential corpus and repeated cycles reconstruct the exact direct root.

### ST3-O02 — Checkpoint frontier normalized

PASS.

TreeFrontier canonicality is inherited from ST0 and ST3 additionally requires
every frontier byte to belong to a full leaf. Short rightmost frontier state is
rejected.

### ST3-O03 — Tail strictly below chunk size

PASS.

Constructor, parser and restored-builder state require:

    len(tail) < 65,536.

### ST3-O04 — Offset arithmetic consistent

PASS.

The invariant is exact:

    completed_bytes
      = completed_leaf_count * chunk_size + len(tail).

Counter drift is rejected.

### ST3-O05 — Profile cannot change on restore

PASS WITH V1 SCOPE.

Only the frozen TreeProfile V1 is accepted. The checkpoint profile and embedded
frontier profile must parse independently to that profile.

### ST3-O06 — Checkpoint persistence transactional

PASS WITH FILESYSTEM SCOPE.

Same-directory temporary + fsync + replace preserves the previous checkpoint
under injected pre-replace failure. No partial checkpoint is published.

### ST3-O07 — Source hints are not security evidence

PASS.

Hints are explicitly typed/documented as heuristics and are demonstrated to
have zero effect on resumed TreeRoot semantics.

### ST3-O08 — Restore cost O(m log N)

PASS.

Structural derivation and frontier-size ledger agree. Prefix bytes are not read
or rehashed during restore.

## 12. Isolation review

Diff from ST2 closure baseline
`360ea2bad8916228da012225aed00e4275dd0ea7` contains:

- new checkpoint module;
- independent checkpoint reference;
- ST3 gates/benchmark/vector generator;
- ST3 tests and vectors;
- additive checkpoint identifiers/exports;
- provisional CLI additions;
- **46 additive lines** in `sigma/tree/core.py` implementing snapshot/restore.

The existing ST0 methods for:

- leaf hashing;
- parent hashing;
- empty root;
- update;
- carry;
- finalization;
- direct build;

are unchanged.

No ST2 proof implementation is modified.
No Sigma v3/IAP source is modified.
No R15 source/design is modified.

ST0 and ST2 frozen vector files are absent from the ST3 diff.

## 13. Execution limitation

The active execution environment does not provide a full Git checkout from the
GitHub connector, so the full repository pytest/ruff/mypy suite is not claimed
here.

Closure evidence instead uses:

- the exact ST3 wire/algorithm logic mirrored locally;
- frozen independent reference algorithms;
- closure-scale split/mutation execution;
- branch diff isolation;
- frozen KAT hashes;
- source inspection of the additive TreeBuilder delta.

Full clean-wheel/repository quality gates remain REL2 concerns and are not
silently conflated with ST3 semantics.

## 14. Adversarial disposition

No unresolved blocking ST3 finding remains.

Important boundaries retained:

1. checkpoint source hints are heuristic, not proof;
2. checkpoint resume authenticates continuity from checkpoint state, not the
   current filesystem prefix;
3. transactionality is scoped to atomic replacement semantics of the host
   filesystem;
4. no hashlib internal state is serialized;
5. no prefix-rehash claim is made for initial checkpoint creation itself;
   the no-rehash property applies to restore/resume.

Adversarial review disposition:

    PASS

ST3-O01..O08 may be marked COMPLETE.
ST4 remains a separate PLANNED stage.
