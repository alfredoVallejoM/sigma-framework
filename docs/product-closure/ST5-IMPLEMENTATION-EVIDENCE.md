# ST5 — Tree Performance and Scale Closure Evidence

Status: **ADVERSARIAL REVIEW PASSED — READY FOR COMPLETE**  
Reviewed implementation baseline: `313a4b7b3d2b717acca4508af03fde58e93a3ec6`  
ST4 baseline: `cea3310013c1ad5af8f5a1e0565e14ab502d8938`  
Date: 2026-09-22

## 1. Scope

ST5 closes accidental Tree performance/memory debt without redefining any
cryptographic object.

Product changes:

- leaf hashing streams the existing canonical leaf preimage in parts;
- TreeBuilder uses memoryviews for complete input chunks;
- TreeProofIndex uses zero-copy leaf views;
- inclusion/range proofs have no-index streaming generators;
- range verification uses logarithmic recursive reconstruction state;
- TreeScalePolicyV1 makes FULL/STREAMING/REJECT decisions explicit;
- Manifest file reads are limited to one Tree chunk.

No new cryptographic primitive is introduced.

No persistent index wire is introduced.

## 2. O01 — Optimized Tree preserves reference bytes

The optimization-sensitive surface was tested against the independent stdlib
Tree/proof references.

Closure-scale isolated execution:

    build differential cases: 1,000
    divergences: 0

Build stream SHA-256:

    18f439cb297bab461841384a6d02220c61794414061d40b5dc2aacca5ee9ce18

Proof differential cases:

    500

For every proof case:

    FULL inclusion wire == STREAMING inclusion wire
    FULL range wire     == STREAMING range wire

and the independent verifier accepts the results.

Proof stream SHA-256:

    f83f23c39aa28defb75dd88d7e34313d30ae4658bc931ba275881c3c38770b55

Boundary cases include:
- empty Tree build;
- 1 byte;
- chunk-1;
- exact chunk;
- chunk+1;
- multi-chunk tails.

Disposition:

    ST5-O01 PASS

## 3. Leaf-frame copy remediation

### Finding

The ST0 implementation was semantically correct but built a complete
`SIGTLEAF` record for each branch before hashing it.

Because V1 has four branches, this created four transient records containing the
same raw leaf.

### Remediation

The exact same byte sequence is now fed incrementally:

    domain
    record header
    TLV fields 1..5
    field-6 TLV header
    raw leaf memoryview

The reference differential confirms byte identity.

The public `leaf_node(..., leaf: bytes)` API remains unchanged.

Internal `_leaf_node_buffer` is not a new semantic authority; it is the
zero-copy realization of the existing leaf frame.

## 4. TreeBuilder copy remediation

### Finding

Complete chunks were produced as `bytes` slices inside `update()`.

### Remediation

Complete chunks are memoryviews over the caller input.

Only an incomplete tail is copied into the builder buffer.

Measured auxiliary-memory sweep:

| Input | Peak auxiliary allocation |
|---:|---:|
| 64 KiB | 3.3 KiB |
| 256 KiB | 4.1 KiB |
| 1 MiB | 5.2 KiB |
| 4 MiB | 6.3 KiB |
| 16 MiB | 7.3 KiB |
| 32 MiB | 8.2 KiB |

A separately ordered 32 MiB gate run observed ~24 KiB peak, still far below the
hard 2 MiB closure budget and independent of B.

Disposition:

    ST5-O03 PASS for Tree build.

## 5. ProofIndex zero-copy layout

### Finding

ST2 TreeProofIndex retained the source bytes and also created a bytes slice for
every leaf.

That is an accidental second B-sized payload representation.

### Remediation

The leaf array is now:

    tuple[memoryview, ...]

and every view points to the original source bytes.

16 MiB audit:

    source bytes:              16,777,216
    peak extra allocation:        392,534
    peak/source:                    2.34%
    conservative policy estimate: 1,114,112

No second B-sized payload copy remains.

Disposition:

    ST5-O02 PASS for ProofIndex.

## 6. Streaming proof fallback

ST5 adds no-index generation:

    prove_leaf_streaming
    prove_range_streaming

The algorithms recursively hash canonical subtrees and retain only:
- current recursion path;
- final proof witnesses/steps;
- bounded edge bytes already required by the proof format.

The generated proof wire is identical to FULL-index generation.

Representative ~16 MiB source:

    ProofIndex build                ~191 ms
    FULL inclusion generation       ~24 us
    STREAMING inclusion generation ~197 ms
    FULL range generation           ~46 us
    STREAMING range generation     ~205 ms

Interpretation:

FULL is appropriate for repeated proofs.

STREAMING is a memory fallback and intentionally pays O(B) hashing work per
proof.

No documentation calls STREAMING "faster".

## 7. Range generation/verification memory findings

Two additional hidden scale debts were discovered during ST5.

### Finding A — selected-range copy

Verification originally created:

    prefix + range_bytes + suffix

which could duplicate a multi-MiB selected range.

### Fix

Interior leaves use memoryview slices.

Only first/last edge leaves may materialize bounded <=65,536-byte buffers.

### Finding B — target leaf node map

After removing the byte copy, verification still accumulated every target leaf
TreeNode in a dictionary.

Memory therefore remained O(range/chunk).

### Fix

Verification now recursively traverses canonical Tree geometry:

- disjoint subtree -> consume witness;
- target singleton -> hash leaf;
- partial subtree -> recurse left/right and combine.

Only O(log N) tree reconstruction state is live.

### Finding C — streaming range generator

The first no-index generator had the same target-node-map issue.

It now uses the same recursive geometry principle and appends only final
witnesses.

Near-full ~16 MiB audit:

    STREAMING range generation peak: ~22.7 KiB
    range verification peak:        ~138.1 KiB

The selected input itself is caller-owned and excluded from auxiliary-memory
claims.

Disposition:

    ST5-O02 PASS
    ST5-O03 PASS for range proof generation/verification.

## 8. DeltaIndex explicit copy

DeltaIndex differs intentionally from ProofIndex.

Incremental same-length edits need mutable source payload state. Therefore
DeltaIndex owns one B-sized mutable/chunked representation.

This is not hidden.

The scale estimator includes B explicitly:

    estimate_delta
      = 65,536 + B + 4,608 * leaf_count

8 MiB audit:

    source bytes:          8,388,608
    measured peak:         8,564,890
    policy estimate:       9,043,968

The estimator covers the audited peak.

## 9. O04 — Explicit index policy/fallback

New policy objects:

    TreeScalePolicyV1
    TreeIndexPlanV1

Operations:

    PROOF
    DELTA

Modes:

    FULL
    STREAMING
    REJECT

Proof over budget:
- STREAMING by default;
- REJECT if explicitly selected.

Delta over budget:
- REJECT.

`delta_index_scaled` evaluates the plan before constructing TreeDeltaIndex.

A constructor-bomb test confirms over-budget delta does not instantiate the
index.

There is deliberately no:

    over-budget delta -> hidden full rebuild

because that would violate ST4's incremental contract.

Disposition:

    ST5-O04 PASS

## 10. Budget estimator scope

Proof estimate:

    65,536 + 4,096 * leaf_count

Delta estimate:

    65,536 + source_bytes + 4,608 * leaf_count

These are conservative logical budget formulas for the supported CPython
implementation, not portable RSS predictions.

They are intentionally padded above the audited tracemalloc peaks.

Policy decisions remain deterministic even if a host allocator has different
RSS overhead.

## 11. Manifest I/O closure

The ST1 manifest semantics are unchanged.

Regular-file hashing previously requested 1 MiB blocks.

ST5 requests:

    <= 65,536 bytes

per `os.read`.

A read-spy test locks this bound.

The file bytes themselves are never accumulated by the manifest scanner.

## 12. Build baseline vs optimized

Frozen local ledger:

| B | speedup vs independent full-frame reference | optimized peak | reference peak |
|---:|---:|---:|---:|
| 64 KiB | ~1.27x | 3.1 KiB | 193 KiB |
| 256 KiB | ~1.14x | 3.8 KiB | 259 KiB |
| 1 MiB | ~1.07x | 4.9 KiB | 265 KiB |
| 4 MiB | ~1.11x | 5.9 KiB | 290 KiB |

Observed local throughput:

    ~75–88 MiB/s

This is EMPIRICAL-PERFORMANCE evidence only.

## 13. CPU profile

After copy remediation, the dominant work is the actual hash primitive updates.

Representative 1 MiB profile:

    hashlib HASH.update total  ~7.71 ms
    blake2b update total       ~1.25 ms
    leaf hashing cumulative    ~9.86 ms
    parent composition         <1 ms

This is the desired endpoint for ST5: the remaining dominant cost is intrinsic
cryptographic hashing rather than avoidable Python payload copying.

## 14. Cross-stage representative checks

ST5 does not reopen ST2-ST4 algorithms.

Representative local ledger:

Resume:
- ~16 MiB prefix;
- restore median ~5 us;
- prefix not rehashed.

Delta:
- ~16 MiB source;
- one-byte edit;
- 65,536 payload bytes rehashed;
- 10 nodes recomputed;
- ~1.96 ms local.

Append:
- one chunk + 17 bytes;
- 65,572 payload bytes rehashed;
- 4 nodes recomputed;
- previous frontier reused;
- ~1.21 ms local.

Manifest fixture:
- 64 files x 64 KiB;
- 4 MiB input;
- ~52 ms hashing fixture;
- ~0.20 MiB peak;
- one-chunk read requests.

The larger delta fraction sweep remains authoritative in ST4.

## 15. Frozen ledger

File:

    docs/product-closure/ST5-PERFORMANCE-LEDGER.json

Environment:

    CPython 3.13.5
    Linux x86_64

The ledger contains:
- semantic stream hashes;
- build baseline/optimized rows;
- streaming memory sweep;
- proof FULL/STREAMING rows;
- resume/delta/append/manifest representative rows;
- CPU profile summary;
- resource-policy formulas.

Timings are explicitly local and not cross-host claims.

## 16. Persistent index decision

The campaign considered whether ST5 needed a persistent sidecar index.

Decision:

    NO NEW PERSISTENT INDEX WIRE IN ST5

Rationale:
- no ST5 obligation requires one;
- Tree identity does not depend on it;
- storage/mmap/atomic sidecar design deserves a separate compatibility surface;
- adding it would create new parser/persistence debt while trying to close scale
  debt.

ST5 freezes the in-memory layout and policy interface required for a future
sidecar implementation.

## 17. Isolation review

Diff from ST4 baseline
`cea3310013c1ad5af8f5a1e0565e14ab502d8938` changes product code only in:

- `sigma/tree/core.py`;
- `sigma/tree/proofs.py`;
- `sigma/tree/manifest.py`;
- new `sigma/tree/scale.py`;
- additive exports.

Not modified:
- `sigma/tree/model.py`;
- `sigma/tree/delta.py`;
- `sigma/tree/checkpoint.py`;
- ST0/ST2/ST3/ST4 frozen vector files;
- Sigma v3/IAP source;
- R15 source/design.

This is consistent with a performance-only closure.

## 18. Adversarial findings

Finding A — leaf records copied raw payload four times  
Status: **FIXED**

Finding B — ProofIndex duplicated B in leaf slices  
Status: **FIXED**

Finding C — range verification copied entire selected range  
Status: **FIXED**

Finding D — range verifier retained O(range/chunk) target nodes  
Status: **FIXED**

Finding E — streaming range generator retained O(range/chunk) target nodes  
Status: **FIXED**

Finding F — scale fallback was previously implicit/nonexistent  
Status: **FIXED** with explicit plan objects

Finding G — DeltaIndex retains B-sized payload state  
Status: **ACCEPTED AND EXPLICITLY BUDGETED**, not hidden

Finding H — persistent index wire could expand scope/debt  
Status: **REJECTED BY DESIGN**

No unresolved blocking ST5 finding remains.

## 19. Obligation disposition

### ST5-O01 — Optimized Tree preserves reference bytes

PASS.

1,000 build differentials + 500 FULL/STREAMING proof corpora produce zero
divergence.

### ST5-O02 — No hidden large copies

PASS WITH EXPLICIT DELTA EXCEPTION.

Build/proof/range accidental B-sized copies are eliminated.

Delta's mutable payload copy is deliberate, measured, documented and budgeted.

### ST5-O03 — Streaming memory bounded

PASS.

Tree build and proof fallback/verification use bounded auxiliary state with
respect to source/range B, excluding caller-owned input and mandatory proof
output.

### ST5-O04 — Index policy fallback explicit

PASS.

FULL/STREAMING/REJECT is deterministic, inspectable and tested before expensive
index construction.

## 20. Execution limitation

As in ST2-ST4, the active environment cannot materialize a complete Git checkout
from the GitHub connector.

Therefore ST5 does not claim:
- full-repository pytest;
- full ruff;
- full mypy;
- clean-wheel execution.

Those remain REL2 gates.

ST5 closure uses:
- exact-semantic local execution;
- independent references;
- GitHub branch diff isolation;
- frozen ledger;
- targeted tests/gates committed to the branch.

## 21. Adversarial disposition

Adversarial review:

    PASS

ST5-O01..O04 may be marked COMPLETE.

ST5 does not authorize opening/changing Sigma v3 semantics.
