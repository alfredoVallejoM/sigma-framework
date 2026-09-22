# ST0 — Implementation Evidence

Status: **CANDIDATE FOR ADVERSARIAL REVIEW**  
Reviewed source baseline before final adversarial review: `7d7acceb3e8470050ec5cc41f9e0fdb18802c1d7`  
Date: 2026-09-22

## 1. Scope actually implemented

ST0 introduces an independent structural layer `Sigma Tree V1` without
modifying Sigma v3/IAP semantics.

Implemented:

- `sigma/tree/ids.py`
- `sigma/tree/codec.py`
- `sigma/tree/model.py`
- `sigma/tree/core.py`
- `sigma/tree/legacy_v22.py`
- `sigma/tree/__init__.py`
- `reference/tree_v1.py`
- `specification/sigma-tree-v1.md`
- `specification/test-vectors/sigma-tree-v1-st0.json`
- ST0 unit/property/differential/vector tests
- independent KAT generator/checker
- reproducible ST0 structural gate
- reproducible ST0 complexity benchmark

The existing non-document files outside `sigma/tree/` changed by ST0 are limited to version/release integration: `sigma/version.py` registers `TREE_WIRE_VERSION = 1`, `scripts/release_artifacts.py` records that axis in SBOM metadata, and `tests/unit/test_versioning.py` checks the new axis. No existing hashing, binding, layout, round, digest or application semantics were changed. `sigma/tree/ids.py` imports the version value rather than duplicating the authority.

## 2. Semantic structure

The fixed V1 profile uses:

- 65,536-byte canonical leaves;
- SHA-512, SHA3-512, BLAKE2b-512 and SHAKE256-512 in a fixed order;
- branch-bound leaf frames;
- canonical binary frontier;
- no odd-node duplication;
- largest-power-of-two recursive split;
- explicit empty root;
- independent Tree domains/wires.

For a tree with `n` completed leaves:

[
n = sum_h b_h 2^h
]

and the frontier is the unique ordered sequence of perfect subtrees for the set
bits of `n`, from most-significant to least-significant bit.

Generic composition of adjacent nodes additionally enforces the canonical
recursive split: if `n=l+r`, then `l` must be the largest power of two
strictly smaller than `n`. The left subtree must be byte-full; only the
globally rightmost subtree may contain the final short leaf.

## 3. Hardening performed before candidate promotion

Source review during implementation identified and repaired these issues before
candidate status:

1. **Leaf branch ambiguity.** The first draft hashed the same canonical leaf
   frame with four primitives but did not carry the algorithm ID inside the
   frame. V1 now binds `algorithm_id` explicitly in each leaf frame.

2. **Alternative tree shapes.** Adjacency alone allowed a structurally
   non-canonical decomposition such as 3+2 leaves for a 5-leaf parent. Parent
   construction now enforces the largest-power-of-two canonical split.

3. **Unreachable short-left trees.** A short subtree was initially admissible
   on the left of a later sibling. Composition and frontier validation now
   require every non-rightmost subtree to be byte-full.

4. **Profile cardinality parsing.** The profile parser now rejects algorithm
   vector counts other than exactly four before constructing enum values.

5. **Mutable structural containers.** Algorithm, digest and frontier containers
   are now required to be typed immutable tuples.

6. **Parser total-size ceiling.** Tree record parsing now rejects records above
   8 MiB before TLV traversal.

7. **Duplicated version authority.** Tree wire version is now owned by
   `sigma.version`; the tree identifier module imports it.

8. **Reference oracle strength.** The independent implementation now
   reconstructs the complete TreeRoot wire, not only the four digest
   components.

9. **Nominal-type aliasing.** Because `IntEnum` values compare equal to plain
   integers, the profile now explicitly requires an immutable tuple of
   `TreeAlgorithmId` members; digest/frontier containers are likewise required
   to be immutable typed tuples.

10. **Version/release drift.** The Tree wire is a first-class package version
    axis and is included in version policy, the existing versioning unit test
    and release SBOM metadata.

## 4. Focused executable evidence

The ST0 implementation was mirrored into an isolated local execution directory
and exercised with Python 3.13.5 on Linux x86_64.

Focused test suite:

    PYTHONPATH=. pytest -q tests/unit tests/property tests/differential tests/vectors

Result:

    29 passed

The focused suite includes:

- canonical profile/root/node/frontier round trips;
- boundary sizes 0, 1, 65,535, 65,536 and 65,537;
- malformed magic/version/trailing data;
- profile cardinality and immutable type rejection;
- canonical-split and short-left negative tests;
- 100,001 exhaustive frontier-decomposition integers;
- 250 random read-partition equivalence cases;
- 250 random frontier wire round trips;
- 300 random prehashed-leaf reducer equivalence cases;
- 128+ deterministic independent-reference cases plus fixed boundaries;
- KAT corpus replay.

Compilation check:

    python -m compileall -q sigma/tree reference/tree_v1.py scripts/product_closure tests

Result: PASS for the focused mirror.

## 5. Independent KAT evidence

The KAT corpus is generated from the stdlib-only independent oracle:

    python -m scripts.product_closure.generate_st0_vectors --check

Output SHA-256:

    9c9637c20c6424ba37d55a7781dd620ed7f22c516bd8aa15d5b916d93a7c70a9

The product implementation is then required to reproduce each independent root
and complete root-wire hash.

## 6. Reproducible ST0 gate

Command:

    python -m scripts.product_closure.st0_gate       --structural-cases 100001       --differential-cases 2000       --fuzz-cases 10000

Result:

- passed: true
- structural cases: 100,001
- independent differential cases: 2,000
- deterministic codec mutations: 10,000
- rejected malformed mutations: 3,143
- accepted-but-different canonical mutations: 6,857
- differential root stream SHA-256:
  `27c4880352dc58d4b381e82ab069984afb63178a3eaee2023fb6519396a270b8`
- mutation stream SHA-256:
  `de8573088fc8cf8b7cea926562066fd3bc9920a99ee5a623ba915d21de6bfe8b`
- frontier wire SHA-256:
  `a069fc7478e862928b77a70bbbfcf45e68c88d6032c32977adf05ae80097d671`

The mutation gate does not require all bit mutations to be rejected. Mutating a
digest payload can yield a different well-formed root. The required invariant is
that no changed accepted wire decodes to the original structural object.

## 7. Complexity evidence

Local engineering benchmark, five repeats per point:

| bytes | leaves | frontier nodes | median ns |
|---:|---:|---:|---:|
| 0 | 0 | 0 | 34,010 |
| 65,536 | 1 | 1 | 615,712 |
| 196,608 | 3 | 2 | 1,878,541 |
| 262,144 | 4 | 1 | 2,512,659 |
| 983,040 | 15 | 4 | 9,663,284 |
| 1,048,576 | 16 | 1 | 10,092,870 |
| 4,128,768 | 63 | 6 | 41,542,565 |
| 4,194,304 | 64 | 1 | 42,050,677 |
| 8,323,072 | 127 | 7 | 90,966,190 |
| 8,388,608 | 128 | 1 | 87,734,171 |

Empirical log-log time exponent:

    1.031162644655983

This is local exploratory engineering evidence only, not a cross-host performance
claim. It is consistent with the declared linear-in-bytes build cost. Frontier
node counts match the popcount/binary-decomposition prediction and remain
O(log N), plus one fixed-size 65,536-byte input buffer.

## 8. Historical isolation evidence

Blob identity was compared between base
`r15-exploratory-engineering-apps` and the product branch:

- v2.2 conformance corpus:
  `1a758b131d0d46769525f512454890e07ba70c42` — unchanged.
- v3 R12 corpus:
  `bb6fe4a39f5f7d68602673ac92bcf0e44ea1c47a` — unchanged.
- v3 R12.5 corpus:
  `736bdd649792d40a6e27923d012a4b19ace331b3` — unchanged.

A branch diff confirms that no Sigma v3 binding/layout/round/digest/application
source file has been modified by ST0.

The historical v2.2 adapter is read-only and calls the unchanged
`TreeWide.compute`; it does not convert the returned evidence to TreeRoot V1.

## 9. Obligation mapping

### ST0-O01 — Deterministic chunking

Evidence:
- random read-partition property tests;
- independent recursive oracle;
- ST0 differential gate.

Candidate status: SATISFIED.

### ST0-O02 — Leaf framing injectivity

Argument:
strict record/TLV lengths plus fixed-width profile, algorithm ID, leaf index,
byte offset and byte length uniquely delimit the accepted leaf frame. The claim
is about canonical framing, not collision-free hash output.

Candidate status: SATISFIED.

### ST0-O03 — Node framing injectivity

Argument:
strict field tags and lengths uniquely bind profile, branch algorithm, height,
start, count, byte length and both ordered child digests.

Candidate status: SATISFIED.

### ST0-O04 — Unique normalized frontier

Argument:
uniqueness follows from uniqueness of binary expansion. Exhaustive check over
leaf counts 0..100,000 confirms the executable decomposition.

Candidate status: SATISFIED.

### ST0-O05 — Combine locality

`combine_nodes` consumes only profile plus its two child summaries and checks
adjacency/canonical split locally.

Candidate status: SATISFIED.

### ST0-O06 — Backend neutrality

A single serial reducer accepts canonical ordered prehashed leaves. Three hundred
random corpora reproduce direct Tree construction exactly. Scheduling is outside
Tree semantics; a future parallel backend must normalize results into this order.

Candidate status: SATISFIED.

### ST0-O07 — Unique empty root

Empty object has explicit EMPTY domain and fixed branch-bound frames; KAT is
frozen. TreeRoot also records zero byte/leaf counts.

Candidate status: SATISFIED.

### ST0-O08 — Legacy v2.2 isolation

Historical implementation/corpus are unchanged and exposed only by the explicit
read-only compatibility facade.

Candidate status: SATISFIED BY SOURCE/CORPUS IDENTITY.

### ST0-O09 — Resource-bounded parser

- each TLV field <= 1 MiB;
- total Tree record <= 8 MiB;
- frontier <= 64 nodes;
- parser validates magic/version/length/schema before semantic construction.

Candidate status: SATISFIED.

### ST0-O10 — Complexity contract

Derived:
- B bytes are hashed once by four fixed branches at leaf level;
- internal node count is O(N);
- N=ceil(B/chunk);
- build O(mB);
- frontier contains at most one node per set bit/height: O(m log N);
- final fold O(m log N).

Local exponent ~1.03 is consistent with the build contract.

Candidate status: SATISFIED.

## 10. Execution limitation

The active environment did not contain a full checkout of the private repository
and outbound Git cloning was unavailable. GitHub Actions are intentionally
disabled in this project. Therefore the complete pre-existing repository pytest,
ruff and mypy suites were **not** executed here.

This limitation is not hidden. ST0 evidence instead consists of:

- focused executable mirror of all new ST0 modules/tests;
- independent stdlib oracle;
- immutable historical corpus blob identities;
- branch-diff source isolation;
- source inspection of the existing versioning test affected by the new
  independent version axis.

A future REL gate still requires clean-wheel/full-package execution before public
release.

## 11. Candidate conclusion

All ST0-specific blocking obligations have implementation evidence and are ready
for the required post-candidate adversarial review.

No ST1 functionality is authorized to consume TreeCore as COMPLETE until that
review is recorded.
