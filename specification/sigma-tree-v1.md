# Sigma Tree V1 — ST0 byte-exact structural specification

Status: **ST0 implementation candidate**  
Date: 2026-09-22  
Scope: Sigma Tree only; no change to Sigma v2.2 or Sigma v3/IAP.

## 1. Purpose and trust boundary

Sigma Tree V1 is a structural-integrity layer intended to support future manifests,
inclusion/range proofs, portable resume and local delta updates.

It is **not**:
- a new Sigma v3 suite;
- a conversion of Sigma v2.2 TreeWide;
- a new cryptographic primitive;
- a claim that four 512-bit branches provide 2048 bits of security;
- a production-security claim.

Sigma v2.2 remains frozen as a historical baseline. Sigma v3/IAP remains the
authority for historical trajectory commitments. Sigma Tree V1 has its own wire
version and domains.

## 2. Fixed profile

The only V1 profile is:

- profile id: `0x0001`;
- chunk size: 65,536 bytes;
- branch order:
  1. SHA-512 (`0x0001`);
  2. SHA3-512 (`0x0002`);
  3. BLAKE2b-512 (`0x0003`);
  4. SHAKE256 with exactly 64 output bytes (`0x0004`);
- each branch output is exactly 64 bytes;
- no odd-node duplication;
- frontier consists of perfect subtrees;
- finalization folds the canonical frontier from right to left.

These algorithm identifiers name standard primitives already used elsewhere in
Sigma. They are a Sigma Tree registry and do not reinterpret v2/v3 suite IDs.

## 3. Common record encoding

All new Tree records use:

    magic[8] || version:u16(1) || body_length:u32 || body

The body is strict TLV:

    tag:u16 || length:u32 || value

with:
- tags positive;
- strictly increasing;
- unique;
- complete for the record schema;
- unknown tags rejected;
- fields bounded to at most 1 MiB;
- trailing bytes rejected.

Tree domain separation is:

    "SIGTRDS1" || domain_id:u16

Domains:

| domain | id |
|---|---:|
| LEAF | 0x0001 |
| NODE | 0x0002 |
| EMPTY | 0x0003 |

## 4. TreeProfileV1

Wire magic:

    SIGTPRF1

Fields:

| tag | value |
|---:|---|
| 1 | profile id u16 |
| 2 | chunk size u32 |
| 3 | count:u16 followed by ordered algorithm ids u16 |

Only the exact profile of section 2 is accepted.

## 5. Leaf framing

For canonical leaf `i`, byte offset is:

    offset_i = i * 65536

and leaf length is in `[1,65536]`.

The leaf frame is:

    record("SIGTLEAF",
      1: TreeProfileV1,
      2: leaf_index:u64,
      3: byte_offset:u64,
      4: byte_length:u32,
      5: exact leaf bytes)

For branch algorithm `H_j`:

    L_i,j = H_j(domain(LEAF) || LeafFrame_i)

A leaf node is:

    start_leaf = i
    leaf_count = 1
    byte_length = len(leaf)
    height = 0
    digests = (L_i,1,...,L_i,4)

## 6. Node semantics

A `TreeNode` is valid only when:

    leaf_count > 0
    start_leaf + leaf_count < 2^64
    byte_length < 2^64
    height = ceil(log2(leaf_count))
           = bit_length(leaf_count - 1)

Canonical chunk accounting requires:

    (leaf_count - 1) * 65536 + 1
        <= byte_length
        <= leaf_count * 65536

The generic node wire magic is:

    SIGTNODE

with fields:
1. start_leaf:u64
2. leaf_count:u64
3. byte_length:u64
4. height:u32
5. four length-prefixed 64-byte digests.

## 7. Parent construction

Given adjacent nodes `L,R`:

    L.start_leaf + L.leaf_count = R.start_leaf

define:

    start = L.start_leaf
    count = L.leaf_count + R.leaf_count
    length = L.byte_length + R.byte_length
    height = max(L.height,R.height) + 1

For every branch j:

    NodeFrame_j =
      record("SIGTJOIN",
        1: profile,
        2: algorithm_id_j,
        3: height,
        4: start,
        5: count,
        6: length,
        7: left_digest_j,
        8: right_digest_j)

    P_j = H_j(domain(NODE) || NodeFrame_j)

A **frontier carry** is stricter: both children must be perfect and have equal
height.

## 8. Canonical frontier

For `n` completed leaves:

    n = sum_h b_h 2^h

The frontier contains exactly one perfect subtree for each set bit `b_h = 1`,
ordered from left to right / most significant bit to least significant bit.

Therefore frontier heights are strictly decreasing.

Example:

    n=7 = 4+2+1  -> heights (2,1,0)
    n=10 = 8+2   -> heights (3,1)

Frontier nodes:
- start at leaf zero;
- are contiguous;
- are perfect;
- have the exact height sequence induced by the binary expansion of `n`;
- are bounded to at most 64 nodes.

Wire magic:

    SIGTFRNT

Fields:
1. profile;
2. count-prefixed sequence of canonical TreeNode records.

## 9. Empty root

For every branch j:

    EmptyFrame_j =
      record("SIGTEMPT",
        1: profile,
        2: algorithm_id_j,
        3: u64(0))

    E_j = H_j(domain(EMPTY) || EmptyFrame_j)

The empty root has:

    byte_length = 0
    leaf_count = 0
    digests = (E_1,...,E_4)

## 10. Streaming construction

Input bytes are rechunked independently of caller read boundaries into exact
65,536-byte leaves except for an optional final shorter leaf.

For every completed leaf, TreeBuilder performs binary carries while the
rightmost frontier node has the same height as the new node.

Consequently:
- there is at most one frontier node per height;
- frontier storage is O(log N);
- read-call boundaries do not affect the result.

## 11. Finalization

If the frontier is empty, return the empty root.

Otherwise:
1. take the rightmost frontier node;
2. combine each remaining frontier node from right to left;
3. require resulting start_leaf=0;
4. require resulting leaf_count equals total leaves;
5. require resulting byte_length equals total bytes.

The final root wire magic is:

    SIGTROOT

Fields:
1. TreeProfileV1;
2. byte_length:u64;
3. leaf_count:u64;
4. four ordered digest components.

The root parser additionally validates canonical byte/leaf bounds.

## 12. Equivalent recursive description

For a non-empty ordered leaf list of size `n>1`, let:

    p = largest power of two strictly less than n

Then:

    Root(leaves[0:n])
      = Parent(
          Root(leaves[0:p]),
          Root(leaves[p:n]))

This recursive specification is the independent reference oracle.

The binary-frontier streaming reducer and recursive specification are required
to agree byte-for-byte.

## 13. Prehashed backend reducer

A backend may supply ordered tuples:

    (four canonical leaf digests, byte_length)

to the serial reducer.

Requirements:
- exactly four 64-byte digests;
- all leaves except possibly the last have length 65,536;
- only the final leaf may be short;
- input order is canonical leaf order.

The reducer does not assert provenance of supplied hashes. Backend code remains
responsible for computing them from the exact leaf framing above.

## 14. Complexity contract

Let:
- `B` = input bytes;
- `N = ceil(B / 65536)` for non-empty input;
- `m=4` branches.

Expected costs:

    build time      O(mB)
    frontier memory O(m log N)
    finalization    O(m log N)

No ST0 claim is made about inclusion-proof or delta complexity; those belong to
later stages.

## 15. Compatibility boundary

The historical v2.2 TreeWide adapter is read-only.

It may:
- reproduce old TreeWide roots;
- support historical regression.

It may not:
- relabel v2.2 evidence as Sigma Tree V1;
- convert a v2.2 root into a TreeRoot V1;
- create a v3 trajectory digest.

The two formats use distinct types, domains and records.

## 16. Structural claims

ST0 may claim:
- deterministic canonical chunking;
- injective accepted record encodings;
- unique frontier decomposition;
- read-partition invariance;
- backend-neutral serial reduction when prehashed leaves are canonically ordered;
- exact agreement between product implementation and independent recursive reference;
- O(log N) frontier node count.

Cryptographic collision/preimage claims remain conditional on underlying
primitives and are not strengthened by concatenating four branch outputs.

## 17. Conformance evidence

Frozen KAT corpus:

    specification/test-vectors/sigma-tree-v1-st0.json

SHA-256 of the initial KAT file:

    3fbd83dc80147127e96374a958b1924e18c4a665dc85381051003417dfba5ab9

Independent oracle:

    reference/tree_v1.py

Reproducible structural gate:

    python -m scripts.product_closure.st0_gate

The ST0 campaign additionally requires manual adversarial review after the
implementation evidence is collected.
