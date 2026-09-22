# SV3 — Verification Receipts and Batch Implementation Evidence

Status: **COMPLETE — RECEIPT/BATCH RUNTIME GATE + ADVERSARIAL REVIEW PASSED**  
Executed product baseline: `3837fa5172c953b3e98175db66fe1dbfd07e2237`  
GitHub Actions run: `35786646804`  
Date: 2026-09-22

## 1. Scope

SV3 adds the non-blocking trajectory-product surfaces for:

- canonical VerificationReceiptV1;
- explicit unsigned receipts;
- optional Ed25519 receipt authentication;
- pointwise batch verification;
- per-item failure isolation;
- deterministic serial/threaded result ordering.

Implemented:

- `sigma/trajectory/receipt_v1.py`;
- `sigma/trajectory/batch_v1.py`;
- additive exports in `sigma/trajectory` and `sigma/v3.py`;
- `reference/verification_receipt_v1.py`;
- `scripts/product_closure/sv3_gate.py`;
- focused unit/adversarial tests.

SV3 does not modify Sigma v3 evaluation or digest semantics.

## 2. Receipt wire

Magic:

    SIGRCPT1

Strict v3 record/TLV encoding.

Bound fields:

1. artifact identity;
2. policy identity;
3. verifier package;
4. verifier version;
5. verifier build identity;
6. evidence kind;
7. evidence identity;
8. decision kind;
9. decision code;
10. decision reason;
11. structure-valid tri-state;
12. message-binding tri-state;
13. evidence hashes;
14. optional claimed Unix time;
15. signature status;
16. signature algorithm;
17. public-key ID;
18. signature.

Strings are canonical UTF-8 NFC.

## 3. Artifact identity boundary

SA0 does not yet exist.

Therefore SV3 does not invent a premature ArtifactId algorithm.

`artifact_identity` is an opaque canonical non-empty bytes identifier. Receipt
semantics are:

    "this record binds exactly these artifact-identity bytes"

not:

    "these bytes have already been proved to be a valid SigmaArtifact ID".

SA0 can later supply its exact ArtifactId without changing receipt wire.

## 4. Policy/result binding

`receipt_from_decision_v1` requires:

    supplied_policy.policy_id == decision.policy_id.

If the decision has an evidence ID, canonical evidence hashes must include it.

`decision_projection()` reconstructs the exact VerificationDecisionV1 fields
recorded by the receipt.

The product deliberately does not add a redundant verification-mode enum.
Executed verification state is already represented by:

    structure_valid
    message_binding_verified.

## 5. Unsigned receipts

Unsigned state is explicit:

    ReceiptSignatureStatusV1.UNSIGNED.

Canonical unsigned form requires:

    signature_algorithm = None
    public_key_id = empty
    signature = empty.

An unsigned receipt never passes `verify_receipt_signature_v1`.

This closes SV3-O04 without inference from missing bytes.

## 6. Signed receipts

SV3 reuses the already-supported standard primitive:

    Ed25519.

No new signature primitive is introduced.

Signing input:

    b"SIGMA-VERIFICATION-RECEIPT-V1\0"
      || canonical signed receipt with empty signature bytes.

The signed placeholder already binds:
- SIGNED status;
- ED25519 algorithm;
- public-key ID;
- every receipt/result/evidence field.

Only the final 64 signature bytes are excluded from their own input.

The gate mutates:
- artifact identity;
- policy identity;
- verifier version;
- decision reason;
- timestamp claim

across 200 signed receipts for 1,000 total signed-field mutations.

Every mutation is rejected.

## 7. Receipt identity

Defined:

    ReceiptId = SHA256(canonical receipt wire).

This is only a deterministic content ID.

No additional security width is claimed.

## 8. Provenance and timestamp claim boundary

A signed receipt proves that the signing key authenticated the canonical record.

It does not prove:
- opaque provenance is semantically true;
- artifact identity is externally authoritative;
- a claimed timestamp is trustworthy;
- an event existed historically at the claimed time.

Executed gate explicitly records:

    opaque_provenance_truth_claim = false.

SA2 remains authority for future provenance semantics.

## 9. Independent receipt encoder

`reference/verification_receipt_v1.py` is stdlib-only and does not import
`sigma`.

It independently implements:
- SIGRCPT1 TLV wire;
- signing-input construction;
- SIGBCRI1 item-result wire;
- SIGBCHT1 batch-result wire.

Product wires are compared byte-for-byte against this encoder.

## 10. Batch model

Batch is strictly:

    map(PointwiseVerify, items).

Pointwise authority:

    verify_batch_item_v1.

For every input index i:

    verify_batch_v1(items).items[i]
      ==
    verify_batch_item_v1(items[i], index=i).

No cryptographic state is shared between items.

## 11. Failure isolation

An item exception becomes a canonical BatchItemResultV1 error.

It does not abort or alter neighboring item receipts.

Captured error text is:
- NFC normalized;
- NUL escaped;
- UTF-8 bounded to 4096 bytes.

This prevents a hostile/invalid error message from causing a second failure in
the error-recording path.

Global batch-configuration errors remain global and reject before scheduling.

## 12. Deterministic ordering

Declared output order:

    input order.

Invariant:

    items[i].index = i.

Threaded mode uses ordered executor mapping.

The executed gate requires:

    serial.to_bytes() == threaded.to_bytes().

No completion-order sorting is allowed.

## 13. Batch wire

Per-item result magic:

    SIGBCRI1

Batch result magic:

    SIGBCHT1

BatchId:

    SHA256(canonical batch result wire).

Again, BatchId is a content identity only.

## 14. Runtime quality result

GitHub Actions run:

    35786646804

Result:

    compile PASS
    Ruff PASS
    Mypy PASS
    pytest 14 passed
    SV3 gate PASS

No test skips occurred in the focused SV3 suite.

## 15. Executed SV3 gate

Frozen report:

    SV3-GATE-REPORT.json

Report SHA-256:

    bd958921a9313d79a1d69d4bfde4dabbee7dbb732b9dff3d00c12400a698cc74

Result:

    passed = true
    closure_eligible = true
    receipt_cases = 200
    signature_mutations = 1,000
    batch_cases = 100
    failure_isolation_cases = 100
    pointwise_equivalence = true
    threaded_equivalence = true
    unsigned_receipt_explicit = true
    opaque_provenance_truth_claim = false
    empirical_performance_claims = false

Frozen streams:

receipt:

    c8f889fc9a20c5c141ca9628cb5abec4b63478744f68e335100a3eddd978c261

signed receipt:

    8d0f725e940b28a7ea9014cfa1f68bff03bbf12779149049d21513b31767d7e4

batch:

    d06d75b39e2b5fed2b264a89b3092b66a6870ea93c1d43219f019fef8deca75b

## 16. Obligation review

### SV3-O01 — Receipt binds artifact/policy/verifier/result

**PASS.**

All required identities and complete decision projection are canonical receipt
fields. Mutation and independent-wire tests pass.

### SV3-O02 — Optional signature covers canonical record

**PASS.**

Ed25519 signing input binds every canonical field except its own signature bytes.

1,000 signed-field mutations were rejected.

### SV3-O03 — No opaque provenance truth implication

**PASS.**

Docs/API make the distinction explicit and the executed gate freezes the claim
boundary as false.

### SV3-O04 — Unsigned receipt marked unsigned

**PASS.**

UNSIGNED is an explicit enum state and all signature material must be empty.

### SV3-O05 — Batch equals pointwise verification

**PASS.**

100 mixed batch cases passed exact item-wise equality.

### SV3-O06 — Item failures isolated

**PASS.**

100 injected failures produced only the failing item's error record; neighboring
receipts remained pointwise-identical.

### SV3-O07 — Deterministic result ordering

**PASS.**

Input indices are canonical and serial/threaded result wires are byte-identical.

## 17. Adversarial design findings

Finding A — SA0 ArtifactId does not yet exist  
Disposition: **FIXED BY BOUNDARY**. Receipt binds opaque artifact identity bytes
without inventing future Artifact semantics.

Finding B — dedicated verification-mode enum would duplicate result flags  
Disposition: **REJECTED**. Receipt binds the actual structure/message-binding
flags instead.

Finding C — signing a record containing its own signature is circular  
Disposition: **FIXED**. Signing input is the complete signed-form canonical
record with only signature bytes empty.

Finding D — item exception text could itself break batch error recording  
Disposition: **FIXED** via canonicalization/NUL escaping/bounded UTF-8.

Finding E — concurrent completion order could reorder results  
Disposition: **FIXED** via input-index invariant and ordered executor map.

Finding F — invalid global signer configuration could look like per-item failure  
Disposition: **FIXED**. Batch-level signer configuration is validated before
scheduling.

No unresolved SV3 design blocker remains.

## 18. Complexity status

Derived contract only:

    work = O(sum_i verifier_cost_i + result encoding).

No empirical batch throughput or speedup claim is made.

Threading is a scheduling option, not a frozen performance claim.

Empirical performance characterization remains deferred as requested.

## 19. Isolation review

SV3 adds only receipt/batch product surfaces and public exports.

It does not modify:
- SigmaContextV3;
- binding/parameter derivation;
- round evaluators;
- history functions;
- layout;
- SigmaDigestV3;
- Tree;
- frozen R12/R12.5 corpora.

## 20. Final disposition

Manual adversarial review:

    PASS

Runtime quality suite:

    PASS

SV3 closure gate:

    PASS

Final status:

    SV3 COMPLETE
