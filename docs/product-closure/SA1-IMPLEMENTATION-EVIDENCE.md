# SA1 — Dual Verification Implementation Evidence

Status: **COMPLETE — RUNTIME GATE + INDEPENDENT SIDE ORACLE + ADVERSARIAL REVIEW PASSED**  
Executed SA1 baseline: `afa58186a93d4680bb47490548aa244f36e70c03`  
GitHub Actions run: `35792567055`  
Date: 2026-09-22

## 1. Scope

SA1 defines runtime verification semantics for SA0 artifacts without modifying
Tree or Sigma v3 commitment semantics.

Implemented:

- `sigma/artifact/verify.py`;
- additive exports in `sigma/artifact`;
- `reference/dual_verification_v1.py`;
- unit and differential SA1 tests;
- `scripts/product_closure/sa1_gate.py`.

SA1 does not define provenance/signature (SA2) or final CLI/API packaging (SA3).

## 2. Result schema

`ArtifactVerificationResultV1` preserves:

    artifact_id
    artifact profile
    Tree side result
    Trajectory side result
    policy result.

Each side stores:
- status;
- reason code;
- reason;
- expected wire;
- actual recomputed wire when available.

This makes positive and negative results reconstructible and side-specific.

## 3. Exact DUAL law

For DUAL artifacts:

    dual_conjunction
      =
    tree.verified
      AND
    trajectory.verified.

Final artifact acceptance additionally requires the artifact-level policy result
to accept.

There is no fallback from one side to the other.

## 4. Tree side

The Tree side:
1. checks committed byte length;
2. replays source through TreeBuilder;
3. compares canonical TreeRoot bytes.

TreeBuilder remains the single product authority.

Reference:
- `reference.tree_v1.root_wire`.

## 5. Trajectory side

The Trajectory side:
1. checks committed cardinality;
2. runs `evaluate_v3` with the committed context;
3. reconstructs SigmaDigestV3;
4. compares canonical digest bytes.

If a TrajectoryAuditV3 is attached, the same evaluation must also reproduce the
attached Audit in its original COMPACT/FULL mode.

Reference:
- `reference.independent_v3.evaluate_suite`.

## 6. Independent claims

SA1 deliberately does not produce a single opaque cryptographic score.

The product retains independent Tree and Trajectory side reports even when the
final policy result rejects.

Executed report freezes:

    tree_trajectory_claims_independent = true
    dual_security_width_addition_claim = false.

## 7. Failure attribution

Executed gate covers three distinct failure families:

    tree_only_failure       = 300
    trajectory_only_failure = 300
    both_failure            = 300.

Observed laws:

Tree-only failure:

    tree = FAILED
    trajectory = VERIFIED.

Trajectory-only failure:

    tree = VERIFIED
    trajectory = FAILED.

Both:

    tree = FAILED
    trajectory = FAILED.

No side result is overwritten by composition.

## 8. Policy integration

SA1 consumes VerificationPolicyV1 without changing its wire or PolicyId.

Preflight handles:
- TREE requirement;
- DUAL requirement;
- Tree-only allowance;
- Audit requirement;
- suite allowlist;
- history-feedback requirement;
- input size;
- round count;
- descriptor/metadata profile;
- signature/provenance capabilities;
- symlink capability;
- proof-size and memory bounds.

When preflight decides before hashing:

    side.status = NOT_RUN.

Bomb-source tests confirm policy short-circuit avoids expensive replay.

## 9. TREE / TRAJECTORY / DUAL policy behavior

TREE:
- can be accepted only under explicit Tree-only policy;
- default product policy does not silently downgrade to Tree-only.

TRAJECTORY:
- verifies only trajectory side;
- rejects if policy requires Tree/DUAL.

DUAL:
- verifies both sides;
- rejects unless both required sides pass.

Executed gate:

    policy_cases = 200.

## 10. Selective manifest verification

SA1 defines explicit modes:

    TREE_ONLY
    DECLARED
    REQUIRE_ALL_FILES.

DECLARED:
- Tree always verified;
- trajectory only where ManifestEntryV1 contains trajectory_digest.

REQUIRE_ALL_FILES:
- every regular file must carry trajectory evidence.

TREE_ONLY:
- trajectory evidence is not evaluated.

Executed:

    manifest_cases = 100
    manifest_declared_cases = 100
    manifest_require_all_missing_cases = 100.

Mixed manifests contain one Tree-only file and one trajectory-critical file.

## 11. Independent runtime campaign

Gate:

    scripts/product_closure/sa1_gate.py

Executed result:

    passed = true
    closure_eligible = true
    dual_cases = 300
    independent_side_cases = 1,200
    policy_cases = 200
    manifest_cases = 100.

Frozen streams:

Tree:

    e5154d09e09d6bd9f773f62412fe4d3e7113c964e4d096898340acc50a6123c1

Trajectory:

    af0ea2e9b2b87f6feffc7bedb8d6793138adebf3b77309f8681c6889446154f7

Composition:

    82fa259392e63533a63ef513f775dc7167c62c01c9c8dd7196f5d43487bc8774

## 12. Frozen report

File:

    SA1-GATE-REPORT.json

SHA-256:

    b3ed54f82e29461e47453f41ef2a038bb29d3688d5f0396d79cddbb6f374f44f

## 13. Runtime quality

GitHub Actions run:

    35792567055

Result:

    compile PASS
    Ruff PASS
    Mypy PASS
    pytest 36 passed
    SA1 gate PASS.

The pytest set includes SA0 regression and SV2 policy integration surfaces.

## 14. Obligation review

### SA1-O01 — Dual verify equals Tree AND Trajectory

**PASS.**

The runtime gate checks exact conjunction against independent side references in
all 1,200 side cases.

### SA1-O02 — Dual failure attribution preserved

**PASS.**

300 Tree-only, 300 Trajectory-only and 300 both-fail cases remain distinguishable.

### SA1-O03 — Tree and Trajectory claims stay independent

**PASS.**

Side result schema retains separate status/code/wires. No combined security score
or nominal-bit sum exists.

### SA1-O04 — Policy can require TREE/TRAJECTORY/DUAL

**PASS.**

200 policy cases exercise all three artifact profiles plus incorrect-profile
rejection and cheap preflight.

### SA1-O05 — Manifest selective trajectory criticality explicit

**PASS.**

100 mixed manifests pass DECLARED mode and fail REQUIRE_ALL_FILES exactly where
trajectory evidence is absent. TREE_ONLY mode remains explicit.

## 15. Adversarial findings

Finding A — final boolean could hide which commitment failed  
Status: **FIXED** with explicit side results and failure_sides.

Finding B — calling SV2 verifier directly would duplicate expensive trajectory
evaluation and conflate policy with cryptographic side result  
Status: **FIXED** with artifact-level preflight over the same canonical policy.

Finding C — default policy could silently interpret TREE as sufficient  
Status: **FIXED**. Tree-only requires `allow_tree_only_artifacts=true`.

Finding D — attached invalid Audit could be ignored because primary digest is valid  
Status: **FIXED**. Attached Audit is replayed and can fail the Trajectory side.

Finding E — manifest optional trajectory field could create implicit criticality  
Status: **FIXED** with TREE_ONLY / DECLARED / REQUIRE_ALL_FILES modes.

No unresolved SA1 blocker remains.

## 16. Claim boundary

SA1 establishes conjunction, not security-bit addition.

It does not claim:

    bits(DUAL) = bits(Tree) + bits(Trajectory).

It also does not claim independence of cryptographic assumptions beyond the
separate evidence/result surfaces actually implemented.

No empirical throughput claim is frozen in SA1.

## 17. Complexity

Structural contract:

    Tree verification       = O(Tree(B))
    Trajectory verification = O(SigmaV3(B))
    DUAL verification       = O(Tree(B) + SigmaV3(B)).

Policy preflight can reject before these costs.

Selective manifest cost is the sum of:
- Tree verification for all regular files;
- trajectory verification only for files selected by explicit manifest mode.

## 18. Final disposition

Independent side oracle:

    PASS

Policy integration:

    PASS

Selective manifest policy:

    PASS

Runtime gate:

    PASS

Manual O01..O05 adversarial review:

    PASS

Final status:

    SA1 COMPLETE
