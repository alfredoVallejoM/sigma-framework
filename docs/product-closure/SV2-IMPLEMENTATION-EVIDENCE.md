# SV2 — Verification Policy Implementation Evidence

Status: **CANDIDATE — SEMANTIC IMPLEMENTATION/REVIEW COMPLETE; RUNTIME GATE PENDING**  
Reviewed implementation baseline: `2c47a2fff90e1000b20e6917e574df29cb2dc238`  
SV0 baseline: `03f8663c12187388c3e67de6958bd58921aaa45b`  
Date: 2026-09-22

## 1. Scope

SV2 adds canonical product policy and an explicit four-way decision model.

Implemented:
- `sigma/trajectory/policy_v1.py`;
- public exports;
- unit/property/vector tests;
- `scripts/product_closure/sv2_gate.py`;
- frozen policy identity vectors.

It does not alter digest/evaluation semantics.

## 2. Policy wire

Magic:

    SIGPOLY1

Policy format version:

    1

Strict TLV fixes:
- v3 suite allowlist;
- history requirement;
- legacy opt-in;
- message-binding requirement;
- Audit/Tree/DUAL/signature/provenance requirements;
- input/round/tree-proof/memory bounds;
- metadata profiles;
- symlink mode.

All lists are canonical sorted/unique tuples.

## 3. Stable PolicyId

Content identity:

    SHA256(canonical policy wire).

This is explicitly a deterministic content ID, not a security-width claim.

Frozen KAT IDs:

default:

    40955b5f49245614b2e9c7af5290725b47beee193a837e2247c17b3991073fbb

strict-history-audit:

    7d4965139e126e60ffae4d0d1746ab61cac1e08600b265fdb7fe06e638ed470a

weak-all-v3:

    730333e62dbfd83fc5321b7f24a23634576ab9951b8bc3aa31f37ab68b6c62be

legacy-opt-in:

    990f24a64501efc5d24f829784fd2c26c1c5334870d9c10a23d23bd70bab82bf

## 4. Parse/accept separation

`parse_verification_evidence_v1` supports:
- SigmaDigestV3;
- TrajectoryAuditV3;
- SigmaDigestV2/v2.2.

Parsing does not consult policy.

A valid evidence object can subsequently be rejected by suite/history/resource
or capability requirements.

## 5. Four-way decisions

`VerificationDecisionV1.kind` is exactly one of:

    Accepted
    Rejected
    Inconclusive
    Unsupported.

Stable codes distinguish reasons.

Examples:
- correct permitted source -> Accepted;
- disallowed suite/oversize/wrong source -> Rejected;
- source or resource estimate required but missing -> Inconclusive;
- unknown/future evidence kind -> Unsupported.

## 6. Cheap checks first

Preflight order precedes expensive source replay.

Tests/gate use bomb verifiers/sources to ensure an oversized committed input is
rejected without iterating the source or invoking full v3 verification.

This is a semantic work-order guarantee, not a benchmark claim.

## 7. Capabilities bridge to Artifact

`VerificationCapabilitiesV1` carries facts that SA0/SA1 will later derive from
SigmaArtifact:
- Tree evidence presence/size;
- signature;
- provenance;
- metadata profile;
- symlink presence;
- working-memory estimate.

This avoids changing PolicyId when Artifact support lands.

Known missing mandatory evidence -> Rejected.

Missing estimate needed for an active resource bound -> Inconclusive.

## 8. Legacy control

Default policy:

    allow_legacy_v22=false.

Therefore valid v2.2 evidence is rejected before full verification.

Explicit opt-in can accept valid v2.2 bytes.

Legacy cannot satisfy history-feedback or trajectory-audit requirements.

## 9. Determinism and monotonicity

Determinism:

    same evidence + policy + capabilities + verifier/source
      => same VerificationDecisionV1.

Normalized partial order:

    policy_is_stricter_or_equal_v1(strict,weak).

The property suite/gate require:

    Accepted(strict,x)
      => Accepted(weak,x)

for generated pairs in the defined subset.

## 10. Codec/adversarial coverage

Tests cover:
- missing/duplicate/reordered/unknown policy fields;
- parse-valid but suite-disallowed evidence;
- all four decisions;
- malformed known evidence;
- cheap oversized rejection;
- wrong source;
- DUAL requirement;
- signature requirement;
- provenance requirement;
- symlink rejection;
- unknown memory estimate;
- default legacy denial and explicit opt-in.

## 11. Gate prepared

`sv2_gate.py` requires:
- >=400 deterministic policy decisions;
- >=100 monotonic strict/weak cases;
- >=100 cheap-reject bomb-source cases;
- exact four-way coverage;
- policy codec/PolicyId round-trip;
- deterministic decisions;
- legacy default reject/opt-in accept;
- future evidence Unsupported;
- DUAL capabilities enforcement.

No timing/throughput criterion is part of this semantic gate.

## 12. Complexity status

Structural contract:

    parse/preflight = O(policy wire + evidence codec/header)

and cheap rejection occurs before source replay.

If message binding is required:

    total cost = selected underlying verifier cost.

Policy throughput/latency/memory distributions are deliberately deferred to the
future empirical campaign.

## 13. Obligation disposition

SV2-O01 parse != accept — **CANDIDATE PASS**  
SV2-O02 explicit four-way decision — **CANDIDATE PASS**  
SV2-O03 cheap checks precede expensive work — **CANDIDATE PASS**  
SV2-O04 deterministic decision — **CANDIDATE PASS**  
SV2-O05 normalized stable PolicyId — **CANDIDATE PASS**  
SV2-O06 monotonic normalized subset — **CANDIDATE PASS**  
SV2-O07 legacy requires explicit opt-in — **CANDIDATE PASS**

Runtime gate execution remains pending.

## 14. Adversarial design findings

Finding A — reusing old v2 ResourcePolicy would conflate version axes  
Status: **REJECTED**; VerificationPolicyV1 has its own wire/version.

Finding B — Artifact requirements could force a future PolicyId break  
Status: **FIXED** via VerificationCapabilitiesV1.

Finding C — missing source could be silently treated as verification success  
Status: **FIXED** via Inconclusive(SourceRequired).

Finding D — over-budget checks could happen after evaluation  
Status: **FIXED** by explicit preflight order/bomb tests.

Finding E — default legacy acceptance would blur frozen/transitional boundary  
Status: **FIXED**; v2.2 opt-in is explicit.

No unresolved design blocker remains.

## 15. Isolation review

SV2 is additive and does not modify:
- v2.2 wire/suites;
- v3 suites/domains/evaluation;
- Tree;
- Audit/checkpoint semantics.

Legacy verification calls the existing frozen v2.2 verifier only after policy
opt-in.

## 16. Promotion requirement

Current correct state:

    SV2 CANDIDATE

Promotion to COMPLETE requires:
1. SV0 COMPLETE;
2. run `python -m scripts.product_closure.sv2_gate --report .sigma/sv2-gate.json`;
3. focused SV2 unit/property/vector tests PASS;
4. post-execution O01..O07 review.

Empirical policy-performance data is intentionally postponed.
