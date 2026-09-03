# Claim-to-evidence traceability

Current line: Sigma `2.2.0a1`. Engineering gates F0–F6 are closed; the
confirmatory protocol and 20 configurations are hash-frozen and F7 is in
progress. Production and security-review gates remain open; see
[`project-status-2026-09-03.md`](project-status-2026-09-03.md).

Pilot measurements are not evidence in this matrix. “Confirmatory pending”
means the mechanism and analysis path exist but the sole canonical dataset has
not been generated.

| Claim or boundary | Formal obligation | Current executable evidence | Status |
|---|---|---|---|
| Accepted encodings are injective | FORM-02 / TH-01 | normative KAT, parser negatives, property/fuzz/mutation tests | internally argued; external review pending |
| Same suite/input is backend invariant | G-CONFORM / TH-01 | differential adapter/backend matrix and independent consumer | local gate met; confirmatory OS matrix pending |
| Retained roots preserve one-sound-branch collision resistance | FORM-03 / TH-02 | roots/evidence vectors and branch failure controls | conditional reduction; assumptions need review |
| Cross connections add no automatic strength | FORM-03 / TH-02 | original roots retained; EXP-04 analysis separates physical/conservative width | explicit claim boundary; confirmatory pending |
| Unequal anchors do not automatically coalesce | FORM-04 / TH-03 | exact stationary/indexed/anchored control tests | conditional RO theorem; confirmatory pending |
| Consecutive-state collisions are capped by anchor strength | FORM-05 / TH-04 | EXP-02/03 survival/exact analysis tests | conditional bound; confirmatory pending |
| Collision, preimage and second-preimage are distinct | FORM-06 / TH-05/06 | EXP-20 separate games, target types and attackers | no cross-substitution; confirmatory pending |
| Input entropy cannot be created | FORM-06 / TH-06 | KDF KAT, independent binding and equal-budget EXP-12 runner | Argon2id supplies memory hardness; confirmatory cost pending |
| Evaluators have the specified adaptive DAG | FORM-07 / TH-07 | exact query accounting and concurrent scheduler equivalence | no universal sequentiality claim |
| Deep fold caps scalar state | FORM-08 | branch-vector/fold intermediate differential checks | limitation explicit |
| DeepVector retains component equality obligations | FORM-08 | independent component/level matrix and KAT | conservative selected-branch argument only |
| Signed attestation authenticates only its declaration | FORM-09 / TH-08 | Ed25519 vector, independent signer and forged-history counterexample | key policy/external review pending |
| Full signed verification binds message and recomputed history | FORM-09 / TH-08 | positive/negative full verification tests | conditional composition argument |
| One valid edge is not trajectory proof | FORM-09 / TH-08 | arbitrary-state adjacent-verifier counterexample | explicit prohibition |
| PoW predicates implement configured reduced acceptance | application model | independent vector and protocol-negative tests | not PoSW/VDF; confirmatory calibration pending |
| StreamWide/TreeWide obey expected memory structures | algorithmic invariant | incremental/frontier invariants and aggregate-memory runner | multihost confirmatory measurement pending |
| Cross-anchor reuse is disrupted by indexed reinjection | FORM-04 / TH-03 | EXP-17 six-attacker controls | scaled frontier pending |
| Fold and DeepVector widths must be reported separately | FORM-08 / TH-07 | EXP-18 fault/segment runner | joint independence is not assumed |
| Signed-state reuse targets exactly signed components | FORM-09 / TH-08 | EXP-19 component-specific runner | Ed25519 is never reduced |
| Registered domains/framing reject confusion/downgrade | FORM-02 / TH-01 | EXP-21 primitive-input/codec matrix and parser tests | deterministic confirmatory matrix pending |
| Distribution/diffusion implies no hardness | claim prohibition | EXP-05/07/08 runners and analysis contracts | descriptive only |
| Fault detection is not DFA resistance | claim prohibition | recomputation, codecs and EXP-14 runner | fault coverage only |
| Constant-time/leakage resistance | native core + EXP-13 required | none | prohibited |
| ASIC/energy resistance | RTL + EXP-16 required | none | prohibited |

FORM-01..09 have explicit games/models and boundaries in
`specification/security-analysis.md`. Literature completeness, novelty,
cryptographic judgment and external reproduction cannot be self-certified.
After F7, this file must replace every “confirmatory pending” entry with the
canonical dataset location, config/hash, analysis output and exact permitted
claim—including negative, null and censored outcomes.
