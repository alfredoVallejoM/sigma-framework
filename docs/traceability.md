# Claim-to-evidence traceability

This matrix distinguishes an implemented mechanism, an internally reviewed
argument, experimental evidence and an external security conclusion. Passing a
test or smoke experiment never upgrades the final column by itself.

| Claim | Obligation | Implementation | Executable/empirical evidence | Current status |
|---|---|---|---|---|
| Accepted encodings are injective | FORM-02 / TH-01 | `sigma/spec`, evidence/digest/application codecs | KAT corpus, parser negatives, property/fuzz/mutation tests | internally argued; external review pending |
| Same suite/input is backend invariant | G-CONFORM / TH-01 | serial, incremental, mmap, multiprocessing, Deep schedulers | differential matrix + independent consumer; EXP-01 smoke | repository gate met; OS matrix pending |
| Retained roots preserve one-sound-branch collision resistance | FORM-03 / TH-02 | StreamWide, CrossWide, TreeWide | independent roots/evidence, failure controls | reduction stated; assumptions need review |
| Cross connections add no automatic strength | FORM-03 / TH-02 | original roots retained alongside connections | KAT and EXP-04 smoke | explicit conservative boundary |
| Unequal anchors do not automatically coalesce | FORM-04 / TH-03 | complete anchor reinjection | exact control tests; EXP-03 smoke | conditional RO theorem stated |
| Segment collisions require repeated equalities up to anchor bottleneck | FORM-05 / TH-04 | consecutive published states | reduced models EXP-02/03 smoke | conditional bound; confirmatory pending |
| Second preimage is separate from collision | FORM-06 / TH-05 | full verifier recomputes all levels | EXP-20R random/exhaustive/table pilot | theorem decomposition; scaled confirmation pending |
| Target preimage is separate from collision | FORM-06 / TH-06 | no special shortcut claimed | EXP-20R regular/uniform targets | regular-image model only, no reduction claimed |
| Input entropy cannot be created | FORM-06 / TH-06 | Argon2id before Sigma | KDF KAT, independent binding, EXP-12 smoke | deterministic argument; Argon2 supplies memory hardness |
| Per-candidate evaluation has the specified adaptive DAG | FORM-07 / TH-07 | WideOnce, Deep, DeepVector | exact query accounting, scheduler equality, EXP-06 smoke | evaluator span established; no universal sequentiality claim |
| Deep fold caps scalar state and needs its own assumption | FORM-08 | Deep branch vector then SHA3-512 fold | fault backends, differential intermediates | limitation explicit |
| DeepVector retains component equality obligations | FORM-08 | full vector consumed and published | independent component/level matrix, KAT | conservative selected-branch argument stated |
| Signed attestation authenticates only the declaration | FORM-09 / TH-08 | Ed25519 signed commitment | frozen vector, independent signer, forged-history counterexample | EUF-CMA reduction stated; key policy external |
| Full signed verification binds message/history | FORM-09 / TH-08 | signature + full recomputation | positive/negative full verification tests | composition argument stated |
| One valid edge is not trajectory proof | FORM-09 / TH-08 | deliberately separate verifier semantics | arbitrary-state counterexample test | explicit limitation |
| PoW predicates have configured reduced acceptance probability | application model | `applications/pow.py` | independent vector + EXP-11 smoke | protocol implemented; not PoSW/VDF |
| StreamWide memory is constant in message size | algorithmic invariant | incremental branch hashers | EXP-10 smoke | tested locally; confirmatory pending |
| TreeWide memory is logarithmic in leaves | algorithmic invariant | frontier reducer | unit invariant + EXP-10 smoke | tested locally; confirmatory pending |
| Cross-anchor work is not automatically reusable after reinjection | FORM-04 / TH-03 | indexed anchor reinjection | EXP-17 six-attacker reduced pilot | stationary control separates reuse; scaled frontier pending |
| DeepVector retains physical branch components; Fold has a narrow successor | FORM-08 / TH-07 | `Deep`, `DeepVector` | EXP-18 segment/fault pilot | physical/conservative/joint widths separate |
| Signed-state reuse reduces to collision of exactly the signed commitment | FORM-09 / TH-08 | signed commitment profiles | EXP-19 component-specific pilot | Ed25519 is never artificially reduced |
| Collision, preimage, second-preimage and multi-target exponents are distinct | FORM-06 / TH-05/06 | reduced trajectories | EXP-20 three-game/three-attacker pilot | slopes underpowered; target classes remain separate |
| Registered domains/framing do not collide and suite downgrade changes context identity | FORM-02 / TH-01 | domain tags, TLV, closed suites, opt-in capture | EXP-21: 52,820 primitive-pair checks | zero pilot violations; exhaustive mutations pending |
| Distribution/diffusion observations imply no hardness | claim prohibition | experiment runners | EXP-05/07/08 smoke | descriptive only |
| Fault detection is not DFA resistance | claim prohibition | recomputation and typed codecs | EXP-14 smoke | fault coverage only |
| Legacy `Psi` is non-bijective | pigeonhole fact only | `experimental/psi.py` | EXP-15 smoke | no collision-resistance claim |
| Constant-time / leakage resistance | requires native core + EXP-13 | none | none | prohibited |
| ASIC/energy resistance | requires RTL + EXP-16 | none | none | prohibited |

## Gate accounting

- FORM-01..09 have a concrete game, theorem/model and claim boundary in
  `specification/security-analysis.md`.
- FORM-10 has a primary-source comparison set, but completeness of the
  literature review and novelty judgment remain human-review obligations.
- Historical smoke and revised pilot references validate code paths and sizing
  only. They must be replaced by task-level, preregistered, clean-tag results
  before manuscript result claims are updated.
- External review cannot be self-certified. Review reports and resolution links
  must be added here before any production-security claim.
