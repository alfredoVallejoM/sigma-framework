# Sigma v2-2 confirmatory preregistration ledger

Status: **draft; not frozen; no confirmatory data authorized**  
Protocol basis: `docs/research-addendum-v2-2.md`, sections E–H.  
Pilot data are development data and will never be pooled with confirmatory data.

## Global analysis contract

Each cell/repetition is an `execution.tasks` partition with an independently
derived child seed. Generation and analysis labels use disjoint suffixes.
Configs become immutable only in a dedicated signed tag after pilot resource
estimates and internal review. A publishable invocation uses
`--require-clean-tag` and an `artifact_path` pointing at the installed wheel.

- Primary population: every configured task, including negative, exhausted and
  right-censored outcomes.
- Exclusions: only a recorded infrastructure error, timeout, invalid host
  control or preregistered warm-up. Both included and excluded analyses are
  published; statistical outlier deletion is forbidden.
- Missingness: no imputation. Error/timeout makes `execution_complete=false`;
  a preregistered right-censored observation is complete.
- Multiplicity: deterministic invariants require zero failures. Statistical
  families use Holm correction unless the experiment declares an exact
  simultaneous interval. Descriptive battery p-values are never security
  acceptance tests.
- Estimation: publish sample count, effect size and 95% interval. Collision and
  search studies use Kaplan–Meier medians/intervals when censored. Timing uses
  per-host robust location and bootstrap intervals; hosts are not pooled as
  independent repetitions.
- Stopping: fixed task count and candidate/byte/time budgets. No optional
  stopping after inspecting effects. A resource pilot may alter this draft,
  but invalidates all prior candidate-confirmatory output.
- Provenance: config, raw rows, task partitions/logs, summary, environment,
  exact tag, wheel hash and all non-self artifact hashes are mandatory.

## Operational campaign ledger

| ID | Primary endpoint | Confirmatory criterion | Partition key | Implementation state |
|---|---|---|---|---|
| EXP-01R | byte divergences | exactly zero | suite × adapter × size × partition × workers × OS | six-suite local pilot integrated; large inputs and OS matrix pending |
| EXP-02R | collision-work survival curve | registered model comparison and slope CI contains 0.5 | construction × n × a × k × repetition | four controls, KM/RMST, model RMSE and deterministic bootstrap slope implemented; sample grid pending |
| EXP-03R | conditional persistence | exact interval/LR against the two registered probabilities | construction × anchor relation × n × length | four controls, independent trial oracles, exact interval/LR and Holm implemented; power grid pending |
| EXP-04R | anchor/digest collision work | report bottleneck and reuse without additive CrossWide claim | construction × fault/relation × n × branches × repetition | nine constructions, seven faults, related-anchor controls and physical/conservative widths implemented; scaled grid pending |
| EXP-05R | invariant violations | exactly zero prohibited no-op or accepted malformed structure | intervention × source bit × layer × sample | Wide/Deep/DeepVector bit and structural matrix (roots, connections, evidence length, context fields) implemented; scaled sampling pending |
| EXP-06R | work/span and time | exact count identities; timing effects with intervals | mode × t × k × candidates × workers × repetition | v2-2 exact counts, precomputed-anchor round timing, Theil–Sen slope and speedup implemented; controlled multihost runs pending |
| EXP-07R | worst flip bias/BIC | interval-based, no zero-significance rule | layer/round × input family × output pair × sample | three-mode SAC/BIC, simultaneous radius, power adequacy and per-branch diffusion velocity implemented; powered execution pending |
| EXP-08R | calibrated battery anomaly | descriptive full-family report | construction × corpus × state/domain × battery × stream | independent v2-2 streams and internal calibration implemented; NIST/PractRand/TestU01 execution gated by unavailable tools |
| EXP-09R | latency/throughput | effect and interval per host/operation | host × operation × mode × size × repetition | v2-2 operation matrix, CPU/context-switch metrology and valid rate units implemented; cold-cache, signed verification and multihost runs pending |
| EXP-10R | peak aggregate memory | growth model and interval | mode × size × t × k × workers × trace × repetition | v2-2 mode/trace grid and Linux aggregate parent+children sampling implemented; larger grid and cross-platform RSS normalization pending |
| EXP-11R | attempts/verification cost | geometric calibration and zero protocol invariant failures | predicate × challenge reuse × difficulty × t × k × repetition | replay/downgrade/tamper/resource attacks and right-censored pilot implemented; nonce-worker scaling pending |
| EXP-12R | guess rate/cost | budget-matched effect; no entropy/memory-hardness claim | Argon2 profile × Sigma mode × corpus × repetition | Wide/Deep/DeepVector v2-2 use the identical Argon2 budget with component timing; calibrated total-budget and physical energy runs pending |
| EXP-13 | none | blocked until specified native core | — | blocked by design |
| EXP-14R | detection/propagation | report detection rate and propagation levels; no DFA claim | fault × location × mode × repetition | bit, omission, reorder, index, repeat, truncation and fold/vector corruption matrix implemented; production grid pending |
| EXP-15 | historical control | no production-security promotion | reduced Psi analysis cell | separate, partial |
| EXP-16 | none | blocked until RTL/toolchain/corner exist | — | blocked by design |
| EXP-17 | cross-anchor reuse/TM frontier | effect/interval for each registered attacker | attacker × n × anchors × memory/chain × repetition | direct, distinguished, rho, Hellman, rainbow and multicollision reduced attackers implemented; scaled frontier pending |
| EXP-18 | Fold/Vector collision work | separate physical width, conservative bound and joint model | mode × fault × n × branches × t × k × repetition | consecutive reduced trajectories, six faults, query work and censored RMST implemented; scaled grid pending |
| EXP-19 | signed commitment reuse work | bound exactly the signed components | commitment × anchor width × n × t × k × repetition | reduced reuse event, search/verification queries, physical and bottleneck widths implemented; Ed25519 remains unreduced |
| EXP-20R | preimage-family search work | separate fits for preimage, second-preimage and multi-target | game × attacker × target kind × construction × a × n × k × targets × repetition | random/exhaustive/table search, censored RMST, query classes and per-game fits implemented; scaled widths pending |
| EXP-21R | framing/domain violations | exactly zero unexplained collisions or policy confusion | primitive × origin-domain × destination-domain × context mutation × suite/version | opt-in real primitive-input matrix plus codec/downgrade audit implemented; exhaustive mutation grid pending |

## Freeze gates

R4 remains open until every applicable row has: a machine-readable task matrix;
pilot CPU/RAM/disk and censoring rates; a fixed sample-size justification;
implemented analysis code tested on synthetic null/effect data; and internal
review sign-off. EXP-13 and EXP-16 remain non-applicable until their technical
dependencies exist. External OS/host runs and cryptographic review are human or
infrastructure dependencies and cannot be satisfied by local green tests.
Pilot envelopes are generated by `scripts.estimate_campaign_budget`; its RSS
field deliberately retains platform-native units and may not be pooled across
operating systems without the conversion fixed in the protocol.

Initial two-task local envelopes (development host, not transferable) measured
EXP-02R at 768 observations and EXP-03R at 12,288. Linear extrapolation to 1,000
tasks was about 192 MB/147 serial seconds and 1.36 GB/184 serial seconds,
respectively. These figures expose raw-partition storage as a planning factor;
they are feasibility measurements, not frozen budgets.
