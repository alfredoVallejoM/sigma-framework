# Sigma v3 R14.1 / R15 confirmatory preregistration

Status: **frozen-r14.1-candidate**

Freeze ID: `sigma-v3-r14-20260921-v2`  
Required tag: `sigma-v3-r14-freeze-v1`  
Confirmatory namespace: `sigma-v3-r15`  
Confirmatory data observed: **no**

This preregistration supersedes the preliminary R14 sampling matrix before any
R15 confirmatory seed was consumed. It changes experimental scale, executors,
analysis precision and data handling; it does not change Sigma R12.5 semantics.

## 1. Immutable construction baselines

- R12.5: `5ac306bb23acae0e0a4ef03eb56b3062343c2127`.
- R13: `8a71de3d350ea8215c481e16c9eadbeed54066ef`.
- R12 remains the fixed-binding ablation.
- No suite/domain/frame/wire/KAT/corpus change is authorized by R14.1.

## 2. Confirmatory attack set

The R15 attack IDs remain exactly:

- HIST-01, HIST-02, HIST-03, HIST-05, HIST-06;
- RED-02, RED-03, RED-04, RED-05;
- TMTO-01, TMTO-02;
- PARAM-01..06;
- LAYOUT-04;
- BRANCH-05, BRANCH-06;
- STAT-01.

No post-data attack may be promoted into R15 without opening a distinct
campaign/freeze.

## 3. Publication-scale doctrine

The normative scale source is
`experiments/r15-publication-scale-plan.json`.

Primary scaling curves require at least six estimable points and normally use
2-bit spacing. Stress/censoring points are marked separately and are not
silently pooled into slope fits.

Primary confidence level:

[
95%.
]

Rare/zero-event security boundaries additionally report:

[
99%	ext{ one-sided upper bounds}.
]

Power target where meaningful:

[
95%.
]

Exceptional minimum:

[
90%.
]

Primary deterministic bootstrap:

[
B=10,000.
]

## 4. History campaigns

HIST-01 contains two predeclared modes:

1. natural crossings, measuring crossings found in generated trajectories;
2. conditional crossings, directly sampling equal visible state with unequal
   histories to measure the non-coalescence mechanism.

Conditional batches contain 1,024 trials and 256 batches/cell.

HIST-03 separates collision, second-preimage, fixed-point and cycle games.

HIST-06/LAYOUT-04 compare exactly:

- fixed;
- values-only;
- adaptive.

## 5. REDUCED campaigns

RED-02 uses a k-dependent dense grid with a deterministic budget rule:

[
Q_{max}=min(2^{22},lceil4cdot2^{kn/2}ceil).
]

Cap-limited cells are stress cells.

RED-03/04 use n=4,6,8,10 as estimable widths and n=12,14,16 as
stress/lower-bound widths.

RED-05 uses:

[
uin{1,2,4,8,16,32,64}.
]

## 6. TMTO

Widths:

[
8,10,12,14,16,18.
]

Strategies:

- direct;
- distinguished;
- rho;
- Hellman;
- rainbow.

The primary representation is the Pareto frontier in offline work, online work
and memory. No scalar score is introduced after data.

## 7. Parameter campaigns

PARAM-01:

- 186,000 samples/replicate;
- 64 replicates;
- 2,000 expected observations per ideal joint (t,k) cell.

PARAM-02:

- 32,768 observations/replicate;
- 128 replicates;
- 5,000 deterministic permutations;
- 6-bit candidate bucket and 6-bit persistent bucket;
- outcome variable is the joint pair (t,k).

PARAM-03 candidate budgets:

93, 186, 465, 930, 1,860, 4,650, 9,300.

## 8. KDF

Three treatments:

1. Argon2id only;
2. Argon2id + complete Sigma for every guess;
3. Argon2id + derive public (t,k), then skip complete Sigma when the wrong
   guess's trajectory parameters differ from the target.

This replaces the ambiguous preliminary phrase "fixed-cost Sigma" with an
executable full-Sigma baseline before confirmatory data.

Publication scale:

- 3 physical hosts;
- 256 paired replicates/host;
- 4,096 guesses/replicate.

Argon2id retains all entropy/memory-hardness attribution.

## 9. PoW

The paired treatments are:

1. full evaluation of every nonce;
2. parameter preparation for every nonce, explicit cheapest-cost selection,
   then complete evaluation of the selected nonce.

Selection work is included in the treatment cost.

Publication scale:

- 3 physical hosts;
- nonce budgets 4,096 and 16,384;
- 512 paired replicates/host/budget.

No VDF/PoSW/ASIC claim is introduced.

## 10. Mitigations

Exactly:

- input-derived;
- context-fixed with t=17,k=3;
- cost-bucketed with upper cost bounds 8,16,24,35.

No fourth mitigation may be created in response to R15 outcomes.

## 11. Deep / DeepVector

BRANCH-05 retains the eight frozen branch/fold faults.

BRANCH-06 uses explicit one-component interventions and measures:

- affected branches;
- all-branches-affected rate;
- Hamming distance;
- first divergence.

## 12. STAT-01 data volume

24 construction/corpus cells.

Each cell has:

- 64 deterministic stream identities;
- 64 MiB per stream;
- 4 GiB logical processed volume/cell.

Total logical processed volume:

[
96	ext{ GiB}.
]

These bytes are **not retained**.

The batteries are:

- NIST STS;
- PractRand;
- TestU01 SmallCrush;
- TestU01 Crush.

The same logical stream identity is reused/regenerated for external tools.
BigCrush is not part of this freeze.

### Exact stream semantics

The normative generator is `experiments/r15_stat_streams.py`.

Each logical stream uses a 32-byte seed derived from
`(freeze_id, construction, corpus, stream_id)`. Messages are exactly 128
bytes:

- `counter`: seed || uint64(counter) || zero padding;
- `ff-tail`: seed || uint64(counter) || 24 zero bytes || 64 0xFF bytes;
- `alternating`: seed || uint64(counter) || 88 bytes of 0xAA,0x55 alternation.

Standard controls emit exactly 64 raw digest bytes per message:

- SHA-512;
- SHA3-512;
- BLAKE2b-512;
- SHAKE256 with 64-byte extraction.

The deliberately broken control emits the first 32 bytes of SHA-512 twice,
preserving marginal hash-like bytes while introducing an explicit repeated-half
dependency.

Sigma constructions use fixed per-stream context derived from the stream seed
and emit only raw trajectory window state bytes, concatenated in canonical
state order:

- R12.5 WideOnce history suite;
- R12.5 Deep history suite;
- R12.5 DeepVector history suite.

No context/frame/digest-envelope bytes are mixed into the pseudo-random stream.
The generator continues message counters until exactly the declared stream byte
length has been emitted, truncating only the final output block if necessary.
Chunking/pipe boundaries are operational only and must not change stream bytes
or SHA-256.

## 13. Storage/provenance policy

Normative policy:
`experiments/r15-data-policy.json`.

Processed volume is not retained volume.

Large streams:

- are deterministic;
- have full SHA-256;
- have chunk SHA-256;
- are consumed by pipe/callback where possible;
- otherwise use one temporary file at a time;
- are never committed to Git.

Scratch ceilings:

- 10 GiB general;
- 2 GiB preferred STAT.

Canonical numeric records are append-only. Each RunKey is immutable and has
one canonical record plus receipt. A deterministic post-hoc ledger binds all
records.

## 14. Terminal states

Exactly:

- success;
- no-success;
- censored;
- timeout;
- error.

Timeout is not no-success. Error is never silently excluded. Censoring requires
a reason. No optional stopping is permitted.

## 15. Analysis implementations

The normative implementations are in
`experiments/r15_estimators.py`.

Frozen methods include:

- Clopper-Pearson;
- 99% zero-event upper bound;
- Kaplan-Meier;
- Q50;
- RMST;
- deterministic percentile bootstrap;
- paired bootstrap ratios;
- Holm adjustment;
- exact Pareto dominance.

PARAM-02 uses the separately frozen deterministic permutation implementation.

## 16. R15 data integrity

Each future run is identified by:

[
(freeze_id,attack_id,cell_id,replicate_id).
]

Seeds are derived deterministically from that RunKey.

Duplicate canonical RunKeys are invalid.

Raw record writes are atomic. Dataset completion requires:

[
ExpectedRunKeys=ObservedRunKeys.
]

## 17. Unlock condition

### Pre-data staged-unlock amendment

This amendment was frozen **before any R15 confirmatory seed or observation was
consumed**. It changes only authorization granularity. It does not change any
attack, cell, factor, sample size, seed derivation, estimator, endpoint, stopping
rule, censoring rule or multiplicity rule.

Every confirmatory scope requires:

1. R14.1 protocol gate PASS;
2. R14.1 source/runtime freeze bundle PASS;
3. exact tag `sigma-v3-r14-freeze-v1` points to the audited source commit;
4. runtime wheel SHA matches the R14.1 runtime manifest;
5. generated config manifest matches;
6. the preregistration and dependency-lock hashes match the runtime manifest.

Authorization is then staged by resource class:

- **internal**: HIST-01/02/03/05/06, RED-02/03/04/05, TMTO-01/02,
  PARAM-01/02/03, LAYOUT-04, BRANCH-05/06. No physical-host or external-battery
  manifest is required because these are deterministic software experiments.
- **physical**: PARAM-04/05/06. In addition to the common requirements, a
  ready registry of at least three concrete physical hosts is mandatory.
- **stat**: STAT-01. In addition to the common requirements, a ready manifest
  for NIST STS, PractRand, TestU01 SmallCrush and TestU01 Crush, including
  version and binary SHA-256, is mandatory.
- **full**: requires both the physical-host and external-tool manifests and
  authorizes the union of all 21 attack families.

Each execution manifest records its scope and exact `authorized_attacks`.
A runner must reject any attack not explicitly authorized by the execution
manifest. Staging therefore cannot weaken the frozen host or external-tool
requirements for the campaigns that depend on them.

No scope may be unlocked if pre-existing unregistered confirmatory data is
present in the checkout.

## 18. Publication interpretation

R15 PASS means campaign completeness and integrity, not a favorable security
outcome. Negative, censored, timeout and error records remain part of the
scientific archive.

R16 remains responsible for independent reproduction and external
cryptographic review.
