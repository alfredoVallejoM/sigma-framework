# Sigma v2.2 confirmatory preregistration

Status: **frozen**

Protocol version: `sigma-v2-2-preregistration-rc1`

Scope: EXP-01R–12R, EXP-14R and EXP-17–21R; EXP-13/16 are not applicable;
EXP-15/Psi is excluded from v2.2.

Pilot basis: [`pilot-decision-record-v2-2.json`](pilot-decision-record-v2-2.json).

This document is the complete confirmatory analysis contract. Pilot data are
development data and will never be pooled with, substituted for, or quoted as
confirmatory evidence. Editing any hypothesis, endpoint, matrix, seed,
exclusion, censoring rule or analysis after freeze invalidates every later run
and requires a new protocol version and untouched dataset.

## 1. Global execution and evidence contract

- Execute the installed `sigma-framework` wheel from outside the checkout at a
  clean exact Git tag. Archive tag, commit, wheel and wheel SHA-256.
- Every effective parameter cell is an `execution.tasks` partition with a
  public master seed and an independently derived labelled child seed.
  Preregistered repetitions/trials remain inside that cell; analysis seeds use
  a disjoint `analysis/` label.
- Archive canonical configs, frozen protocol/hash, freeze record, raw compressed
  observations, summaries, task states, all attempts/logs, environment, package
  import path and every non-self artifact hash.
- Valid terminal states are success, preregistered right-censoring, error and
  timeout. Success and censoring count as complete; error and timeout do not.
- Fixed budgets prohibit optional stopping. Exhausted search is retained as
  censored, never discarded. Negative or hypothesis-opposing outcomes are
  published with the same prominence as supporting outcomes.
- EXP-01/05/14/21 deterministic invariants require zero violations. One
  violation rejects the corresponding gate and is published as a
  counterexample; it is not averaged away.
- Statistical families use two-sided 95% intervals and Holm correction at
  family alpha 0.05 unless an exact simultaneous interval is named below.
  Report sample count, effect size, interval, censoring and all adjusted tests.
- Collision/search experiments use Kaplan–Meier curves and restricted mean
  survival time (RMST) at the fixed candidate horizon. Medians are reported
  only where estimable. Timing uses per-host robust locations and bootstrap
  intervals; hosts are not pooled as independent observations.

## 2. Exclusion, missingness and host controls

No statistical outlier deletion or imputation is allowed. A partition may be
excluded only for a recorded infrastructure error, runner exception, timeout,
artifact/hash mismatch, failed deterministic quality control, or invalid
predeclared host condition. Both the all-observed and valid-host-only analyses
are published. Warm-ups are never observations.

Performance/memory hosts must record CPU model, logical/physical cores, RAM,
OS/kernel, Python/dependency versions, affinity, governor/power mode and
start/end frequency/temperature when exposed. Timing is invalid if affinity or
requested governor cannot be applied, frequency changes by more than 10%, or
thermal throttling is reported. Memory units remain platform-native and are
converted only with the OS-specific rule recorded before execution.

Required external strata are Linux, macOS and Windows for EXP-01, and at least
two independently administered physical hosts for EXP-06/07/09/10/11/12.
EXP-08 additionally requires archived NIST SP 800-22, PractRand and TestU01
versions, exact commands, byte/bit transform and full outputs. Unavailable or
inapplicable tests are reported, not silently omitted.

## 3. Frozen matrices and primary analyses

All integer ranges are inclusive lists. The final machine-readable configs must
encode these values exactly; splitting them into tasks does not change the
design.

### EXP-01R — canonical conformance

- Matrix: all six v2.2 presets; bytes/reader/file/incremental and applicable
  mmap/multiprocessing routes; workers 1,2,3,4,8;
  adversarial/random partitions; sizes 0,1,63,64,65,65535,65536,65537, 1 MiB,
  16 MiB, 256 MiB and 1 GiB on Linux/macOS/Windows.
- Independent consumer limit: 1 MiB; larger inputs compare all primary
  backends and preserved intermediate values without loading duplicate buffers.
- Primary endpoint/criterion: byte divergences in context, anchor/evidence,
  every selected state and final digest; exactly zero.
- Output: cell coverage/divergence table and timing-by-size as secondary data.

### EXP-02R — segment collision scaling

- Matrix: widths 4,6,8,10,12; state counts 1,2,3; target rounds 1,4;
  anchor multipliers 1,2; eight stationary/indexed/anchored ×
  single/consecutive controls; 64 repetitions; horizon 1,048,576 candidates.
- Primary endpoint: candidates to first collision/right censoring.
- Primary analysis: KM/RMST and deterministic bootstrap interval for the slope
  of log2 work versus effective bits. Supporting result requires the 95% slope
  interval to contain 0.5 and lower predictive RMSE for registered
  `min(a,k*n)` than stationary-`n` and additive alternatives. Report every
  construction separately.

### EXP-03R — conditional persistence

- Matrix: widths 4,6,8; segment lengths 1,2,3; stationary, indexed, anchored
  and anchored-indexed controls; same/different anchors; 65,536 trials/cell.
- Primary endpoint: conditional equality persistence.
- Primary analysis: Clopper–Pearson intervals and likelihood/deviance against 1
  and `2^(-n*l)`, Holm-corrected within anchor-relation × construction. Cells
  with zero expected/observed events are upper limits, not point confirmation.

### EXP-04R — anchor/combiner bottlenecks

- Matrix: widths 4,6,8; branches 2,3,4; all nine implemented constructions;
  all seven implemented normal/fault/related controls; 32 repetitions; horizon
  65,536 candidates.
- Primary endpoint: first anchor/digest collision and reusable components.
- Analysis: KM/RMST by construction/fault with physical and conservative widths
  separate. Cross connections receive no additive security credit.

### EXP-05R — structural dependency

- Matrix: Wide, Deep and DeepVector v2.2; 64-byte messages; 32 samples; every
  input bit; every eighth component bit; rounds/states 4/3; bit, zero,
  permutation, omission and malformed-length interventions.
- Primary endpoint: prohibited no-op or accepted malformed structure.
- Criterion: exactly zero. Secondary outputs are Hamming distance, layer
  propagation and source/destination coverage with simultaneous intervals.

### EXP-06R — work, span and parallelism

- Matrix: Wide, Deep, DeepVector; target rounds 1,4,16,64; state counts 1,2,4;
  candidate counts 1,4,16,64; workers 1,2,4,8; 64-byte messages; 30
  repetitions/cell on each required host.
- Primary endpoints: exact primitive-query/depth identities and marginal round
  wall time. Deterministic identities require zero violations.
- Analysis: per-host Theil–Sen slope, median speedup/efficiency and bootstrap
  intervals, separating anchor cost from precomputed-anchor rounds. No PoSW,
  VDF or universal sequentiality inference is allowed.

### EXP-07R — SAC/BIC and diffusion

- Matrix: Wide, Deep and DeepVector; 64-byte messages; all input bits; sampled
  BIC output pairs at stride 8; rounds/states 4/3; exactly 700 samples/input bit
  per host (above the pilot maximum requirement of 677); two independent hosts.
- Primary endpoint: worst absolute flip bias. Secondary endpoints: BIC
  dependency, mean distance and diffusion velocity.
- Analysis: familywise simultaneous radius at alpha 0.05 and interval for the
  worst effect. A supporting outcome requires no systematic effect replicated
  on both hosts; individual significant p-values are reported and are not a
  pass/fail security test.

### EXP-08R — distribution batteries

- Matrix: SHA-512, BLAKE2b-512, Sigma Wide/Cross/Deep/DeepVector; counter,
  `ff-tail` and alternating corpora; 64-byte messages; 65,536 messages and 32
  independent streams/construction/corpus.
- Primary endpoint: complete calibrated battery result family. Internal
  frequency/runs/autocorrelation/chi-square is supplemented by NIST SP 800-22,
  PractRand through the predeclared aggregate 1 GiB per construction/corpus,
  and TestU01 SmallCrush and Crush. BigCrush is non-applicable unless separately
  frozen before any data.
- Analysis: p-value QQ/distribution and adjusted anomaly rates against standard
  hashes on identical framing. Descriptive only; passing implies no hardness.

### EXP-09R — performance

- Matrix: seven implemented constructions; full-hash, file-hot, file-cold
  (`POSIX_FADV_DONTNEED` required),
  anchor, rounds, serialization, full and local verification; sizes 0,64,4096,
  1 MiB and 16 MiB; 50 measured repetitions after 10 warm-ups; one process per
  isolated task on each required host.
- Primary endpoint: per-operation wall latency. Secondary: CPU time, valid
  operations/s or bytes/s, context switches and variability.
- Analysis: randomized order, median, MAD and host-stratified bootstrap 95%
  interval. No host pooling or ASIC inference.

### EXP-10R — memory

- Matrix: Wide/Cross/Deep/DeepVector/Tree/parallel Tree; sizes 0,64 KiB,1 MiB,
  16 MiB,256 MiB; target rounds 1,16,256; state counts 1,2,4; workers 1,2,4,8;
  trace none/full; 10 repetitions/cell. The separate LIB-02 depth task uses
  rounds 16,64,256,1024,4096 at fixed zero-byte input.
- Primary endpoint: aggregate parent+child peak RSS. Secondary: tracemalloc,
  frontier nodes and temporary disk.
- Analysis: per-OS log-log growth and bootstrap bands. `trace=none` is tested
  for zero-compatible slope versus depth; `full` is diagnostic O(t).

### EXP-11R — bounded PoW

- Protocol matrix: unique/reused challenges; difficulty 12 bits; target rounds
  1,4,16; state counts 1,2,4; 256 trials; horizon 262,144 attempts.
- Parallel matrix: difficulty 16 bits; nonce workers 1,2,4,8; target round 4;
  state count 2; 64 trials; same horizon.
- Primary endpoints: attempts distribution and zero replay/downgrade/malformed
  acceptance. Analyze geometric calibration with exact interval and per-host
  speedup. Censored searches remain in survival analysis.

### EXP-12R — equal-budget KDF composition

- Matrix: Argon2id alone and plus Wide/Deep/DeepVector; memory 19,456 and 65,536
  KiB; time cost 2,3; parallelism 1; 32 candidates and 20 repetitions/cell on
  each required host.
- Primary endpoints: guesses/s and total latency under identical Argon2id
  parameters. Report component timing and RSS. Energy is omitted unless a
  physical meter and acquisition protocol are frozen before execution.
- Interpretation: Sigma may add binding/deterministic work, never entropy or a
  new memory-hardness claim.

### EXP-14R — fault detection

- Matrix: Lightweight/Wide/Deep/DeepVector; 64-byte messages; rounds/states
  4/3; all implemented bit, omission, reorder, repeat, index, truncation,
  fold/vector and codec faults; 256 trials/cell.
- Primary endpoint: undetected fault; every verifier/codec invariant requires
  zero violations. Secondary: detection level and propagation distance. No DFA
  resistance claim.

### EXP-17 — attacker frontier

- Matrix: widths 8,12,16; anchors 2,4,8; direct table, distinguished points,
  rho, Hellman, rainbow and multicollision; table 1,024; chain 64;
  distinguished bits 4; 64 repetitions.
- Primary endpoints: online/offline queries, memory and reuse across anchors.
  Analyze time-memory frontiers and amortized cost with censored intervals.

### EXP-18 — Fold versus DeepVector

- Matrix: widths 4,6,8,10; branches 2,4; rounds/states 1,4 × 1,2,4; all six
  implemented normal/fault controls; 32 repetitions; horizon 65,536.
- Primary endpoint: collision work/RMST. Report physical, conservative and
  independence-model widths separately; no additive-branch claim.

### EXP-19 — signed commitment reuse

- Matrix: widths 4,6,8,10; three commitment shapes; rounds 1,4; states 1,2,3;
  anchor multipliers 1,2; 32 repetitions; horizon 65,536.
- Primary endpoint: candidates/queries to the exact reusable signed component.
  Ed25519 is never reduced; only Sigma's test digest is reduced.

### EXP-20R — preimage families

- Matrix: widths 3,5,7,9; anchor multipliers 1,2; states 1,2,4; target counts
  1,4,16; preimage, second-preimage and multi-target; random, exhaustive and
  inversion-table attackers; regular-image/uniform targets; simple,
  reinjected/DeepVector constructions; 32 repetitions; horizon 65,536.
- Primary endpoint: search queries/right censoring. Fit log2 median/RMST slopes
  separately by game; collision results cannot substitute for preimage claims.

### EXP-21R — domain separation and canonical framing

- Matrix: all six active presets; every registered domain pair; base, salt,
  challenge and application contexts; canonical roundtrip plus length,
  trailing, unknown, reordered and reserved-suite downgrade mutations.
- Primary endpoint/criterion: unexplained equal primitive inputs, uninfluential
  authenticated fields or accepted noncanonical mutation; exactly zero.
  Specified equal raw-branch inputs are listed separately and are not failures.

## 4. Planned outputs and figures

Every table/figure is generated from the verified canonical dataset: conformance
coverage; collision/persistence survival curves; bottleneck and dependency
matrices; work/span and speedup; SAC/BIC/diffusion; battery QQ/anomaly table;
latency decomposition; memory growth; PoW calibration; KDF budget comparison;
fault propagation; attacker time-memory frontier; Fold/Vector comparison;
signed reuse; separate preimage-family scaling; and domain-pair coverage.
Figures show intervals, repetition counts and censoring. Manual values are
forbidden.

## 5. Resource envelope and stopping

The 20-run pilot used 18,250,664 transient bytes, 36,731 observations and
54.691294 aggregate task-seconds on its development host, with peak reported
worker RSS 121,052 KiB. These are feasibility measurements, not linear runtime
promises. Before freeze, a human reviewer must approve storage/CPU allocations
for the much larger matrices above and the external-host/battery schedule.

No confirmatory cell may be removed after observing data. A campaign may stop
only for integrity failure, safety/resource limit fixed in its config, or loss
of required host controls. Restarting after a protocol or code change creates a
new dataset namespace; prior outputs remain archived as invalidated attempts.

## 6. Human freeze gate

To authorize F7, the reviewer must verify this document against generated
machine-readable configs, approve the resource envelope, change the status line
to exactly `Status: **frozen**`, provide identity and timezone-aware review
timestamp, and generate `configs/confirmatory-frozen/freeze.json` with
`python -m experiments.freeze`. Until all hashes verify, F7 is blocked by
design.
