# Sigma v3 R15 — traceability

Fecha: 2026-09-21.  
Estado: **R15 CONFIRMATORY ACQUISITION ACTIVA; application benchmarks reclasificados como exploratory engineering**.

R15 queda dividido en ejecución secuencial. Antes de cualquier dato
confirmatorio debe cerrarse R14.1 porque el candidato R14 técnico original no
congeló todavía toda la implementación de endpoints ni la escala de publicación.

| Etapa | Objetivo | Estado |
|---|---|---|
| R15-0A | execution closure | **PASS** — 21/21 executors |
| R15-0B | publication-scale volume/interval freeze | **PASS** — 406 cells / 153,536 run units |
| R15-0C | streaming/storage/provenance freeze | **PASS** |
| R14.1 | regenerate/refreeze/re-audit | **TECHNICAL PASS** — CI/bundle green |
| TAG-01 | exact final freeze tag | **PASS** — `sigma-v3-r14-freeze-v1` -> `80214af...` |
| R15-A | staged unlock/preflight | **INTERNAL ACTIVE; mandatory full now = internal + STAT only** |
| R15-B | harness validation | **PASS** — 7 tests / 11 adversarial checks |
| R15-C | structural acquisition | **REAL ACQUISITION BLOCKED; 33-cell shadow battery launched** |
| R15-D | reduced cryptanalysis | **REAL ACQUISITION BLOCKED; 32-cell shadow battery launched** |
| R15-E | KDF/PoW/mitigation | **EXPLORATORY ENGINEERING LAUNCHED; excluded from R15 PASS/core claims** |
| R15-F | external STAT | **REAL BATTERIES BLOCKED; 24-cell exact-stream shadow launched** |
| R15-G | locked analysis | **REAL ANALYSIS BLOCKED; 15-figure/9-table synthetic rehearsal launched** |
| R15-H | adversarial data audit | **REAL AUDIT BLOCKED; synthetic complete-dataset audit launched** |
| R15 closure | dataset + review + handoff R16 | **not blocked by physical hosts; STAT remains external requirement** |

## Publication-scale doctrine

Primary curves target 6–8 estimable points, usually 2-bit spacing, plus stress
points where useful. Cheap reduced campaigns use hundreds to ~1,000 replicates
per point; physical paired campaigns use hundreds per host; rare events use
large conditional-exposure counts.

Primary results require 95% confidence intervals. Rare/zero-event security
boundaries additionally report 99% one-sided upper bounds. Power target is 95%
where meaningful.

## Data doctrine

Processed bytes are not retained bytes. Large STAT streams are deterministic,
hashed and consumed incrementally. Git stores code/config/manifests/results, not
large generated streams.

Scratch targets:

- default <=10 GiB;
- preferred STAT <=2 GiB.

Final retained scientific dataset target: approximately 1–5 GiB or less.

## No confirmatory execution

Until R14.1 PASS + exact TAG-01:

- no `sigma-v3-r15` seed may be consumed for measurement;
- no result may be labelled confirmatory;
- no publication-scale config may be altered based on observed R15 outcomes.

Governing plan: `docs/r15-confirmatory-campaign-plan.md`.


## Estado técnico observado antes de R15-B

Último baseline verde antes de la batería R15-B:

- HEAD `00c2e172b81fb9c45df4cd9ab70fe72f3606a39b`;
- CI run `35548277304`: PASS;
- 1033 tests passed, 1 skipped;
- R14.1 protocol: 21 attacks, 406 cells, 153,536 run units;
- regions: 240 estimable, 92 exhaustive, 32 stress, 18 paired, 24 descriptive;
- R15-0A execution closure: PASS;
- R15-0C data closure: PASS;
- R14.1 source/runtime freeze bundle: PASS;
- R15-A static preflight: PASS;
- confirmatory_unlocked=false.

R15-B usa exclusivamente el namespace `sigma-v3-r15-harness-v1` y valida
crash/resume, timeout, duplicate RunKey, wrong seed, record/checkpoint tampering,
budget overflow, execution-manifest mismatch y retry policy. No consume el
namespace `sigma-v3-r15`.


## Shadow acquisition doctrine

R15-C/D shadow rehearsals are pre-data integration tests, not scientific
observations. They use dedicated namespaces:

- `sigma-v3-r15-shadow-c-v1`;
- `sigma-v3-r15-shadow-d-v1`.

They consume real R14.1 cell factors but clamp work to CI-safe limits, write
canonical records/receipts, build deterministic ledgers and assert mode/fault/
strategy coverage. They never call `derive_confirmatory_seed_r141` and cannot
enter R15 figures/tables.


R15-E shadow uses production Argon2id, history-feedback Sigma v3 and PoW
primitives at tiny non-confirmatory scale. It validates the three frozen KDF
treatments, nonce preparation/selection accounting and the three mitigation
modes without using physical-host measurements or confirmatory seeds.


R15-F now has exact pre-data stream semantics in
`experiments/r15_stat_streams.py`. The shadow battery covers all 8
constructions × 3 corpora, verifies chunking-invariant regeneration and the
broken-control defect, but does not invoke external NIST/PractRand/TestU01
binaries and therefore remains non-confirmatory.


R15-G shadow executes the frozen statistical estimators against deterministic
synthetic inputs for all F01–F15 and binds the resulting analysis bundle by
SHA-256. R15-H shadow builds an append-only synthetic dataset and verifies
RunKey completeness, duplicate rejection, record/receipt tamper detection,
missing-record rejection and deterministic ledger ordering. Neither rehearsal
derives or consumes confirmatory R15 seeds.


## Application engineering reclassification

Before any PARAM-04/05/06 engineering acquisition, these three families were
removed from the mandatory confirmatory closure path and reclassified as
`exploratory-engineering`.

Normative machine-readable amendment:
`experiments/r15-application-engineering-amendment.json`.

Consequences:

- PARAM-04/05/06 never consume the `sigma-v3-r15` confirmatory namespace;
- they do not count toward R15 PASS or core security claims;
- no three-host physical manifest is required for R15 closure;
- C15 remains a boundary statement;
- C16/C17 become exploratory application observations only;
- mandatory confirmatory volume is 145,088 units:
  143,552 internal + 1,536 STAT;
- exploratory application acquisition uses 64 hosted-runner records with its
  own namespace and integrity ledger.

The hosted-runner measurements are environment-specific engineering evidence,
not hardware-generalizable benchmarks.
