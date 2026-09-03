# Reproducible experiment harness

This directory contains only the active Sigma v2.2 experimental runners,
their final development-pilot configurations and the frozen
preregistration. Pilot raw data are transient and cannot feed the paper. The
only retained pilot evidence is
[`pilot-decision-record-v2-2.json`](pilot-decision-record-v2-2.json); the
confirmatory campaign will produce the sole article dataset.

Experiments are measurements or reduced-model simulations, never proofs. The
allowed interpretation of every endpoint is fixed in
[`preregistration-v2-2.md`](preregistration-v2-2.md) and
[`../specification/security-analysis.md`](../specification/security-analysis.md).

## Local pilot campaign

Run all 20 current configurations into a disposable directory:

```console
python -m experiments.reproduce_all \
  --campaign pilot \
  --output-root /tmp/sigma-v2-2-pilots
python -m scripts.summarize_pilots /tmp/sigma-v2-2-pilots \
  --output experiments/pilot-decision-record-v2-2.json
```

Resume an interrupted campaign without duplicating completed tasks:

```console
python -m experiments.reproduce_all \
  --campaign pilot \
  --output-root /tmp/sigma-v2-2-pilots \
  --resume
```

The retained 2026-09-03 decision record covers EXP-01R–12R, EXP-14R and
EXP-17–21R: 20 runs, 36,731 observations and zero failed run-level quality
controls. These values demonstrate runner feasibility only. EXP-07 measured a
confirmatory requirement of 566–677 samples per input bit, so the frozen design
must use at least 677. EXP-12 verified that every compared mode receives the
same Argon2id budget. Timing/memory cells still require controlled multihost
execution.

## Transactional scheduler

Every configuration is validated against a closed, versioned per-experiment
schema before an output directory is created. `execution.tasks` partitions a
configuration into deterministic child seeds. Each task owns an immutable
directory containing its effective config, result, integrity record and
stdout/stderr. States distinguish `success`, `censored`, `error` and `timeout`;
right-censoring is a completed scientific result. A retry archives its failed
attempt instead of overwriting it, and resume rejects tampered artifacts.

Run or resume one configuration with:

```console
python -m experiments.runner CONFIG OUTPUT
python -m experiments.runner CONFIG OUTPUT --resume
```

Summaries separate execution completeness, deterministic invariants,
hypothesis outcome and quality controls. A result contrary to a hypothesis is
not an execution failure.

## Current experiment catalogue

- EXP-01: six-suite adapter/backend/worker conformance against the independent
  consumer.
- EXP-02–04: reduced collision, persistence, anchor and combiner models with
  censored survival analysis and explicit controls.
- EXP-05–08: structural dependency, work/span, SAC/BIC and independently framed
  distribution streams.
- EXP-09–10: operation-level performance and aggregate memory/trace policy.
- EXP-11–12: bounded PoW behavior and equal-budget Argon2id+Sigma composition.
- EXP-14: fault detection/propagation, explicitly not a DFA claim.
- EXP-17–20: reduced attacker frontiers, Fold/Vector comparison, signed
  commitment reuse and distinct preimage-family games.
- EXP-21: primitive-input domain, canonical-framing and downgrade audit.

EXP-13 is not applicable without a specified native core and valid leakage
acquisition. EXP-16 is not applicable without RTL, testbench, toolchain,
technology/corner and reproducible synthesis. EXP-15/Psi is not part of the
active product or campaign.

## Confirmatory freeze and execution

The preregistration was human-approved and frozen on 2026-09-03. Its binding
record covers the protocol plus 20 final configurations and 7,233 effective
tasks. The reproducible preparation commands are:

```console
python -m scripts.prepare_confirmatory \
  --preregistration experiments/preregistration-v2-2.md \
  --output experiments/configs/confirmatory-frozen \
  --artifact-path dist/sigma_framework-2.2.0a1-py3-none-any.whl
python -m experiments.freeze \
  --preregistration experiments/preregistration-v2-2.md \
  --config experiments/configs/confirmatory-frozen/EXP_CONFIG.json \
  --output experiments/configs/confirmatory-frozen/freeze.json \
  --reviewed-by "alfredoVallejoM (repository owner)" \
  --reviewed-at "2026-09-03T14:27:27+02:00"
```

Repeat `--config` for every frozen file. The freeze record hashes the protocol
and complete config set. Confirmatory configs must bind that protocol hash,
select the freeze manifest, the v2.2 suite family and the installed wheel.

Only a clean checkout at an exact tag may run the campaign:

```console
python -m experiments.reproduce_all \
  --campaign confirmatory \
  --output-root /ARCHIVE/sigma-v2-2-confirmatory
```

The runner records the exact commit/tag, canonical config, wheel metadata/hash,
real import path, command, interpreter, dependencies, host/hardware and hashes
of every non-self artifact. Confirmatory raw data, logs, wheel, checksums and
SBOM belong in the versioned external archive; Git retains the configs, freeze,
index, hashes and summaries.

## External distribution batteries

EXP-08 stream export preserves byte order and records the transformation:

```console
python -m scripts.export_distribution_streams EXP08_RUN BATTERY_EXPORT
```

NIST SP 800-22, PractRand and TestU01 must be run externally with versions,
commands and complete outputs archived. Availability detection is not evidence
that a battery ran, and passing a battery is not a cryptographic security claim.

The project-wide order and gates are defined in
[`../docs/final-development-plan-v2-2.md`](../docs/final-development-plan-v2-2.md).
