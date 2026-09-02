# Reproducible experiment harness

Experiments are simulations or measurements, never proofs. Every configuration
contains a public master seed. The runner derives independent labelled PRNG
streams, writes one CSV row per observation, derives a JSON summary, and records
the source/environment metadata and SHA-256 artifact hashes in a manifest.

Run a configuration into a new, empty directory:

```console
python -m experiments.reproduce \
  --config experiments/configs/exp01-smoke.json \
  --output experiments/results/my-exp01-run
```

Committed `*-smoke-*` results only validate the pipeline at modest cost. They
must not be described as the full experiment or as evidence at production
width. Full paper datasets belong in a versioned archival release/DOI and must
retain their compressed raw observations, configuration and manifest together.

Current runners:

- `EXP-01`: exact adapter/chunk/backend/worker determinism.
- `EXP-02`: deterministic reduced-oracle collision simulations.
- `EXP-03`: conditional collision persistence with exact binomial checks.
- `EXP-04`: reduced-width anchor bottlenecks under broken/correlated branches.
- `EXP-05`: exact bit-difference masks across real v2 roots, connections and states.
- `EXP-06`: exact work/depth accounting and measured candidate-level concurrency.
- `EXP-07`: layer-separated SAC masks with exact binomial/Bonferroni analysis.
- `EXP-08`: canonical output streams with frequency, runs and serial-dependence tests.
- `EXP-09`: randomized multi-process timings with raw observations and bootstrap intervals.
- `EXP-10`: fresh-process Python allocation/RSS measurements and explicit model selection.
- `EXP-11`: reduced-difficulty, canonically specified multi-state PoW predicates.
- `EXP-12`: Argon2id versus Argon2id-plus-Sigma dictionary cost (optional `kdf` extra).
- `EXP-13`: gated; requires a specified native implementation and leakage evidence.
- `EXP-14`: fault propagation/detection, explicitly not DFA.
- `EXP-15`: structural and reduced-width legacy `Psi` analysis.
- `EXP-16`: gated; requires RTL, toolchain, constraints and actual synthesis.

Each new run embeds a canonical `config.json`. To execute all ten smoke
configurations and regenerate the complete figure set in one operation, use:

```console
python -m experiments.reproduce_all \
  --output-root /tmp/sigma-reproduction \
  --figure-output /tmp/sigma-reproduction-figures
```

Preregistered resource-intensive configurations are under
`experiments/configs/confirmatory`. Run them only on a controlled host with
adequate disk, RAM and time by adding `--campaign confirmatory`. EXP-01 switches
to bounded-memory file generation above 16 MiB; EXP-02 records right-censoring
at its declared candidate budget. These configs are a protocol, not a claim
that the confirmatory campaign has already been executed.

The manifest records a best-effort snapshot of host temperature, CPU frequency
and governor. Missing or inaccessible measurements are represented as `null`;
they are never inferred. A controlled EXP-09 release must still stabilize and
record these conditions externally because a single snapshot is not a control.
