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

The v2 scheduler executes every atomic task in a separate Python process. A
task owns `tasks/<sha256>/config.json`, `result.json`, `stdout.log` and
`stderr.log`; the deterministic identifier commits to the effective config,
label and ordinal. Explicit tasks receive independent SHA-256-derived child
seeds, recorded in their effective configs; overriding `master_seed` inside a
task is forbidden. Results are written atomically. An interrupted run can be
continued without repeating or duplicating completed partitions:

```console
python -m experiments.runner CONFIG OUTPUT --resume
```

Legacy configurations remain one atomic `complete-config` task. New campaigns
can partition cells without overloading an experiment's scientific
`repetitions` parameter:

```json
{
  "experiment": "EXP-01",
  "master_seed": "public-seed",
  "presets": ["reference-v2-2"],
  "sizes": [],
  "execution": {
    "timeout_seconds": 3600,
    "tasks": [
      {"label": "empty", "overrides": {"sizes": [0]}},
      {"label": "boundary-65", "overrides": {"sizes": [65]}}
    ]
  }
}
```

`success`, `censored`, `error` and `timeout` are distinct task states.
Right-censoring is a completed scientific observation. Summary v2 reports
`execution_complete`, `invariants_passed`, `hypothesis_outcome` and
`quality_controls_passed`; an unsupported statistical hypothesis does not turn
an otherwise valid run into an execution failure.

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
- `EXP-17`: cross-anchor precomputation controls (direct and distinguished tables).
- `EXP-18`: reduced Deep fold versus DeepVector collision comparison.
- `EXP-19`: reduced commitment-reuse search with Ed25519 explicitly unreduced.
- `EXP-20`: separate preimage, second-preimage and multi-target games.
- `EXP-21`: deterministic registered-domain, TLV and downgrade-confusion audit.

The EXP-17..21 smoke configurations are implementation pilots, not the full R
campaigns. In particular, EXP-17 still needs rho/Hellman/rainbow and
multicollision attackers; EXP-21 still needs the complete instrumented oracle
input matrix. Their absence remains visible in the preregistration rather than
being inferred from a passing smoke run.

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

The manifest records exact commit/tag state, microcode, dependencies, command,
seed derivation and artifact hashes. Each task records start/end temperature,
CPU frequency and governor samples. Missing or inaccessible measurements are
represented as `null`; they are never inferred. Use `--require-clean-tag` for
a publishable run: it refuses execution unless the tree is clean, `HEAD` has an
exact tag and `artifact_path` identifies the installed wheel/executable whose
SHA-256 is recorded. Two endpoint samples expose drift but do not replace
external host stabilization or a higher-frequency hardware logger.
