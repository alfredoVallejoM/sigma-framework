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
On resume, `success` and `censored` partitions are immutable. Failed or timed
out attempts are moved to `tasks/<id>/attempts/` with their logs before a new
attempt; this retains the failure history while permitting operational
recovery with a different CLI timeout.

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
- `EXP-17`: six reduced precomputation/TM/multicollision attackers across anchors.
- `EXP-18`: consecutive reduced Deep fold versus DeepVector trajectories.
- `EXP-19`: reduced commitment-reuse events with Ed25519 explicitly unreduced.
- `EXP-20`: separate preimage, second-preimage and multi-target games/attackers.
- `EXP-21`: real primitive-input, registered-domain, TLV and downgrade audit.

The EXP-17..21 smoke configurations are historical implementation pilots. The
revised pilot configs under `configs/pilots` add rho/Hellman/rainbow/
multicollision attackers, consecutive Fold/Vector segments, explicit signed
components, three preimage attackers and opt-in capture of actual primitive
inputs. They are still reduced pilots, not confirmatory evidence.

Prepare independent EXP-08 streams for external batteries without changing
their byte or bit order:

```console
python -m scripts.export_distribution_streams EXP08_RUN BATTERY_EXPORT
```

The export manifest commits to the source config/observations and every binary
stream, records the exact transform, and reports NIST SP 800-22, PractRand and
TestU01 executables as available or unavailable. It does not claim a battery
was executed; full commands, versions and stdout/stderr belong in the archived
external campaign.

Each new run embeds a canonical `config.json`. To execute all ten smoke
configurations and regenerate the complete figure set in one operation, use:

```console
python -m experiments.reproduce_all \
  --output-root /tmp/sigma-reproduction \
  --figure-output /tmp/sigma-reproduction-figures
```

The files under `experiments/configs/confirmatory` are retained historical
`confirmatory-v1` drafts. They predate the revised R designs and are deliberately
blocked by both the runner and `reproduce_all`. A future confirmatory config
must name a frozen preregistration and its SHA-256; the runner also automatically
requires a clean exact tag and hashed installed artifact. The current
`preregistration-v2-2.md` is explicitly a draft and cannot satisfy that gate.

The manifest records exact commit/tag state, microcode, dependencies, command,
seed derivation and artifact hashes. Each task records start/end temperature,
CPU frequency and governor samples. Missing or inaccessible measurements are
represented as `null`; they are never inferred. Use `--require-clean-tag` for
a publishable run: it refuses execution unless the tree is clean, `HEAD` has an
exact tag and `artifact_path` identifies the installed wheel/executable whose
SHA-256 is recorded. Two endpoint samples expose drift but do not replace
external host stabilization or a higher-frequency hardware logger.

After a pilot, derive a measured planning envelope with:

```console
python -m scripts.estimate_campaign_budget PILOT_RUN --planned-tasks 1000
```

The report extrapolates serial wall time, disk and observations from completed
partitions and reports worker CPU/RSS data where the platform exposes it. RSS is
kept in the operating system's native `getrusage` units (KiB on Linux, bytes on
macOS), so cross-platform conversion must be explicit in the frozen protocol.
