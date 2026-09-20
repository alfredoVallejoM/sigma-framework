# Sigma Framework

Sigma is an experimental Python framework for canonical wide-input hash
commitments, input-reinjected iteration and multi-state digests.

> **Security status:** Sigma v3 / Sigma-IAP is an experimental research line.
> R12 has a traceable engineering/conformance PASS, but this is not a
> cryptographic audit. A post-R12 semantic correction, R12.5, restores historical
> feedback so prior trajectory state becomes part of the effective round binding.
> R12.5 and R13 are closed research gates, but no v3 suite is production-ready or security-stable; R14–R16 remain open.

Sigma v2.2 remains a frozen historical baseline and regression oracle. Sigma v3
is developed on this branch with byte-exact specifications, an independent
implementation, conformance corpora and versioned adversarial reviews. The R12
construction is preserved rather than silently rewritten and is now also an
ablation baseline for measuring the effect of historical feedback.

## Sigma v3 research status

| Layer | Status |
|---|---|
| R0–R12 engineering/conformance | PASS recorded |
| R12.5 historical feedback | **PASS** — candidate `5ac306bb…` |
| R13 formal security & cryptanalysis | **next active gate** |
| R14 experimental freeze/preregistration | pending |
| R15 confirmatory scientific campaign | pending |
| R16 external reproduction/review | pending |
| independent cryptographic audit | not performed |
| production-security claim | not made |

Current governing documents:

- [R12.5 byte-exact specification](specification/sigma-v3-r12-5-history.md)
- [R12.5 implementation traceability](docs/traceability-v3-r12-5.md)
- [R12.5 adversarial review](docs/adversarial-reviews/R12-5.md)
- [R12.5 history-feedback plan](docs/sigma-v3-r12-5-history-feedback-plan.md)
- [cryptographic/scientific paper validation plan](docs/paper-cryptographic-validation-plan-v3.md)
- [v3 assessment and development plan](docs/assessment-and-development-plan-v3-2026-09-19.md)
- [R12 traceability](docs/traceability-v3-r12.md)
- [R12 adversarial review](docs/adversarial-reviews/R12.md)
- [R12 byte-exact specification](specification/sigma-v3.md)

The core research object after R12.5 is the full trajectory state
`Z_i = (H_i, S_i)`: the public state `S_i` may collide without implying that
two distinct historical trajectories have coalesced.

## Frozen v2.2 baseline

Sigma v2 separates five concerns that v1 mixed together:

1. a registered suite fixes the mathematical function;
2. an anchor profile commits to the complete message;
3. a round profile defines state evolution;
4. an output profile preserves consecutive complete states;
5. an execution backend changes scheduling only, never the digest.

The current reference implementation provides:

- strict canonical context, digest, typed-evidence and application parsers;
- `StreamWide`, `CrossWide` and canonical `TreeWide` anchors;
- `WideOnce`, `Deep` and vector-preserving `DeepVector` rounds;
- genuine multi-state output `S_t..S_(t+k-1)`;
- full-history and explicitly local adjacent verification;
- serial, incremental and multiprocessing/mmap execution;
- distinct reference, Lightweight, Simultaneous, Paranoid Wide, Paranoid Deep
  and Paranoid DeepVector v2.2 presets;
- local `ResourcePolicy` enforcement and coherent file snapshots;
- non-serializable Argon2id+Sigma derived keys and separate public password
  records;
- explicitly v2.2-bound experimental PoW3 and Ed25519 commitments;
- current known-answer vectors and an independent six-suite/application
  conformance consumer.

`Psi` is not used by v2 and is not a root of trust. Its legacy implementation
and EXP-15 campaign are absent from the active tree.

## Installation

Sigma requires Python 3.10 or newer.

```console
python -m pip install -e '.[test,quality]'
```

No third-party package is required by the runtime v2 core. The optional
`analysis` group contains dependencies for experimental statistics and plots.

## Python API

Hash bytes with an explicit preset:

```python
from sigma.presets import lightweight_v2_2
from sigma.v2 import hash_bytes, verify_full

context = lightweight_v2_2(target_round=4, state_count=2)
digest = hash_bytes(b"example", context)

assert verify_full(b"example", digest)
print(digest.hex())  # complete self-describing envelope
print(digest.states)  # S_4 and S_5, both preserved in full
```

Use the Simultaneous suite with different worker counts without changing its
mathematical result:

```python
from sigma.backends import MultiprocessingTreeBackend
from sigma.presets import simultaneous_v2_2
from sigma.v2 import hash_file

context = simultaneous_v2_2()
digest = hash_file(
    "large.bin",
    context,
    backend=MultiprocessingTreeBackend(workers=4),
)
```

Incremental RealTime finalization:

```python
from sigma.incremental import IncrementalSigmaV2
from sigma.presets import lightweight_v2_2

stream = IncrementalSigmaV2(lightweight_v2_2())
stream.update(b"first packet")
checkpoint = stream.checkpoint()  # provisional and bound to its byte offset
stream.update(b"second packet")
digest = stream.finalize()  # the only definitive complete-message digest
```

Calling `finalize()` twice or updating afterwards is an error. A checkpoint is
never presented as the final digest of a stream that may continue.

## Presets

| Preset | Anchor | Rounds | Intended property |
|---|---|---|---|
| `reference-v2-2` | four-branch StreamWide | WideOnce | normative reference profile |
| `lightweight-v2-2` | two-branch StreamWide | WideOnce | O(1) message-size memory |
| `simultaneous-v2-2` | canonical TreeWide | WideOnce | backend-neutral parallel leaves |
| `paranoid-wide-v2-2` | four-branch CrossWide | WideOnce | retains roots plus connections |
| `paranoid-deep-v2-2` | four-branch CrossWide | Deep | evaluates every branch per level |
| `paranoid-deep-vector-v2-2` | four-branch CrossWide | DeepVector | retains the complete branch vector per level |

The names are convenience presets, not security grades. Different presets have
different suite IDs and intentionally produce different digests. RealTime is
an incremental execution policy over `lightweight-v2-2`, not a distinct suite.

## Verification and development

```console
python -m scripts.validate_project --fuzz-iterations 10000 --report /tmp/sigma-gate.json
```

That gate runs formatting/lint/type checks, compilation, the full test and
coverage suite, deterministic codec fuzzing, clean sdist/wheel builds, release
metadata checks and isolated-wheel CLI/import smoke tests outside the checkout.
It also rejects accidental build and coverage artifacts in the tree.

`constraints/experiments-py313.txt` freezes the currently validated Python
3.13 analysis environment. Release artifacts receive SHA-256 checksums and a
CycloneDX SBOM; the runtime package intentionally has no third-party dependencies.
The coverage-guided and mutation campaigns use the optional `fuzz` and
`mutation` dependency groups. Version dimensions and release eligibility are
defined in [`docs/versioning.md`](docs/versioning.md).

The active v3 roadmap is
[`docs/assessment-and-development-plan-v3-2026-09-19.md`](docs/assessment-and-development-plan-v3-2026-09-19.md).
R12.5 is specified as a post-R12 correction in
[`docs/sigma-v3-r12-5-history-feedback-plan.md`](docs/sigma-v3-r12-5-history-feedback-plan.md),
and the paper evidence program is in
[`docs/paper-cryptographic-validation-plan-v3.md`](docs/paper-cryptographic-validation-plan-v3.md).
The preserved v2.2 historical status remains documented in
[`docs/project-status-2026-09-03.md`](docs/project-status-2026-09-03.md).
The preserved v2.2 historical scope remains documented in
[`docs/current-scope-v2-2.md`](docs/current-scope-v2-2.md) and
[`docs/final-development-plan-v2-2.md`](docs/final-development-plan-v2-2.md).
The formal claims and working paper are in
[`specification/security-analysis.md`](specification/security-analysis.md) and
[`paper/manuscript.md`](paper/manuscript.md). The reproducible experiment
protocol and current pilot configurations are documented in
[`experiments/README.md`](experiments/README.md).
The dependency-free consumer in
[`reference/independent_v22.py`](reference/independent_v22.py) deliberately
imports no `sigma` code and differentially reconstructs all six v2.2 suite
constructions, including every Deep/DeepVector intermediate and TreeWide leaf
boundaries, directly from the published byte specification. The normative
[`conformance-v2-2.json`](specification/test-vectors/conformance-v2-2.json)
corpus covers complete trajectories for all suites, every active PoW/KDF/signed
mode and all public codec families, including negative cases. The detailed F2
closure is in
[`docs/conformance-audit-v2-2.md`](docs/conformance-audit-v2-2.md).

## Claims and limitations

- Backend equality is tested behavior, not a security proof.
- Multiple output states do not prove prior sequential history by themselves.
- Multiple hash branches do not automatically provide additive or independent
  security; conservative combiner assumptions apply.
- Sigma does not create entropy for passwords or supply memory hardness. The
  optional KDF composition uses Argon2id first and measures Sigma only as
  transcript-binding overhead.
- Python execution is not claimed constant-time. Side-channel claims require a
  separately reviewed native implementation and physical evidence.
- No ASIC area, energy or resistance claim is made without an RTL artifact and
  reproducible synthesis.

Sigma is licensed under AGPL-3.0-or-later. Commercial licensing arrangements do
not change the technical security status of the implementation.
