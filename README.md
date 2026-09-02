# Sigma Framework

Sigma is an experimental Python framework for canonical wide-input hash
commitments, input-reinjected iteration and multi-state digests.

> **Security status:** Sigma v2 is an alpha research implementation. Its wire
> formats and current suite vectors are frozen for interoperability, but the
> construction has not received independent cryptographic review. Do not treat
> it as a password KDF, digital signature, authentication scheme, production
> proof of work, or replacement for a standard hash function.

The repository also retains the original v1 prototype for reproducibility.
Those APIs are explicitly legacy and contain known design defects documented in
[`docs/audit-2026-09-02.md`](docs/audit-2026-09-02.md).
The current internal verdict and remaining external gates are recorded in
[`docs/final-audit-2026-09-02.md`](docs/final-audit-2026-09-02.md).

## What v2 changes

Sigma v2 separates five concerns that v1 mixed together:

1. a registered suite fixes the mathematical function;
2. an anchor profile commits to the complete message;
3. a round profile defines state evolution;
4. an output profile preserves consecutive complete states;
5. an execution backend changes scheduling only, never the digest.

The current reference implementation provides:

- strict canonical context and digest parsers;
- `StreamWide`, `CrossWide` and canonical `TreeWide` anchors;
- `WideOnce` and `Deep` input-reinjected rounds;
- genuine multi-state output `S_t..S_(t+k-1)`;
- full-history and explicitly local adjacent verification;
- serial, incremental and multiprocessing/mmap execution;
- distinct Lightweight, Simultaneous, RealTime, Paranoid Wide and Paranoid
  Deep presets;
- frozen known-answer vectors and differential tests.

`Psi` is not used by v2 and is not a root of trust. It remains only as part of
the reproducible legacy prototype pending separate cryptanalysis.

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
from sigma.presets import lightweight_v2
from sigma.v2 import hash_bytes, verify_full

context = lightweight_v2(target_round=4, state_count=2)
digest = hash_bytes(b"example", context)

assert verify_full(b"example", digest)
print(digest.hex())       # complete self-describing envelope
print(digest.states)      # S_4 and S_5, both preserved in full
```

Use the Simultaneous suite with different worker counts without changing its
mathematical result:

```python
from sigma.backends import MultiprocessingTreeBackend
from sigma.presets import simultaneous_v2
from sigma.v2 import hash_file

context = simultaneous_v2()
digest = hash_file(
    "large.bin",
    context,
    backend=MultiprocessingTreeBackend(workers=4),
)
```

Incremental RealTime finalization:

```python
from sigma.incremental import IncrementalSigmaV2
from sigma.presets import realtime_v2

stream = IncrementalSigmaV2(realtime_v2())
stream.update(b"first packet")
checkpoint = stream.checkpoint()  # provisional and bound to its byte offset
stream.update(b"second packet")
digest = stream.finalize()        # the only definitive complete-message digest
```

Calling `finalize()` twice or updating afterwards is an error. A checkpoint is
never presented as the final digest of a stream that may continue.

## Presets

| Preset | Anchor | Rounds | Intended property |
|---|---|---|---|
| `lightweight-v2` | two-branch StreamWide | WideOnce | O(1) message-size memory |
| `simultaneous-v2` | canonical TreeWide | WideOnce | backend-neutral parallel leaves |
| `realtime-v2` | two-branch StreamWide | WideOnce | incremental update and explicit EOF |
| `paranoid-wide-v2` | four-branch CrossWide | WideOnce | retains roots plus connections |
| `paranoid-deep-v2` | four-branch CrossWide | Deep | evaluates every branch per level |
| `paranoid-deep-vector-v2-2` | four-branch CrossWide | DeepVector | retains the complete branch vector per level |

The names are convenience presets, not security grades. Different presets have
different suite IDs and intentionally produce different digests.

## Legacy v1

The `SigmaFactory` and current `sigmahash` command reproduce v1. Prefer explicit
mode names such as `legacy-v1-lightweight`; short names remain temporary aliases.

```console
sigmahash --mode legacy-v1-lightweight example.bin
```

The legacy CLI is not a KDF or production integrity tool. Simultaneous v1 is
hardware-dependent and is intentionally excluded from canonical v1 vectors.

## Verification and development

```console
python -m compileall -q sigma tests
python -m pytest -q
python -m scripts.fuzz_codecs --iterations 10000
python scripts/fuzz_atheris.py --write-corpus /tmp/sigma-fuzz-corpus
python scripts/fuzz_atheris.py /tmp/sigma-fuzz-corpus -atheris_runs=10000
mutmut run 'sigma.spec.encoding*'
ruff check sigma scripts experiments tests
mypy sigma scripts experiments
python -m build
python scripts/release_artifacts.py dist
```

`constraints/experiments-py313.txt` freezes the currently validated Python
3.13 analysis environment. Release artifacts receive SHA-256 checksums and a
CycloneDX SBOM; the runtime package intentionally has no third-party dependencies.
The coverage-guided and mutation campaigns use the optional `fuzz` and
`mutation` dependency groups. Version dimensions and release eligibility are
defined in [`docs/versioning.md`](docs/versioning.md); test campaign evidence is
recorded in [`docs/testing-hardening.md`](docs/testing-hardening.md).

The byte-level construction is specified in
[`specification/sigma-v2.md`](specification/sigma-v2.md). Work packages, gates
and remaining experimental/paper tasks are tracked in
[`docs/implementation-roadmap.md`](docs/implementation-roadmap.md).
The post-audit redesign, formal obligations, confirmatory experiments, metrics
and planned paper figures are specified in
[`docs/research-addendum-v2-2.md`](docs/research-addendum-v2-2.md).
The formal claims and working paper are in
[`specification/security-analysis.md`](specification/security-analysis.md) and
[`paper/manuscript.md`](paper/manuscript.md). The reproducible experiment protocol and smoke configurations are documented in
[`experiments/README.md`](experiments/README.md).

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
