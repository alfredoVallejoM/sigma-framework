# Sigma: Wide Input Commitments and Round-Separated Multi-State Hash Iteration

Working manuscript — Sigma v2.2 alpha, 2026-09-03.

> **Evidence status:** F5 removed all historical result data and figures. The
> results section is intentionally empty until F7 produces the single frozen,
> preregistered v2.2 confirmatory dataset. This draft is not an independent
> cryptographic review.

## Abstract

We describe Sigma v2.2, an experimental framework separating a canonical wide
input commitment from an anchor-reinjected sequence of hash transitions and a
digest containing consecutive states. Its engineering contribution is a strict
byte-level specification shared by streaming, tree and parallel backends. Its
analytical contribution is a conditional random-oracle account of
non-coalescence and multi-state collision bounds: unequal anchors make the next
queries distinct after a state collision, while an ordinary chain repeats the
same query. This neither proves sequential work nor overcomes the effective
strength of the anchor. The repository supplies a reference implementation,
independent consumer, normative conformance corpus, local validation gate and
transactional experiment harness. Twenty development pilots validated the
runners and dimensioned a review-ready preregistration, but their measurements
are excluded from the article. Confirmatory evidence and independent
cryptanalysis remain open.

## 1. Scope and contribution

Iterated hashing mixes quantities that must remain distinct: honest work,
adaptive depth, physical state width, output length and source entropy.
Repetition does not create password entropy, memory hardness, authentication or
a succinct proof of prior work. Likewise, retaining multiple branch roots can
support a conservative combiner argument, while deterministically derived
connections receive no automatic additive security credit.

Sigma v2.2 is therefore an **input-bound, round-separated iterated hash
combiner with a multi-state trajectory commitment**. It follows four rules:

1. every suite parameter is canonical and authenticated;
2. the anchor retains standard branch roots;
3. every transition injects the full anchor, context and round index;
4. the digest publishes complete consecutive states in a self-describing wire.

The work contributes versioned codecs; StreamWide, CrossWide and TreeWide
anchors; WideOnce, Deep and DeepVector rounds; backend-invariant execution;
explicit conditional arguments TH-01–TH-08; and a data-first experiment
pipeline. It claims neither production readiness, post-quantum security,
constant-time execution, ASIC resistance nor a proof of sequential work.

## 2. Threat models

The collision adversary chooses distinct canonical `(context,message)` pairs.
A target adversary receives a digest target. A conformance adversary searches
for an adapter, partition or schedule that changes an intermediate or output for
the same bytes and suite. Reduced experiments use small deterministic random
oracles; formal transition arguments use ideal random oracles. Concrete hash
functions retain their standard collision/preimage assumptions and are not
treated as proven independent oracles.

Low-entropy input remains enumerable. The optional composition runs Argon2id
before Sigma and attributes memory hardness only to Argon2id. Sigma can add
context binding and deterministic per-guess work, not entropy.

## 3. Construction

For encoded context `C`, complete anchor evidence `A`, state function `F`,
target round `t` and number of states `k`:

```text
S_0     = F(DST_init  || Enc(C,A))
S_(i+1) = F(DST_round || Enc(C,i,A,S_i))
D_(t,k) = Enc(C,S_t,...,S_(t+k-1)).
```

`SigmaContextV2` is a strict TLV record covering suite, anchor, round/output
profiles, `t`, `k`, ordered branch IDs, tree leaf size, salt, challenge and
application context. Unknown, reordered, duplicate, missing, truncated and
trailing fields are rejected. Scheduling choices are deliberately absent.

StreamWide frames the same message into every registered branch and retains
the roots. CrossWide retains roots and adds connections over their full vector;
these connections are diffusion structure, not independent security bits.
TreeWide uses fixed 65,536-byte leaves and canonical range/height/length node
framing, retaining an O(log N) frontier without duplicating odd nodes.

Deep evaluates every branch at each level and folds the vector with SHA3-512.
DeepVector retains the complete ordered component vector and makes every next
component consume the previous vector. Branches within a level may run in
parallel; levels remain adaptive. Full verification recomputes the message,
anchor and trajectory. Adjacent verification proves one transition only.

## 4. Security analysis boundary

The full games, reductions and assumptions are in
[`security-analysis.md`](../specification/security-analysis.md).

- TH-01 establishes injective accepted encodings and deterministic backend
  conformance.
- TH-02 reduces retained-root anchor collision to the branch assumptions.
- TH-03 establishes distinct successor queries under unequal anchors.
- TH-04 bounds segment collisions by anchor advantage plus a conditional
  random-oracle term and explicit non-ideal error.
- TH-05 treats second preimage separately from collision.
- TH-06 treats target preimage and multi-target factors separately and caps
  claims by source entropy.
- TH-07 describes evaluator work/span without a universal sequentiality bound.
- TH-08 separates Ed25519 attestation, full recomputation and one-edge checking.

Physical retained width never substitutes for an assumed collision/preimage
strength. Multiple standardized hash names, and distinct domains of one
primitive, are not automatically independent.

## 5. Implementation

Six active presets bind distinct suite IDs: reference StreamWide, Lightweight,
Simultaneous TreeWide, Paranoid Wide, Paranoid Deep and Paranoid DeepVector.
Their names describe profiles rather than grades. RealTime is incremental
execution over Lightweight, not a separate construction.

The serial implementation is normative. Tree multiprocessing hashes canonical
leaves in bounded batches and reduces them identically; Deep threads normalize
completion order before framing. File APIs check one coherent snapshot and the
multiprocess route shares one private immutable copy. `ResourcePolicy`
separates canonical wire validity from local acceptance limits.

The v2.2 PoW profile binds challenge, suite, depth, states and predicate, but is
neither cheap nor succinct and leaves nonces parallelizable. The KDF API keeps
the derived key non-serializable and exposes a separate public password record.
Signed commitments use standard Ed25519 and distinguish attestation from full
trajectory verification.

## 6. Experimental method

Each experiment uses a closed versioned JSON schema and public master seed.
Labelled SHA-256 derivation produces independent child seeds. A transactional
scheduler writes raw compressed observations, summary, canonical config,
per-task result/integrity/log files and a manifest binding commit/tag, wheel
hash/metadata, real import path, command, runtime, dependencies and host.
Retries archive failed attempts; right-censoring, timeout, error and success are
separate states.

Development pilots cover conformance (EXP-01), reduced collision/persistence
models (02–04), structure/diffusion/distribution (05–08), work/performance/
memory (06,09,10), bounded applications/faults (11,12,14) and offensive reduced
models/domain audit (17–21). They establish feasibility only. The exact
hypotheses, matrices, exclusions, censoring, analyses, outputs and resource
rules are fixed in
[`preregistration-v2-2.md`](../experiments/preregistration-v2-2.md).

The confirmatory protocol and configuration set were human-reviewed and
hash-frozen on 2026-09-03. Execution requires a clean exact Git tag, an
installed wheel outside the checkout, controlled hosts where specified and
external distribution-battery logs. Statistical results opposing a hypothesis
are valid results, not execution failures.

## 7. Confirmatory results

Confirmatory execution is in progress; no complete canonical result set exists
yet. After F7 this
section, all tables and all figures will be generated exclusively from the
verified canonical dataset, including adverse, null, censored and failed cells.
No pilot number or hand-edited figure may appear here.

## 8. Limitations and open validation

The implementation is Python and not constant-time. TreeWide and the compound
applications require independent cryptographic review. Reduced-oracle data
cannot be extrapolated directly to 512-bit security. Multi-state output is
bounded by anchor strength. There is no native core, valid leakage acquisition,
RTL, synthesis or physical energy evidence, so no side-channel, gate-area,
energy or ASIC claim is permitted. EXP-13 and EXP-16 remain non-applicable for
those reasons.

## 9. Reproducibility

The repository contains the active specification, one normative vector corpus,
independent consumer, runners, current pilot configs and compact pilot decision
record—no historical raw evidence. The local engineering gate is:

```console
python -m scripts.validate_project --fuzz-iterations 10000 --report /tmp/sigma-gate.json
```

The pilot campaign is recreated with:

```console
python -m experiments.reproduce_all --campaign pilot --output-root OUTPUT
```

The future frozen campaign uses `--campaign confirmatory` and rejects an
unreviewed protocol, dirty/non-tagged source or non-installed artifact. Its raw
dataset, logs, wheel, checksums and SBOM will be archived under one persistent
identifier; Git will retain the frozen configs, manifest, index and hashes.

## 10. Conclusion

Sigma v2.2 replaces an ambiguous prototype with a testable construction whose
encoding, anchor evidence, transition inputs and limitations are explicit.
Anchor reinjection changes conditional persistence in the idealized model, and
consecutive states impose repeated equalities only up to the anchor bottleneck.
The strongest present result is architectural and conditional, not a new
production primitive. The frozen confirmatory campaign and independent review
will determine whether stronger empirical conclusions are justified.
