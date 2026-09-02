# Sigma v2.2 security analysis

Status: internal, reviewable formalization of the experimental v2.2 family.
It is not a third-party proof or a production-security claim. “RO” means an
ideal random oracle. Different standardized hash names, and distinct domain
prefixes used with one primitive, do not by themselves establish independent
random oracles.

## 1. Objects and notation

Let `C` be a suite-valid canonical context, `M` a byte string, `A_C(M)` the
complete canonical anchor evidence, and `n=512` the scalar state width. For
WideOnce,

```text
S_0     = F(DST_init  || Enc(C,A))
S_(i+1) = F(DST_round || Enc(C,i,A,S_i))
D[t,k]  = Enc(C,S_t,...,S_(t+k-1)).
```

Deep replaces a transition by branch outputs `B_i^j` and a 512-bit fold.
DeepVector publishes `V_i=(B_i^1,...,B_i^m)` and every next component consumes
the complete previous vector. `Q` denotes all distinct oracle inputs in an
execution; repeated identical inputs count once.

The following quantities are assumptions or measured attack costs, never
inferred from byte length:

- `alpha_coll(A)`: collision strength of the complete anchor;
- `alpha_pre(A)`: target-preimage strength of the anchor;
- `alpha_2pre(A)`: second-preimage strength of the anchor;
- `alpha_joint(A,J)`: strength under a named joint branch assumption `J`;
- `w_phys(A)`: physical number of retained evidence bits.

No formula may substitute `w_phys` for an `alpha` parameter. CrossWide
connections are deterministic functions of retained roots and receive no extra
independent strength. Additive branch strength is used only when a separately
stated joint assumption supplies it.

## 2. Adversary interface and seven games (FORM-01)

Every result fixes a suite set `S`, context policy `P`, time/work `W`, anchor
queries `q_A`, transition/component queries `q_R`, adaptive parallel depth
`d`, processors `p`, memory `mu`, and number of targets/users `u`. The
adversary may choose contexts only from `S` accepted by `P`, sees the public
algorithms and domains, and may adapt later queries to prior answers. It never
receives secret state from the implementation.

1. **G-COLL.** Output distinct canonical `(C,M) != (C',M')` whose complete
   digests are equal. Cross-context wins are allowed only when the encoded
   contexts are equal, which canonicality reduces to `C=C'`.
2. **G-PRE.** Receive a target sampled by the challenger under a declared
   message distribution and fixed `C`; output any `M'` with the same digest.
   The target distribution and its min-entropy are part of the game.
3. **G-2PRE.** Receive `(C,M,D(C,M))`; output `M' != M` with the same digest.
4. **G-SEG-COLL.** Choose two distinct inputs whose `k` published states at
   target round `t` match. This game exposes `t,k` and does not treat one valid
   edge as proof of its prefix.
5. **G-MULTI.** Receive or choose `u` explicitly domain-separated contexts and
   targets. Win against any one. Bounds pay an explicit union factor (normally
   at most `u` or `binom(u,2)`); “multi-user security for free” is not assumed.
6. **G-CONFORM.** Choose one valid `(C,M)` plus adapter, chunk partition,
   backend and worker schedule. Win if two conforming executions disagree on
   any context, anchor, intermediate or digest byte. This is a deterministic
   implementation game, not a cryptographic game.
7. **G-SIG-REUSE.** With signing-oracle budget `q_S`, output a valid Ed25519
   signature/commitment for an unsigned record not previously signed. The game
   separately records whether the verifier checks attestation, full history or
   only one edge.

Reports must publish `(W,q_A,q_R,d,p,mu,u,q_S)`, available context/message
oracles, censoring and success definition. Query count, wall time and adaptive
depth are not interchangeable.

## 3. Canonicality theorem (FORM-02)

**TH-01 (injective accepted encodings).** `Enc` is injective over each accepted
type: context, v2.2 WideEvidence, v2.2 CrossWideEvidence, digest,
Argon2idParameters, SigmaKdfResult, PowParameters and signed commitment. It is
also injective over framed StreamWide inputs and TreeWide leaves/nodes. For a
fixed suite and message, conforming schedulers compute the same mathematical
object.

**Argument.** Integers have one fixed-width big-endian representation. TLV tags
are positive, unique and strictly increasing; schemas are closed; every
variable component has an exact count or length; parsers reject missing,
unknown, duplicate, reordered, truncated and trailing fields. Context and
evidence headers carry version and, for evidence, type and suite. Digest state
width is fixed by the registered suite. Therefore decoding is a left inverse
of encoding on every accepted type. Stream transcripts include a terminal
domain and `|M|`; tree inputs include context, algorithm, range/height/length
and child order. Backend configuration is absent from mathematical inputs.

This theorem is conditional on the codecs satisfying their stated checks.
Differential tests, KATs, property tests, fuzzing and mutation tests are the
executable evidence; arbitrary third-party code does not inherit conformance.

## 4. Anchor properties (FORM-03)

**TH-02 (retained-root collision reduction).** A collision in StreamWide or
CrossWide evidence for distinct canonical inputs makes every retained branch
root equal. For any selected collision-resistant branch `j`, this yields a
collision in `H_j` on distinct framed inputs. CrossWide cannot become weaker
merely by appending connections because the original roots remain present.

For TreeWide, equality of one sound branch root over unequal canonical leaf
sequences recursively yields a collision in that branch's leaf or node hash.
This uses ordered children and bound ranges; it does not claim equivalence to
another tree standard.

**Corollary (conservative combiner).** If at least one retained branch is
collision resistant on Sigma's canonical transcripts, the complete retained
anchor is collision resistant. Constant, truncated or correlated other
branches do not defeat this reduction. No analogous preimage or second-
preimage conclusion follows from collision resistance.

`alpha_pre(A)` and `alpha_2pre(A)` must therefore be assumed or reduced from
the corresponding property of a retained branch under an appropriate
composition model. `alpha_joint(A,J)` may exceed the conservative bound only
when `J` explicitly defines independence/correlation and survives review.

## 5. Reinjection and segment collision (FORM-04, FORM-05)

**TH-03 (conditioned non-coalescence).** Condition on `A != A'` and
`S_i=S'_i`. The next WideOnce inputs are distinct because the anchor occupies
its own injective field. If both RO queries are fresh, their outputs agree with
probability exactly `2^-n`. Binding only the index does not prevent coalescence
when indices and states agree; binding only the anchor and binding anchor plus
index both separate unequal-anchor queries. The index additionally separates
levels and prevents cross-level input reuse.

Let `Bad_Q` be the event that a proof step treats a query as fresh when its
complete encoded input already occurred, or that two intended domains encode
the same bytes. For an ideal `n`-bit oracle and at most `Q` distinct queries, a
generic output-repeat union bound is

```text
Pr[Bad_Q] <= Q(Q-1) / 2^(n+1) + epsilon_enc,
```

where canonical domain separation makes `epsilon_enc=0` for conforming v2.2
encodings. Non-ideal primitive behavior belongs in an explicit instantiation
term `epsilon_inst`.

**TH-04 (collision of a consecutive WideOnce segment).** For `q` candidate
messages under one valid context, assuming fresh separated RO calls,

```text
Adv_seg-coll <= Adv_coll(A; q_A)
                + binom(q,2) * 2^(-k*n)
                + Pr[Bad_Q] + epsilon_inst.
```

Split on equal anchors. Unequal anchors make the first matching published state
an equality of answers to distinct inputs; TH-03 supplies another independent
factor for each following state while freshness holds. Union-bound over message
pairs. The theorem does not prove that the first published state has a valid
prefix, and it does not apply unchanged to Deep/DeepVector without their
assumptions below.

For an ideal uniform image of `b` bits, the median first-collision query count
is approximately

```text
sqrt(2 ln 2) * 2^(b/2),
```

not merely `2^(b/2)`. Using `b=min(alpha_coll(A),k*n)` is a generic model under
regularity assumptions, not an unconditional lower bound.

## 6. Preimage and second preimage (FORM-06)

**TH-05 (second-preimage decomposition).** Given `(C,M)`, any successful
second preimage `M'` either has `A_C(M')=A_C(M)`, winning the anchor
second-preimage game, or has a different anchor whose `k` published states
match. Under the TH-04 freshness model,

```text
Adv_2pre(D) <= Adv_2pre(A; q_A) + q_M*2^(-k*n)
               + Pr[Bad_Q] + epsilon_inst.
```

Here `q_M` counts distinct evaluated candidates. Collision resistance alone
cannot replace `Adv_2pre(A)`.

**TH-06 (target preimage is a separate assumption).** No preimage lower bound
for `D` follows from TH-02 or TH-04. Under a declared regular-image model for
the map `M -> (A,D)` and a target distribution independent of the adversary's
fresh queries, generic work is modeled by

```text
2^min(alpha_pre(A), k*n)
```

candidate evaluations, capped by the message source min-entropy `h`. This is a
model prediction, not a reduction from collision resistance. For a dictionary
source the adversary enumerates at most about `2^h` candidates; deterministic
Sigma processing adds cost per guess but no entropy.

Multi-target estimates replace a single-target success probability by an
explicit union bound in `u` (approximately `u*q_M/2^b` in the ideal uniform
model). Every experiment must keep collision, preimage, second preimage and
multi-target outcomes in separate fields.

## 7. Parallel depth (FORM-07)

**TH-07 (evaluation DAG, not universal lower bound).** For the specified
evaluation algorithm, reaching the last published level needs `t+k-1`
adaptive transitions after initialization.

- WideOnce: one state-oracle layer per transition.
- Deep serial implementation: `m` branch calls followed by one fold per level;
  work `m+1`, parallel span two oracle layers.
- Deep with ideal branch parallelism: one branch layer plus one fold layer.
- DeepVector: one parallel branch layer per level because every component
  consumes the complete previous vector; there is no scalar fold.

Candidates are freely parallelizable. Threads/processes changing wall time do
not alter the DAG. The data dependency proves the span of the specified
straight-line evaluator only; a lower bound against every alternative
algorithm requires a separate sequentiality theorem, which Sigma does not
claim. Guessing an intermediate state succeeds with the relevant state/vector
guessing probability and must be included in any such game.

## 8. Deep and DeepVector failure models (FORM-08)

**Deep.** Only the 512-bit fold state is published. Even with ideal independent
branches, generic collision/preimage strength is capped by the fold width. If
the fold is constant, adversarially malleable or collision-broken, retained
branch outputs do not give a conservative final-digest reduction because they
are hidden behind the fold. One sound branch is therefore insufficient for a
Deep final-state theorem unless the fold also satisfies the named property and
the composition assumption binds all branch outputs.

**DeepVector.** Equality of a published vector makes every component equal.
For distinct canonical component inputs, one sound retained branch gives the
same conservative collision reduction as TH-02. A constant broken branch does
not erase a sound component; correlated branches prevent additive claims but
not that selected-branch reduction. Preimage/second-preimage require the
corresponding branch and joint-input assumptions separately.

Both modes consume the complete anchor at every level. Related or adversarially
chosen anchors remain distinct inputs by TH-01/03, but their hash outputs are
not assumed independent merely because their encodings differ. Any
related-anchor theorem must name the oracle/related-input assumption. Backend
reordering is normalized before Deep's fold and is only a conformance property.

## 9. Signed commitment composition (FORM-09)

The signed object contains `(C,A,states,algorithm,key_id)` under a dedicated
domain and canonical encoding.

**TH-08 (signature reuse decomposition).** A new accepted attestation over a
record not submitted to the signing oracle yields either (a) an Ed25519
EUF-CMA forgery, or (b) two distinct semantic records with one signing input,
contradicting TH-01/domain separation. Thus

```text
Adv_reuse-attest <= Adv_EUF-CMA(Ed25519; q_S) + Adv_noncanonical.
```

Signing only `D[t,k]` authenticates those states/context but omits independently
presented anchor evidence. Signing `(A,D[t,k])`, as v2.2 does, binds the claim
to both. `verify_signed_attestation` proves only that the key authenticated the
claim. `verify_full_signed` additionally recomputes `A` and the entire prefix,
so reuse against a different message requires a signature forgery, an encoding
failure, or a successful underlying anchor/digest equality attack. A verifier
that checks one edge proves only that edge: arbitrary `X` and its public
successor form a valid pair without showing that `X=S_t`.

This theorem assumes correct key-to-identifier policy outside the codec and
the standard security requirements of Ed25519; Sigma does not strengthen the
signature scheme.

## 10. Positioning and candidate novelty (FORM-10)

- PBKDF2 and PRF iteration concern keyed password derivation; Sigma's public
  reinjected anchor is not a secret PRF key or memory-hardening mechanism.
- HAIFA binds salts/counters within a hash iteration. Sigma similarly values
  explicit tweaks but commits an external retained wide anchor at every level.
- Wide-/double-pipe designs enlarge internal state inside a hash. Sigma exposes
  a multi-algorithm anchor and, only in DeepVector, a vector state.
- Robust combiners motivate retaining component outputs. Short compressed
  combiners face different limits; CrossWide connections are not credited as
  independent roots.
- Multicollision, herding and long-message second-preimage work warn against
  deriving one property from another; Sigma states each game separately.
- TupleHash/ParallelHash and tree hashes provide standardized tuple/parallel
  hashing goals. Sigma is not offered as their replacement.
- Hash chains, time-lock puzzles, VDFs and proofs of sequential work provide
  different delay/proof guarantees. Sigma has no succinct proof and candidates
  remain parallel.
- Memory-hard functions and pebbling analyses target cumulative memory cost.
  Sigma's Python hash iteration makes no such claim; the optional KDF obtains
  memory hardness only from Argon2id.

The candidate novelty is narrowly the combination of a canonically retained
wide multi-hash anchor, complete anchor reinjection at each separated level,
and a commitment to consecutive scalar or vector states. It is not the first
use of iteration, counters, salts, trees, wide pipes or tweaks. Novelty and
security still require literature review and external cryptanalysis.

Primary comparison sources include the HAIFA proposal
([Biham–Dunkelman](https://eprint.iacr.org/2007/278)), the impossibility result
for short black-box collision-resistant combiners
([Pietrzak](https://eprint.iacr.org/2006/348)), the wide-/double-pipe design
principle ([Lucks](https://www.iacr.org/archive/asiacrypt2005/472/472.pdf)),
the herding attack ([Kelsey–Kohno](https://eprint.iacr.org/2005/281)), NIST's
standardized [TupleHash and ParallelHash](https://csrc.nist.gov/pubs/sp/800/185/final),
the Cohen–Pietrzak
[proof of sequential work](https://eprint.iacr.org/2018/183),
[PBKDF2](https://www.rfc-editor.org/info/rfc8018/),
[Argon2](https://www.rfc-editor.org/rfc/rfc9106.html), and the CFRG
[Ed25519 specification](https://datatracker.ietf.org/doc/html/rfc8032). This is
a scoped comparison set, not a claim that the literature search is complete.

## 11. Claim boundaries and review checklist

- Multiple branch widths are not added as “security bits” without `J`.
- Multiple consecutive states are not a proof of their prefix.
- SHA3-512 and SHAKE256 share Keccak structure; domain separation is not
  primitive independence.
- PoW verification recomputes all work and is neither succinct nor asymmetric.
- Argon2id supplies the KDF's memory hardness; Sigma supplies deterministic
  binding and overhead.
- Python is not claimed constant-time. Native leakage claims need a reviewed
  native core and measurements.
- No ASIC, energy or resistance claim exists without RTL and synthesis data.
- All theorem-to-code mappings require frozen vectors and reproducible tests.
- External cryptographic review remains a release dependency.
