# Sigma v2-1 security analysis

Status: internal formal analysis for the frozen v2-1 construction. These
statements are not a third-party cryptographic review. “RO” below is an ideal
random-oracle model; the instantiated SHA-2/SHA-3/BLAKE2/SHAKE functions are not
proved random or independent merely because they have different names.

## Notation and games

Let `Enc` be the canonical encoding in `sigma-v2.md`, `C` a valid context,
`A_C(M)` the complete encoded anchor evidence, and `F` the registered state
function with output width `n`. Define

`S_0 = F(DST_init || Enc(C,A))` and
`S_(i+1) = F(DST_round || Enc(C,i,A,S_i))`.

The digest segment is `D_(t,k)(M,C) = Enc(C,S_t,...,S_(t+k-1))`. An anchor has
effective collision strength `a` when the best permitted adversary needs about
`2^(a/2)` work to collide it; its physical byte length is not, by itself, `a`.
All bounds count distinct, validly encoded queries and include an explicit
`epsilon` term for violated freshness, encoding bugs, or deviation from the
stated idealized model.

## TH-01 — Canonicality

**Statement.** `Enc` is injective on valid contexts, anchor records, tree nodes
and digest records. For a fixed suite and input byte string, every conforming
backend computes the same mathematical value.

**Argument.** Fixed-width big-endian integers have a unique representation.
Each TLV has a fixed header; tags are strictly increasing and unique; every
container carries its exact length/count; and decoders reject unknown, missing,
truncated or trailing data. Parsing is therefore a left inverse of encoding,
which proves injectivity on accepted values. A branch transcript ends in the
fixed `BRANCH_END` tag and `|M|:u64`; equality fixes the message length and hence
the boundary and bytes of `M`. Tree leaves and nodes additionally bind index,
range, height and byte length. Backend, adapter, read size and worker count are
absent from `C` and from the mathematical algorithms. Backend equality is a
conformance obligation tested by EXP-01, not a consequence that arbitrary code
inherits automatically.

## TH-02 — Anchor binding

**Statement.** A StreamWide or CrossWide anchor collision for distinct
`(C,M)` yields equal message length and a collision in every retained branch.
For TreeWide, it yields for every retained branch either an underlying hash
collision at a leaf/node or identical canonical leaf sequence. CrossWide cannot
be weaker than its retained root vector merely because connections are added.

**Reduction.** Parse equal evidence using TH-01. Algorithm identifiers and root
lengths align uniquely, so every corresponding root is equal. For distinct
branch transcripts, this is a collision in that branch. CrossWide serializes
the original roots before all connections; deleting the connection suffix gives
the same reduction. Recursing from an equal TreeWide root over unequal canonical
trees reaches the first unequal pair of inputs with equal output for the
corresponding registered hash. Consequently, for any selected retained branch
`j`, an anchor-collision adversary becomes a collision adversary against `H_j`
with essentially the same work. This is the conservative “at least one sound
branch” claim. Additive `m*n` strength requires an additional joint-independence
assumption that v2-1 does not assert.

## TH-03 — Non-coalescence under reinjection

**Statement.** If `A != A'` and `S_i = S'_i`, then the two encoded round queries
at level `i` are distinct. In an `n`-bit RO, conditioned on the existing view,
`Pr[S_(i+1)=S'_(i+1)] = 2^-n` when both queries are fresh.

**Proof.** The anchor occupies its own TLV. By TH-01, unequal anchors cannot
produce equal encoded round inputs even when context, index and state agree.
Fresh RO answers to distinct inputs are independent uniform `n`-bit strings.
Without anchor reinjection, equal states and indices give the same query and
coalescence has probability one. EXP-03 illustrates this distinction at reduced
width; it does not validate SHA3-512 as an RO.

## TH-04 — Collision of a consecutive segment

**Statement.** For `q` distinct messages and fixed valid `C`, under fresh,
domain-separated RO queries,

`Adv_coll(D_(t,k),q) <= Adv_coll(A,q) + binom(q,2)*2^(-k*n) + epsilon`.

**Proof sketch.** Split on whether any message pair has equal anchors. The first
event is bounded by anchor collision advantage. Otherwise anchors differ. For a
fixed pair to share `S_t`, its distinct query outputs must match; conditioned on
that match, TH-03 gives another independent `2^-n` factor for every subsequent
state while queries remain fresh. Multiplying gives `2^(-k*n)` and a union bound
over pairs gives the formula. `epsilon` accounts for internal repeated queries,
domain overlap or non-ideal instantiation. The statement does not claim that
two published states contain a proof of how `S_t` was obtained.

## TH-05 — Generic classical work

**Statement.** If the anchor exposes `a` effective collision bits and the
segment behaves as `k*n` independent constrained bits, generic collision work is
approximately

`2^(min(a,k*n)/2) * (C_A + (t+k-1) C_R)`.

Generic target/preimage work is approximately

`2^min(a,k*n) * (C_A + (t+k-1) C_R)`.

**Justification.** The reachable segment space cannot exceed either the anchor
image or the segment range. Birthday search takes the square root of the smaller
effective range; target search takes the range itself. These are model-based
generic estimates, not unconditional lower bounds, post-quantum estimates, or
claims about a concrete branch's cryptanalysis. EXP-02 tests only reduced-width
scaling and explicitly records censored trials.

## TH-06 — Sequential depth per candidate

**Statement.** Evaluating one candidate to `D_(t,k)` requires
`t+k-1` adaptive transition levels after `S_0`, unless the evaluator guesses an
intermediate state or violates the transition assumptions.

**Proof.** The query for level `i+1` contains `S_i`; its complete input is
unknown before level `i` returns. Branches inside one Deep level can run in
parallel, but the fold output is required by the next level. Independent
candidates can be evaluated concurrently. Thus candidate throughput and
per-candidate critical depth are different quantities. EXP-06 reports both
exact query accounting and wall time; timing regression is not the proof.

## TH-07 — Conservative combiner robustness

**Statement.** For a concatenated retained-root anchor, collision resistance is
preserved if at least one retained branch remains collision resistant on the
canonical transcript.

**Reduction.** An anchor collision makes every retained component equal. Select
any branch covered by the assumption and return the two distinct transcripts as
its collision. Constant or correlated broken branches do not invalidate that
reduction for the selected sound branch. Connections may improve diffusion or
fault coverage but are not credited with extra security in this conservative
bound. `Psi`, CrossOnly and independence-based sums are outside this theorem.

## TH-08 — Input entropy bound

**Statement.** If candidate messages have min-entropy `h`, Sigma cannot raise
the cost of enumerating that message source beyond roughly `2^h` candidates;
it only multiplies per-candidate evaluation cost.

**Argument.** The digest is a deterministic public function of message and
context. An adversary enumerates the same ranked dictionary, evaluates Sigma
for each candidate and compares the digest. No deterministic post-processing
adds uncertainty about the original message. Password applications therefore
require a standard salted memory-hard KDF such as Argon2id; any Sigma layer must
be compared against Argon2id alone.

## TH-09 — Adjacent verification is not history verification

**Statement.** Checking `S_(t+1)=F(C,A,t,S_t)` proves only that single edge. It
does not prove that `S_t` equals the state obtained from `S_0` after `t` levels.

**Counterexample.** Choose any 512-bit value `X`, compute one public transition
`Y=F(C,A,t,X)`, and present `(X,Y)`. The edge verifies regardless of whether `X`
belongs to the canonical trajectory. Full verification must recompute the
anchor and all preceding transitions, as `verify_full` does, or use a separately
specified proof-of-sequential-work protocol. Sigma v2-1 contains no such proof.

## Instantiation and review limits

- SHA3-512 is used both as one anchor branch and as the state/fold hash under
  disjoint prefixes. This is domain separation, not a proof of independence.
- SHA3-512 and SHAKE256 share Keccak structure. No orthogonality claim is made.
- Multi-state output cannot exceed the effective binding of its anchor.
- Python is not constant-time and EXP-13 is gated on a native implementation.
- No hardware, energy, ASIC-resistance, signature, authentication, KDF or PoW
  security property follows from TH-01–TH-09. The optional application modules
  are compositions with separate assumptions, not consequences of these theorems.
- External cryptographic review remains required before production use.
