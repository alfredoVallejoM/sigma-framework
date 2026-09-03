# Sigma v2-1 and v2-2 wire specification

Status: v2.1 compatibility bytes and the implemented v2.2 experimental family
are frozen for interoperability. Gates R1–R3 are closed locally; R4–R6 and
external review remain open. This denotes byte-level stability, not a security
audit or production claim. Any incompatible change requires a new version or
identifier and deliberate vector regeneration.

The security obligations and their explicit assumptions are stated separately
in `security-analysis.md`.

## Integer and TLV encoding

All integers are unsigned, fixed-width and big-endian. A TLV field is
`tag:u16 || length:u32 || value:length`. Tags are positive, unique and strictly
increasing. Parsers reject unknown tags, omitted required tags, truncation,
trailing bytes and values outside documented limits.

## `SigmaContextV2`

Envelope: `"SIGMACTX" || version:u16(2) || body_length:u32 || body_tlvs`.

| tag | field | representation |
|---:|---|---|
| 1 | suite | registered u16 |
| 2 | anchor profile | registered u16 |
| 3 | round profile | registered u16 |
| 4 | output profile | registered u16 |
| 5 | target round `t` | u32, 0..1,000,000 |
| 6 | state count `k` | u16, 1..16 |
| 7 | branch algorithms | count:u16 then registered u16 values |
| 8 | canonical tree chunk size | u32; zero means not applicable |
| 9 | salt | bytes, at most 4096 |
| 10 | challenge | bytes, at most 4096 |
| 11 | application context | bytes, at most 4096 |

The execution backend, adapter, read buffer and worker count are deliberately
absent. Total message length is authenticated by anchor finalization because it
may be unknown when this context is constructed.

Initial registry values live in `sigma/spec/ids.py`. Suite `0x0001` identifies
the frozen reference StreamWide/WideOnce construction.

## `SigmaDigestV2`

Envelope:
`"SIGMADG2\\0" || context_length:u32 || context || state_count:u16 || states`.
Each state is `state_length:u16 || state`. There must be exactly `k` states,
each with the exact `state_size` registered by the selected suite (64 bytes for
scalar suites and 256 bytes for the four-component DeepVector suite), and no
trailing bytes.
`.hex()` encodes this complete envelope, never a bare final state.

## Normative transcript domains

Every domain tag is `"SIGMADST" || domain_id:u16`. Registered IDs are:
branch=1, branch-end=2, anchor-evidence=3, init=4, round=5, cross=6,
deep=7, fold=8, output=9, tree-leaf=10, tree-node=11 and tree-empty=12.
The v2.2 application/vector additions are signed-commitment=13,
vector-init=14 and vector-round=15. Reusing an ID for different semantics is
forbidden.

For branch `j`, indexed from zero, the branch prefix is:

`DST(branch) || TLV(1,j:u16; 2,algorithm_id:u16; 3,context)`.

The complete branch input is prefix, the exact message bytes, then
`DST(branch-end) || message_length:u64`. The four draft-1 algorithms, in fixed
order, are SHA-512, SHA3-512, BLAKE2b with a 64-byte digest, and SHAKE256 with
exactly 64 output bytes. SHA3 and SHAKE share the Keccak family; no independence
or “orthogonality” is presumed.

`AnchorEvidence` is `DST(anchor-evidence) || count:u16`, followed for every
root by `algorithm_id:u16 || root_length:u16 || root`, followed by
`message_length:u64`. Draft-1 retains all four 64-byte roots (2048 physical
bits) and never passes them through `Psi`.

Let `A` be that complete evidence encoding and `C` the context encoding. With
`F = SHA3-512`:

`S_0 = F(DST(init) || TLV(1,C; 2,A))`

`S_(i+1) = F(DST(round) || TLV(1,C; 2,i:u64; 3,A; 4,S_i))`

The output contains exactly `S_t` through `S_(t+k-1)`. A full verifier
recomputes branch roots, anchor and every preceding state. Adjacent-only
verification checks one transition and explicitly does not prove its history.

## Typed anchor evidence v2-2

Suite IDs `0x0101..0x0106` select the v2-2 evidence family. They do not alter or
reinterpret any `0x0001..0x0006` bytes. The new envelope is:

`"SIGMAAE" || evidence_version:u16(2) || evidence_type:u16 || suite_id:u16 || body_length:u32 || body_tlvs`.

Evidence type 1 is `WIDE_ROOTS`; type 2 is `CROSS_WIDE`. Both bodies contain:

| tag | field | representation |
|---:|---|---|
| 1 | message length | u64 |
| 2 | roots | `count:u16`, then ordered `algorithm_id:u16 || length:u16 || root` |

`CROSS_WIDE` additionally requires tag 3 with connections in the same component
encoding and algorithm order. The suite ID must equal the context suite. Counts,
algorithm IDs, order and 64-byte component lengths must equal its registered
descriptor. A v2-2 round refuses legacy untyped evidence, even if its components
otherwise appear compatible.

For the Deep suite, every transition first computes one `Z_(i,j)` per branch
using `DST(deep)` and TLVs for context, round index, algorithm ID, complete
CrossWide evidence and current state. The ordered vector of algorithm ID,
length and `Z_(i,j)` values is then hashed by SHA3-512 under `DST(fold)`, again
with context, round index and complete anchor. Branches within a level may run
in parallel; level `i+1` cannot start before the fold of level `i`.

DeepVector suite `0x0106` deliberately removes that fold. Its state is the
ordered concatenation `V_i = S_i^1 || ... || S_i^m`, with every component fixed
to the registered 64-byte anchor-component width. Initialization is:

`S_0^j = H_j(DST(vector-init) || TLV(1,C; 2,A; 3,j:u16))`.

Every subsequent component consumes the complete prior vector:

`S_(i+1)^j = H_j(DST(vector-round) || TLV(1,C; 2,i:u64; 3,A; 4,V_i; 5,j:u16))`.

The digest publishes `V_t..V_(t+k-1)` as fixed 256-byte states. This avoids a
single fold bottleneck but does not imply additive security across deterministic
connections; any stronger claim requires an explicit joint assumption.

## Sigma Tree v2.1/v2.2

Suites `0x0003` and `0x0103` use a fixed leaf size of 65,536 bytes. Read-call
boundaries and worker count are execution details: bytes are rechunked into consecutive leaves
of that exact size, except for a final shorter leaf. An empty message has no
leaf. No odd leaf or subtree is duplicated.

For branch algorithm `H_j`, leaf `i` is:

`H_j(DST(tree-leaf) || TLV(1,C; 2,H_j:u16; 3,i:u64; 4,len:u32; 5,bytes))`.

Perfect adjacent subtrees of equal leaf count are combined eagerly. At EOF the
remaining power-of-two frontier is folded from right to left. This is equivalent
to recursively splitting a non-singleton tree at the largest power of two
strictly smaller than its leaf count. It is Sigma Tree v2, not RFC 6962.

A node hashes `DST(tree-node)` followed by TLVs for context, algorithm, resulting
height (`u32`), starting leaf (`u64`), leaf count (`u64`), cumulative byte length
(`u64`), left digest and right digest. The empty root uses `DST(tree-empty)` and
TLVs for context, algorithm and zero length. The streaming reference retains at
most one frontier subtree per power of two and one leaf buffer: O(log N) state.

## Frozen preset suites

| ID | preset | anchor | rounds | branches |
|---:|---|---|---|---|
| 1 | reference-stream-wide-v2-1 | StreamWide | WideOnce | SHA-512, SHA3-512, BLAKE2b-512, SHAKE256-512 |
| 2 | paranoid-wide-v2 | CrossWide | WideOnce | four reference branches |
| 3 | simultaneous-v2 | TreeWide | WideOnce | four reference branches |
| 4 | lightweight-v2 | StreamWide | WideOnce | SHA-512, SHA3-512 |
| 5 | realtime-v2 | StreamWide | WideOnce | SHA-512, SHA3-512 |
| 6 | paranoid-deep-v2 | CrossWide | Deep | four reference branches |
| 257 | reference-stream-wide-v2-2 | StreamWide | WideOnce | four reference branches |
| 258 | lightweight-v2-2 | StreamWide | WideOnce | SHA-512, SHA3-512 |
| 259 | simultaneous-v2-2 | TreeWide | WideOnce | four reference branches |
| 260 | paranoid-wide-v2-2 | CrossWide | WideOnce | four reference branches |
| 261 | paranoid-deep-v2-2 | CrossWide | Deep | four reference branches |
| 262 | paranoid-deep-vector-v2-2 | CrossWide | DeepVector | four reference branches |

Presets have distinct suite IDs and therefore distinct contexts and digests.
Backend name, worker count, mmap use and reader buffer size are never encoded.

## Optional application encodings

These alpha profiles compose registered suites; they do not create new suite
security claims. `PowParameters` currently composes frozen reference suite
`0x0001` and encodes `"SIGMAPOW2"` followed by strict
TLVs for challenge, `t:u32`, `k:u16`, predicate ID and difficulty bits. Work
messages encode the exact payload and `nonce:u64` as separate TLVs. Predicate 1
checks leading zero bits of `S_t`; predicate 2 applies the configured per-state
difficulty to both `S_t` and `S_(t+1)`; predicate 3 checks leading zero bits of
the concatenated published states. Full verification recomputes all work.

`Argon2idParameters` encodes `"SIGMAKDF2"` and memory KiB, time cost,
parallelism, output length and Argon2 version 1.3. The composition computes
Argon2id first, then hashes that key with a Sigma context containing the salt
and encoded parameters. It adds deterministic binding and overhead, not
password entropy or independent memory hardness.

The v2-2 composition never returns the intermediate Argon2id key. It hashes the
intermediate under `lightweight-stream-wide-v2-2`, binding
`"SIGMA-KDF-FINAL-V1" || parameters` as application context, and derives the
requested final length with SHAKE256 over that domain plus canonical TLVs for
parameters, salt and complete Sigma digest. `SigmaKdfResult` encodes
`"SIGMAKDR2"` followed by strict TLVs 1=parameters, 2=salt, 3=Sigma digest and
4=final key. The parser recomputes the final derivation and rejects inconsistent
records. Password verification reconstructs the exact recorded v2.2 context,
recomputes the composition and compares final keys with a constant-time
comparison provided by the runtime. The registered post-processing choices are
Lightweight Wide, Paranoid Wide, Paranoid Deep and Paranoid DeepVector v2.2;
all preserve the same Argon2 budget selected by the caller.

`SigmaSignedCommitmentV2` is a separate envelope, not a digest or a new
signature primitive:

```text
"SIGMASIG" || version:u16(2) || TLV(
  1=context,
  2=typed_anchor_evidence,
  3=count:u16 || repeated(state_length:u16 || state),
  4=signature_algorithm:u16,
  5=public_key_id,
  6=signature
)
```

Only v2.2 suites and Ed25519 (`algorithm_id=1`) are accepted. `public_key_id`
is 1..255 opaque bytes and key resolution remains an application responsibility.
The signature input is `DST(signed-commitment) || unsigned_envelope`, where the
unsigned envelope includes fields 1..5. Attestation verification authenticates
that declaration only; full signed verification additionally recomputes the
message anchor and complete trajectory. Neither operation turns one adjacent
edge into proof of its prefix.

## Operational acceptance and file consistency

`ResourcePolicy` is deliberately not serialized into a digest. It distinguishes
well-formed/suite-valid objects from values acceptable to a local consumer and
sets bounds for message size, rounds, states, PoW attempts/difficulty and Argon2
cost. Applications must supply a policy appropriate to their threat model;
accepting the package default is an explicit local decision.

File hashing holds a stable descriptor and validates device, file identifier,
size, mtime and ctime before and after reading. Multiprocessing paths operate on
a private immutable snapshot so that workers share one byte image. A detected
replacement or mutation aborts instead of returning a digest over mixed file
states.

Primitive-input capture is diagnostic and disabled by default. When enabled it
records the complete algorithm/input pair actually delivered to each primitive
for conformance and domain-separation audits. It does not alter the normative
function or establish independence between concrete hash algorithms.
