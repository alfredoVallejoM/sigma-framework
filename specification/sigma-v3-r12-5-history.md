# Sigma v3 R12.5 — historical-feedback extension

Status: **normative implementation candidate; R12.5 adversarial gate pending**  
Date: 2026-09-20

This document specifies the post-R12 historical-feedback construction byte for
byte. The R12 specification in `specification/sigma-v3.md`, its suite IDs,
corpus and adversarial PASS remain immutable. R12.5 introduces new suite IDs and
new domains; it never reinterprets an R12 digest.

## 1. Suites and profiles

| Suite | SuiteId | Round profile | State width |
|---|---:|---:|---:|
| WideOnce-history | `0x0321` | `WIDE_ONCE=0x0301` | 64 |
| Deep-history | `0x0323` | `DEEP=0x0302` | 64 |
| DeepVector-history | `0x0324` | `DEEP_VECTOR=0x0303` | 256 |

All three use:

- `LayoutProfileIdV3.SHAKE256_HISTORY_REJECTION = 0x0321`;
- `TrajectoryProfileIdV3.HISTORY_FEEDBACK = 0x0321`;
- the same four registered hash algorithms and the same `t∈[2,32]`,
  `k∈[2,4]` ranges as their R12 controls;
- SHA3-512 as the history-commitment primitive.

The suite identifier is part of `SigmaContextV3`; therefore R12 and R12.5
anchors, signatures, parameters, states and digests are intentionally distinct
even before historical feedback is exercised.

## 2. New domains

| Domain | ID |
|---|---:|
| HISTORY_SEED | `0x0317` |
| HISTORY_STEP | `0x0318` |
| HISTORY_LAYOUT_ROUND | `0x0319` |
| HISTORY_ROUND_FRAME | `0x031a` |
| HISTORY_VECTOR_ROUND_FRAME | `0x031b` |
| HISTORY_DEEP_BRANCH_FRAME | `0x031c` |
| HISTORY_DEEP_FOLD | `0x031d` |
| HISTORY_BINDING_FIELD | `0x031f` |

The R12 transcript and hash conventions remain:

```text
TR(D, fields) = "SIGMA3TR" || uint16(3) || uint16(D) || TLV64(fields)
DST(D)        = "SIGMA3DS" || uint16(D)
H_alg(D,X)    = hash_alg(DST(D) || X)
```

Thus a history hash is domain separated both by the transcript identifier and
by the primitive wrapper exactly as other v3 hashes are.

## 3. Persistent input binding

R12.5 keeps the persistent input binding unchanged in structure:

[
P_X=(A_X,kappa_X,Lambda_X,J_X).
]

Its wire remains `SIGMA3BI`. Because the R12.5 suite ID is inside the context,
its values are nevertheless R12.5-specific.

Trajectory parameters remain derived only from `(C,P_X)`:

[
(t_X,k_X)=DeriveParameters(C,P_X).
]

Historical feedback therefore changes the round dynamics, not the already
declared `t,k` derivation.

## 4. History commitment

### 4.1 Wire

`HistoryCommitmentV3` is:

```text
record("SIG3HIST",
  1: uint64(round_index),
  2: digest[64])
```

`round_index=i` means that `H_i` commits to the strict trajectory past before
round `i`.

### 4.2 Genesis

[
T_0=TR(HISTORY_SEED,(1,C),(2,P_X))
]

[
H_0 =
SIG3HIST{
  round=0,;
  digest=H_{SHA3-512}(HISTORY_SEED,T_0)
}.
]

No synthetic `S_{-1}` exists.

### 4.3 Causal step

For round `i`, after the round has consumed `(H_i,S_i)`, define:

[
T^H_i =
TR(HISTORY_STEP,
 (1,C),(2,P_X),(3,uint64(i)),(4,H_i),(5,S_i)).
]

Then

[
H_{i+1} =
SIG3HIST{
  round=i+1,;
  digest=H_{SHA3-512}(HISTORY_STEP,T^H_i)
}.
]

Consequently `H_i` commits to `P_X,S_0,...,S_{i-1}`; it does not depend on
`S_i` until the next history value is created. This ordering is normative and
prevents circular definition.

## 5. Effective round binding

The effective round binding is

[
E_{X,i}=(P_X,H_{X,i}).
]

Its wire is:

```text
record("SIG3RDBD",
  1: PersistentBinding,
  2: HistoryCommitmentV3)
```

The public digest does not serialize `H_i`; `verify_full_v3` deterministically
reconstructs the entire history chain from the canonical source. History is an
internal causal separator, not an advertised independent security width.

## 6. History-adaptive round layout

INIT is unchanged from R12 and inserts the four persistent fields into the
canonical message.

ROUND uses five typed fields:

| field | ID |
|---|---:|
| anchor | `0x0301` |
| cardinality | `0x0302` |
| length signature | `0x0303` |
| joint signature | `0x0304` |
| history | `0x0305` |

For round `i` and current state width `L`:

[
seed_i =
TR(HISTORY_LAYOUT_ROUND,
 (1,C),(2,Lambda_X),(3,H_i),(4,uint16(ROUND)),
 (5,uint64(i)),(6,uint64(L))).
]

A SHAKE256 reader under the same domain samples one unbiased slot in `[0,L]`
for each of the five fields, in field-ID order. Rejection sampling is the R4
algorithm. Placements are then sorted by `(slot,field_id)`.

Each placement is:

```text
record("SIG3HPLC",
  1: uint16(field_id),
  2: uint64(slot))
```

The plan is:

```text
record("SIG3HPLN",
  1: uint64(round_index),
  2: uint64(base_length),
  3: TLV(placements 1..5),
  4: uint16(ROUND))
```

A placed field is:

```text
"SIG3HFLD" || DST(HISTORY_BINDING_FIELD)
             || uint16(field_id)
             || uint64(len(value))
             || value
```

The placed stream is:

```text
"SIG3HPS0" || uint16(3)
            || uint32(len(plan)) || plan
            || uint64(len(body)) || body
```

Slots refer to the original state bytes; prior insertions never shift later slot
semantics.

## 7. Round dynamics

The full dynamic state is

[
Z_i=(H_i,S_i).
]

### 7.1 WideOnce-history

[
F_i =
TR(HISTORY_ROUND_FRAME,
 (1,C),(2,uint64(i)),(3,Pi_i),(4,Place(S_i,E_i))).
]

[
S_{i+1}=H_{state}(HISTORY_ROUND_FRAME,F_i).
]

Only after this round binding is fixed is `H_{i+1}` calculated from `H_i,S_i`
as in Section 4.3.

### 7.2 Deep-history

The state frame is the WideOnce-history frame above. Each branch receives:

[
D_{i,j} =
TR(HISTORY_DEEP_BRANCH_FRAME,
 (1,C),(2,uint64(i)),(3,uint16(j)),(4,uint16(alg_j)),(5,F_i)).
]

[
R_{i,j}=H_j(HISTORY_DEEP_BRANCH_FRAME,D_{i,j}).
]

The scalar fold is:

[
Q_i =
TR(HISTORY_DEEP_FOLD,
 (1,C),(2,uint64(i)),(3,byteseq(R_{i,*}))).
]

[
S_{i+1}=H_{state}(HISTORY_DEEP_FOLD,Q_i).
]

### 7.3 DeepVector-history

The complete vector `V_i` is the base object in a
`HISTORY_VECTOR_ROUND_FRAME`. Every branch consumes that complete frame:

[
R_{i,j}=H_j(HISTORY_DEEP_BRANCH_FRAME,D_{i,j}),
qquad
V_{i+1}=R_{i,0}VertcdotsVert R_{i,3}.
]

There are no independent component chains and no scalar fold.

## 8. Required structural property

For the byte-exact construction:

[
H_i^X
e H_i^Y,quad S_i^X=S_i^Y
]

implies distinct canonical round layouts and/or placed streams and, in every
case, distinct complete round-frame bytes. Therefore equality of the observable
state alone does not make two histories the same dynamic state.

This is an encoding/construction property. Cryptographic claims about the
probability of future collisions are deferred to R13 and require explicit
assumptions about the instantiated primitives.

## 9. Conformance corpus

The frozen encoded corpus is:

`specification/test-vectors/conformance-v3-r12-5.json.gz.b64`.

It is base64(gzip(JSON)); compression is storage-only and is not part of Sigma.
The authoritative decoded JSON is exactly `render_corpus()` from
`scripts/generate_v3_r125_corpus.py`.

The corpus contains for every R12.5 suite:

- message, context, `κ,A,Λ,J,P_X,t,k`;
- INIT plan/frame;
- every `H_i`;
- every effective round-binding wire;
- every history-adaptive round plan and placement;
- round frames, Deep branch frames/outputs and folds;
- all states, header, window and digest.

Digest-wire KAT SHA-256 values:

| suite | t,k | SHA-256 |
|---|---|---|
| `0x0321` | 2,2 | `7a193b729984b4000d86ae97db449164dc7e1dbbde18f343216e2043d275e63b` |
| `0x0323` | 2,2 | `f20d6f602264a5b024651faa9da29a3adbb4f9df9345c19dcab82dc119193258` |
| `0x0324` | 2,2 | `a2305b9e18a873224ddedef1f6dd6938d199b0bdfc1b59dfd3d37fcd41ee3809` |

The independent implementation in `reference/independent_v3.py` remains
stdlib-only and evaluates both the frozen R12 controls and the R12.5 history
suites.

## 10. Claim boundary

R12.5 establishes a new deterministic function and its conformance machinery.
It does **not** establish a new numeric security strength. In particular:

- 64 history bytes are not added to state width as independent security bits;
- multi-state windows are not automatically `k*n` secure;
- multiple branch algorithms are not assumed independent;
- Python is not claimed constant-time;
- no VDF, PoSW, memory-hardness, ASIC/GPU-resistance or cheap-verification claim
  follows from historical feedback.

Those questions belong to R13–R16.
