# SV0 — Trajectory Audit Implementation Evidence

Status: **CANDIDATE — IMPLEMENTATION/ADVERSARIAL DESIGN REVIEW COMPLETE; RUNTIME GATE PENDING**  
Reviewed implementation baseline: `799332dac40e3bc11a6ec1e4b588b55a4331bbb6`  
ST5 baseline: `e283a2630965656c1629c692899f2a0f620dac33`  
Date: 2026-09-22

## 1. Scope

SV0 adds an observational product surface over the existing Sigma v3 evaluation
objects.

Implemented:

- `sigma/trajectory/audit_v3.py`
- `sigma/trajectory/__init__.py`
- additive public exports in `sigma/v3.py`
- `reference/trajectory_audit_v3.py`
- `scripts/product_closure/sv0_gate.py`
- `scripts/product_closure/sv0_benchmark.py`
- unit/differential/frozen-corpus tests.

SV0 does not alter the function that computes Sigma v3.

## 2. No-interference architecture

The dataflow is one-way:

    evaluate_v3(source)
      -> EvaluationV3
      -> audit_from_evaluation_v3(EvaluationV3)

No trajectory evaluator imports or calls TrajectoryAuditV3.

The ST5->SV0 branch diff does not modify:

- sigma/binding/*
- sigma/layout/*
- sigma/rounds/*
- sigma/outputs/digest_v3.py
- sigma/spec/ids_v3.py
- the R12 or R12.5 conformance corpora
- any frozen ST0-ST4 vectors.

The only existing product facade modified is `sigma/v3.py`, additively exporting
the new audit API.

Therefore the implementation structure itself enforces that audit construction
cannot influence the evaluated digest.

## 3. Canonical wire

Top-level:

    SIG3AUD0

Per-round record:

    SIG3AUR0

Both reuse record version 3 and the existing strict TLV codec.

No new:
- SuiteIdV3;
- DomainIdV3;
- AlgorithmId;
- cryptographic primitive;
- security parameter

is introduced.

## 4. COMPACT

COMPACT contains:

- exact SigmaDigestV3;
- exact PersistentBinding;
- exact init layout wire;
- every state S_i;
- every history H_i for HISTORY_FEEDBACK suites;
- exact round layout wires.

FULL-only fields are required to be empty.

COMPACT does not invent hashes/IDs for omitted frames. Replay deterministically
reconstructs those frames from the existing v3 authorities.

## 5. FULL

FULL contains all COMPACT evidence plus exact existing v3 wires:

- RoundBindingV3 for history suites;
- RoundFrame/VectorRoundFrame or history variants;
- DeepBranchFrame/history variants;
- branch outputs;
- DeepFoldFrame/history variant only for scalar Deep.

DeepVector has no fold frame because its successor is the full branch vector.

## 6. Replay layers

Structural replay:

    verify_trajectory_audit_structure_v3(audit)

does not receive the source.

It validates internal trajectory consistency from:
- context;
- persistent binding;
- states;
- histories;
- layouts;
- existing v3 framing and hash laws.

A positive result does **not** claim that the persistent binding came from a
specific current source.

Full source verification:

    verify_trajectory_audit_full_v3(source,audit)

reevaluates Sigma v3 from the source, reconstructs the audit in the same mode and
requires canonical byte equality.

This is the SV0 message-binding API.

## 7. Independent encoder

`reference/trajectory_audit_v3.py` is stdlib-only and imports no Sigma package.

It consumes the dictionary produced by the already-independent
`reference.independent_v3.evaluate_suite()` and independently encodes:

- SIG3AUD0;
- SIG3AUR0;
- COMPACT;
- FULL.

The differential test requires product audit bytes to equal this independent
encoding for all six executable suites.

## 8. Frozen R12.5 replay

SV0 does not create a second cryptographic corpus.

The blocking vector test consumes the existing frozen:

    specification/test-vectors/conformance-v3-r12-5.json.gz.b64

and requires for suites 0x0321 / 0x0323 / 0x0324:

- exact existing digest_hex;
- exact existing histories;
- state cardinality t+k;
- product COMPACT == independent audit encoding;
- product FULL == independent audit encoding;
- structural replay PASS;
- full source replay PASS.

Existing frozen digest SHA-256 values remain authoritative:

    0x0321
    7a193b729984b4000d86ae97db449164dc7e1dbbde18f343216e2043d275e63b

    0x0323
    f20d6f602264a5b024651faa9da29a3adbb4f9df9345c19dcab82dc119193258

    0x0324
    a2305b9e18a873224ddedef1f6dd6938d199b0bdfc1b59dfd3d37fcd41ee3809

No frozen v3 vector file is modified by SV0.

## 9. Closure gate prepared

`scripts/product_closure/sv0_gate.py` enforces:

- >=600 differential cases;
- all six executable v3 suites;
- R12.5 frozen replay;
- product vs independent audit byte equality;
- COMPACT/FULL digest projection equality;
- canonical codec round-trip;
- t+k / t+k-1 cardinality;
- >=2,000 directed mutations;
- >=60 correct/wrong source-binding replays;
- Deep vs DeepVector semantic checks;
- security_width_claim=false.

The gate produces deterministic stream hashes for:
- COMPACT audit wires;
- FULL audit wires;
- projected digests.

Those hashes are intentionally not fabricated in this document: they become
evidence only after the gate is executed.

## 10. Mutation/adversarial coverage

Implemented mutations include:

- S_0 bit mutation;
- H_i digest mutation;
- layout wire mutation;
- state-frame mutation;
- branch-output mutation;
- missing round;
- non-contiguous round index;
- COMPACT carrying FULL-only evidence;
- wrong Deep branch count;
- missing scalar fold frame;
- unexpected DeepVector fold frame.

Expected disposition is constructor reject or structural replay false.

## 11. Complexity ledger

`scripts/product_closure/sv0_benchmark.py` covers all six suites in COMPACT/FULL.

It records:

- t;
- k;
- state count;
- transition count;
- state size;
- audit wire bytes;
- build-from-existing-evaluation time;
- structural replay time;
- allocation peak.

Derived contract:

    R = t + k - 1

COMPACT construction from an existing evaluation:

    O(compact audit output size)

FULL construction:

    O(full audit output size)

Structural replay:

    O(R * registered round transition cost)

with no source I/O.

Full source verification:

    O(evaluate_v3(source) + audit compare)

Timing evidence remains local EMPIRICAL-PERFORMANCE.

## 12. Disclosure boundary

TrajectoryAudit is not a privacy surface.

COMPACT exposes:
- PersistentBinding;
- every S_i;
- every H_i where applicable;
- layouts.

FULL additionally exposes:
- round bindings;
- state frames;
- branch frames;
- branch outputs;
- fold frames.

A later Artifact/Receipt must therefore attach an audit only under explicit
disclosure policy.

## 13. Obligation review

### SV0-O01 — Audit projects exact SigmaDigestV3

**CANDIDATE PASS.**

The audit embeds the exact SigmaDigestV3 produced by
`digest_from_evaluation_v3`. Product/reference and frozen corpus tests require
byte equality.

Runtime closure still requires executing sv0_gate.py.

### SV0-O02 — Audit replays successfully

**CANDIDATE PASS.**

Structural and full-source replay APIs are implemented and their semantic roles
are separated. Unit, differential and frozen-corpus tests are present.

Runtime gate pending.

### SV0-O03 — Round cardinality matches t/k

**CANDIDATE PASS.**

The constructor enforces:

    states = t+k
    rounds = t+k-1

and contiguous round indices.

### SV0-O04 — Historical causality H_i -> H_i+1 exact

**CANDIDATE PASS.**

Replay uses the existing `history_seed_v3` and `history_step_v3` authorities.
History mutation tests and frozen R12.5 histories are wired into the suite.

### SV0-O05 — Audit links exact layout/frame identities

**CANDIDATE PASS.**

Layouts are exact existing wires.

FULL stores exact canonical frame wires rather than introducing a new hash or
identity scheme.

### SV0-O06 — Deep vs DeepVector semantics preserved

**CANDIDATE PASS.**

Scalar Deep requires fold-frame replay.

DeepVector requires vector concatenation and forbids a fold frame.

Both R12 and R12.5 suite families are included in differential coverage.

### SV0-O07 — COMPACT/FULL project same digest

**CANDIDATE PASS.**

Both modes are projections of the same immutable EvaluationV3 and share
digest/states/histories/layouts by construction and tests.

### SV0-O08 — Audit makes no security-width claim

**PASS BY DESIGN/DOC AUDIT.**

No SV0 type, wire, documentation or gate adds nominal security bits.

FULL is described as more inspectable evidence, not a stronger primitive.

## 14. Adversarial findings

Finding A — initial planning proposed abstract frame identities/hashes  
Status: **REMOVED**. FULL stores exact canonical existing wires; COMPACT derives them.

Finding B — structural replay could be confused with message binding  
Status: **FIXED** by separate structural/full-source APIs and documentation.

Finding C — planned TrajectoryCheckpoint magic collided with Tree checkpoint name  
Status: **FIXED** in functional namespace planning; SV1 reserves a distinct trajectory magic.

Finding D — Audit disclosure was under-specified  
Status: **FIXED** with explicit disclosure boundary.

Finding E — creating a second SV0 cryptographic corpus would duplicate authority  
Status: **REJECTED**. Existing R12.5 corpus remains authoritative.

No unresolved design blocker remains.

## 15. Isolation review

Diff from ST5 baseline is additive/observational.

No change to:
- v3 context;
- binding;
- parameters;
- history functions;
- layouts;
- round evaluators;
- frame builders;
- SigmaDigestV3;
- suite/domain IDs;
- frozen R12/R12.5 vectors.

This satisfies the SV0 design-side no-interference requirement.

## 16. Why status is CANDIDATE, not COMPLETE

The implementation, reference, tests, gate, complexity ledger and adversarial
design review are present.

However this execution environment does not expose a complete checkout and the
container cannot resolve github.com. Therefore the required closure command has
not been executed here:

    python -m scripts.product_closure.sv0_gate \
      --report .sigma/sv0-gate.json

Nor has the resulting report been frozen and reviewed.

Claiming COMPLETE without that execution would violate the campaign's own closure
rule.

Required promotion sequence:

1. run sv0_gate.py from a real checkout;
2. run the focused SV0 unit/differential/vector tests;
3. retain the JSON gate report;
4. review any divergence/failure;
5. if PASS, change SV0-O01..O08 and SV0 to COMPLETE.

## 17. Disposition

Manual implementation/adversarial review:

    PASS

Runtime closure gate:

    PENDING

Current correct status:

    SV0 CANDIDATE
