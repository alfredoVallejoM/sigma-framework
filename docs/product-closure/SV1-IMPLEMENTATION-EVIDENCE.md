# SV1 — Trajectory Checkpoint Implementation Evidence

Status: **CANDIDATE — SEMANTIC IMPLEMENTATION/REVIEW COMPLETE; RUNTIME GATE PENDING**  
Reviewed implementation baseline: `2c47a2fff90e1000b20e6917e574df29cb2dc238`  
SV0 baseline: `03f8663c12187388c3e67de6958bd58921aaa45b`  
Date: 2026-09-22

## 1. Scope

SV1 adds internal trajectory checkpoint/continuation after Sigma v3 has already
derived context, persistent binding and trajectory parameters.

Implemented:
- `sigma/trajectory/checkpoint_v3.py`;
- additive exports in `sigma/trajectory` and `sigma/v3.py`;
- `reference/trajectory_checkpoint_v3.py`;
- unit/differential tests;
- `scripts/product_closure/sv1_gate.py`.

No evaluator, layout, binding, frame or digest implementation is modified.

## 2. Distinction from SigmaCheckpointV3

Existing `sigma.incremental_v3.SigmaCheckpointV3`:
- checkpoints a source prefix;
- stores a provisional digest;
- reevaluates the source prefix.

SV1 `TrajectoryCheckpointV1`:
- checkpoints internal state S_i/H_i after P_X,t,k exist;
- contains no source bytes;
- continues the round trajectory directly.

The two types/APIs are intentionally distinct.

## 3. Corrected minimal state

The original planning tuple (C,P_X,t,k,i,H_i,S_i) is insufficient for checkpoints
inside the public window.

SV1 therefore stores:

    Q_i =
      C,
      P_X,
      t,k,
      i,
      S_i,
      H_i?,
      W_i

with:

    W_i = states[t:i] if i>t else ().

Invariant:

    len(W_i)=max(0,i-t).

This is the minimal additional state required to reconstruct the exact final
TrajectoryWindow from every valid index.

## 4. Wire

Magic:

    SIG3TCK0

Strict record v3 fields:
1. context;
2. binding;
3. parameters;
4. round/state index;
5. current state;
6. optional current history;
7. public-window prefix.

Nested objects use their existing canonical codecs.

## 5. All-index continuation

For every valid:

    i in [0,t+k-1]

`checkpoint_from_evaluation_v3(E,i)` creates Q_i.

`continue_trajectory_checkpoint_v3(Q_i)` returns:
- states[i:];
- histories[i:] for history suites;
- exact final SigmaDigestV3.

`advance_trajectory_checkpoint_v3` rejects negative advances and advances beyond
the final state; no rewind/wrap/skip fallback exists.

## 6. Independent reference

`reference/trajectory_checkpoint_v3.py` imports no Sigma package.

It consumes the dictionary returned by `reference.independent_v3.evaluate_suite`
and independently serializes Q_i.

Differential tests require product checkpoint wire == reference wire for **every
valid index** across all six executable v3 suites.

## 7. Source rebind

`verify_trajectory_checkpoint_source_v3(source,Q_i)`:
1. reevaluates v3 on source;
2. reconstructs Q_i;
3. compares canonical bytes.

Internal continuation itself performs no source I/O.

Correct-source and wrong-source tests are present.

## 8. Codec/adversarial coverage

Tests cover:
- mutated parameters;
- cross-suite context;
- wrong H_i index;
- non-canonical window-prefix length;
- negative/after-final advance;
- final-state checkpoint;
- missing/duplicate/reordered/unknown TLV fields;
- state/history/window-prefix mutations.

## 9. Gate prepared

`sv1_gate.py` requires:
- >=60 independent evaluations;
- every valid checkpoint index in every evaluation;
- >=500 directed mutations;
- >=30 source-rebind checks;
- all six executable suites.

For every index it requires:
- exact independent checkpoint wire;
- exact continuation state suffix;
- exact history suffix;
- exact final digest;
- codec round-trip.

The gate produces deterministic checkpoint/digest stream hashes.

## 10. Complexity status

Structural contract is closed:

    checkpoint size = O(context+binding+state+history+k*state_size)

and:

    continuation from i
      = O((t+k-1-i)*round_cost)

without source preparation/I/O.

No empirical timing/speed claims are frozen in SV1 yet, by explicit campaign
decision.

## 11. Obligation disposition

SV1-O01 continuation equivalence — **CANDIDATE PASS**  
SV1-O02 final digest identity — **CANDIDATE PASS**  
SV1-O03 binding/context/parameters immutable — **CANDIDATE PASS**  
SV1-O04 round index exactness — **CANDIDATE PASS**  
SV1-O05 internal checkpoint distinct from source verification — **CANDIDATE PASS**  
SV1-O06 checkpoint codec canonical — **CANDIDATE PASS**

These dispositions are based on implementation/reference/test review. Runtime
promotion still requires executing the gate.

## 12. Isolation review

SV1 does not modify:
- SigmaContextV3;
- PersistentBinding/parameter derivation;
- history functions;
- layouts;
- frame builders;
- round evaluators;
- SigmaDigestV3;
- historical corpora.

It is an additive trajectory product surface.

## 13. Promotion requirement

Current correct state:

    SV1 CANDIDATE

Promotion to COMPLETE requires:
1. SV0 COMPLETE;
2. run `python -m scripts.product_closure.sv1_gate --report .sigma/sv1-gate.json`;
3. focused SV1 tests PASS;
4. post-execution O01..O06 review.

Empirical performance characterization may be added later and is not used here
to overstate semantic closure.
