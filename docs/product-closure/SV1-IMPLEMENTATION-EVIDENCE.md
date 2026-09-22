# SV1 — Trajectory Checkpoint Implementation Evidence

Status: **COMPLETE — ALL-INDEX RUNTIME GATE + REVIEW PASSED**  
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

## 9. Executed closure gate

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

Executed on GitHub Actions run `35783661720` against commit
`5fa4ddc38a159742866acc2ed6a81aa2bdbfa4d4`.

Result:

    passed = true
    closure_eligible = true
    evaluations = 60
    all_index_cases = 1,214
    directed_mutations = 1,946
    source_rebinds = 30

Frozen streams:

    checkpoint:
    5e4205ef191c7fd53553d88383ec617b3e8424f85ff33df0a246d8d0faf72ec6

    continuation digest:
    26f5f9d4ed8df5b51de0c7bb74c158c276acf7e9342c58ac790b1b05b1516fe9

Frozen report:

    SV1-GATE-REPORT.json

Report SHA-256:

    0c67644a01d0537999af18e2c0dbfec2e1748a0a86ecbaa180b8513fdbe4ccae

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

SV1-O01 continuation equivalence — **PASS**  
SV1-O02 final digest identity — **PASS**  
SV1-O03 binding/context/parameters immutable — **PASS**  
SV1-O04 round index exactness — **PASS**  
SV1-O05 internal checkpoint distinct from source verification — **PASS**  
SV1-O06 checkpoint codec canonical — **PASS**

These dispositions are now supported by the executed all-index gate and focused
test suite.

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

## 13. Runtime findings and final disposition

The first full-chain execution exposed one real source-rebind edge case: a wrong
source can derive a shorter trajectory, making the checkpoint index unavailable.
The API initially raised ValueError.

Remediation:

    wrong source with shorter reevaluated trajectory -> false

rather than exception.

The subsequent isolated run passed:

    compileall PASS
    Ruff PASS
    Mypy PASS
    pytest 41 passed, 1 skipped
    SV1 gate PASS

Manual post-execution review:

    SV1-O01..SV1-O06 PASS

Final status:

    SV1 COMPLETE

No empirical performance claim is introduced by this closure.
