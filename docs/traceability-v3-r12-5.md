# Sigma v3 R12.5 — implementation traceability

Date: 2026-09-20.  
Status: **implementation candidate; adversarial PASS not yet recorded**.

R12 remains an immutable ablation baseline. R12.5 is represented by new suite
IDs and new history-specific domains.

| Obligation | Implementation | Permanent evidence |
|---|---|---|
| history types/wire | `sigma/binding/history.py` | `test_v3_history_feedback.py` |
| H0 / causal H-step | `history_seed_v3`, `history_step_v3` | causal/replay tests + independent differential |
| effective binding | `RoundBindingV3` | round-trip + corpus `round_bindings` |
| history-adaptive layout | `sigma/layout/history.py` | five-field/layout differential |
| history round frames | `sigma/rounds/history_framing_v3.py` | product/reference frame equality |
| WideOnce history | `evaluate_history_wide_once_v3` | unit/differential/vector tests |
| Deep history | `evaluate_history_deep_v3` | serial/thread equality + differential |
| DeepVector history | `evaluate_history_deep_vector_v3` | vector differential |
| generic dispatch | `sigma/rounds/evaluate_v3.py` | full-verification tests |
| digest verification | `sigma/outputs/digest_v3.py` | `verify_full_v3` recomputation |
| independent oracle | `reference/independent_v3.py` | Hypothesis differential, no `sigma` imports |
| frozen corpus | `conformance-v3-r12-5.json.gz.b64` | generator `--check` + KAT test |
| parser hardening | `scripts/fuzz_codecs.py` | history/context/layout/digest mutation fuzz |
| package/release gate | `scripts/validate_project.py` | R12 + R12.5 corpus checks and wheel smoke |
| multiplatform CI | `.github/workflows/ci.yml` | Python 3.10–3.13/Linux + macOS + Windows |

## Normative chain

```text
M -> P_X=(A,kappa,Lambda,J) -> (t,k) -> Init -> S0
                                            |
                                            +-> H0=HistorySeed(C,P_X)

for i:
  E_i=(P_X,H_i)
  (H_i,state width,index) -> history-adaptive Layout_i
  (S_i,E_i,Layout_i) -> history RoundFrame_i -> S_(i+1)
  (C,P_X,i,H_i,S_i) -> H_(i+1)
```

The two outputs of a step are causally ordered by definition: the frame for
round i consumes H_i, never H_(i+1).

## R12 preservation

The old suites `0x0301/0x0303/0x0304`, their domains, specification and corpus
are not modified. `reference/independent_v3.py` continues to reproduce their
published R12 KATs. The new suites are `0x0321/0x0323/0x0324`.

## R12.5 candidate KATs

- `0x0321`: `7a193b729984b4000d86ae97db449164dc7e1dbbde18f343216e2043d275e63b`
- `0x0323`: `f20d6f602264a5b024651faa9da29a3adbb4f9df9345c19dcab82dc119193258`
- `0x0324`: `a2305b9e18a873224ddedef1f6dd6938d199b0bdfc1b59dfd3d37fcd41ee3809`

## Closure requirements still pending

R12.5 is not marked PASS until the exact final commit:

1. passes the authoritative local-equivalent gate in CI;
2. passes all platform/Python jobs;
3. regenerates both R12 and R12.5 corpora exactly;
4. passes the frozen v2.2 baseline guard from full Git history;
5. has no unclassified parser/fuzz failure;
6. receives a versioned adversarial review identifying the exact candidate
   commit and its findings.

A PASS on any earlier intermediate commit does not close R12.5.
