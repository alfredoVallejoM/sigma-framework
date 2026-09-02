# Claim-to-evidence traceability

| Claim | Formal obligation | Implementation | Current evidence | Status |
|---|---|---|---|---|
| Canonical message commitment | TH-01/02 | `sigma/spec`, `anchors` | vectors, codec tests, EXP-01 smoke | implemented; full campaign pending |
| Conservative multi-hash robustness | TH-02/07 | retained roots in Stream/Cross/Tree | EXP-04 reduced | theorem stated; external review pending |
| Collisions do not automatically coalesce | TH-03 | anchor reinjection in `rounds` | EXP-03 reduced | internally supported |
| Consecutive states impose repeated equalities | TH-04/05 | `SigmaDigestV2.states` | EXP-02/03 reduced | model-dependent |
| Sequential depth grows with `t+k-1` | TH-06 | WideOnce/Deep | exact counts and EXP-06 smoke | implemented |
| Backend choice does not alter values | TH-01 | serial/multiprocessing/incremental | differential tests, EXP-01 smoke | release gate; platform matrix pending |
| StreamWide memory is constant in message size | algorithmic invariant | `stream_wide.py` | EXP-10 smoke | supported to 4 MiB |
| TreeWide memory is logarithmic in leaves | algorithmic invariant | frontier reducer | unit invariants, EXP-10 smoke | supported to 4 MiB |
| Distribution/diffusion observations only | none implying security | experiment runners | EXP-05/07/08 smoke | appendix evidence only |
| PoW predicates have configured reduced acceptance probability | application model | `applications/pow.py` | EXP-11 smoke | protocol implemented; not a PoSW |
| Password entropy is not increased | TH-08 | `applications/kdf_argon2id.py` | formal argument + EXP-12 smoke | Argon2id supplies memory hardness; Sigma adds overhead |
| Faults change outputs / fail full verification | no DFA claim | `verify_full`, round/anchor code | EXP-14 smoke | fault coverage only |
| `Psi` is non-bijective and has sampled diffusion | pigeonhole argument only | `experimental/psi.py` | EXP-15 smoke | incomplete cryptanalysis; no trust claim |
| Adjacent edge is not trajectory proof | TH-09 | separate verification APIs | unit tests and counterexample | explicit limitation |
| Constant-time / power leakage | requires native core + EXP-13 | none | none | claim prohibited |
| ASIC/energy resistance | requires RTL + EXP-16 | none | none | claim prohibited |

“Smoke” denotes pipeline validation at modest sizes. It must not be cited as a
completed paper experiment. An external review cannot be self-certified by this
repository; review reports and addressed findings must be linked here before a
production-security claim is considered.
