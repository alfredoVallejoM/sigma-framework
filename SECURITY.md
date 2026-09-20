# Security policy

Sigma Framework is a research implementation. No current release or v3
candidate is supported for production-security use, and no Sigma construction
has completed an independent cryptographic audit.

The v2.2 family is preserved as a frozen historical/interoperability baseline.
Sigma v3 / Sigma-IAP is the active research line. R12 has a traceable
engineering/conformance PASS, but that PASS proves byte-level and implementation
conformance, not cryptographic security. R12.5 reopens the round semantics to
restore historical feedback through an evolving history commitment before the
formal security and confirmatory-paper gates.

Current security/publication gates:

- R12.5: **PASS** — history-feedback semantics, corpus/reference and adversarial review;
- R13: **PASS** — formal games, reductions, claim matrix and cryptanalytic attack design;
- R14: **next active gate** — semantic/experimental freeze and preregistration;
- R15: confirmatory scientific campaign;
- R16: external reproduction, archival and cryptographic review.

See:

- [R12.5 history-feedback plan](docs/sigma-v3-r12-5-history-feedback-plan.md)
- [R12.5 adversarial review](docs/adversarial-reviews/R12-5.md)
- [R13 security analysis](specification/security-analysis-v3-r13.md)
- [R13 adversarial review](docs/adversarial-reviews/R13.md)
- [paper cryptographic validation plan](docs/paper-cryptographic-validation-plan-v3.md)

Please report suspected security issues privately to the maintainer rather than
opening a public issue. Include the affected suite/version or commit, a minimal
reproducer, the expected impact and whether the issue concerns specification,
cryptography, parser/resource handling, application composition or release
integrity. Do not include real secrets or third-party data.

Interoperability stability, passing tests, statistical randomness batteries or
an internal adversarial review do not imply a security guarantee. Wire-incompatible
corrections require new suite/profile identifiers or an explicit pre-freeze
supersession; existing audited artifacts are never silently reinterpreted.

No claim is currently made that Sigma itself provides password entropy,
memory-hardness, VDF/PoSW properties, constant-time execution, ASIC/GPU
resistance or security additive across hash branches. Argon2id and Ed25519 keep
their own standard security attribution in the experimental compositions.
