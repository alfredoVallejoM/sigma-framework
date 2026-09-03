# External review and publication gate

The repository cannot self-certify cryptographic review. Before any production
or stable-security claim, an independent reviewer must receive and assess:

Current status: **not reviewed externally**. This checklist is a release gate,
not evidence that the gate has passed.
The implementation baseline and open R4–R6 gates are summarized in
[`../docs/project-status-2026-09-03.md`](../docs/project-status-2026-09-03.md).

- active experimental `sigma-v2-2` wire, evidence, tree and application
  specifications and the current v2.2 vectors;
- G-COLL, G-PRE, G-2PRE, G-SEG-COLL, G-MULTI, G-CONFORM and G-SIG-REUSE,
  including all budgets, target distributions and freshness events;
- TH-01–TH-08, including separate anchor collision/preimage/second-preimage
  parameters and every regularity or joint-branch assumption;
- domain separation and cross-use of Keccak-family functions;
- parser limits, denial-of-service surfaces and canonicality tests;
- StreamWide/CrossWide/TreeWide reductions, Deep/DeepVector failure models and
  scheduler/multiprocessing equivalence;
- the Ed25519 reuse reduction and the difference between attestation, full
  verification and one-edge verification;
- complete (not smoke) EXP-01R–21R data/configs/manifests for every applicable
  experiment, with EXP-13/16 absent unless their native/RTL gates exist;
- all negative, censored and statistically corrected results;
- release artifact checksums, SBOM and clean tagged commit.

Each finding must record reviewer, date, scope, severity, affected claim/code,
resolution commit and reviewer disposition. Unresolved high-severity findings
block the release. Absence of a report is “not reviewed”, never “no findings”.
