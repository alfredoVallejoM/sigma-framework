# External review and publication gate

The repository cannot self-certify cryptographic review. Before any production
or stable-security claim, an independent reviewer must receive and assess:

Current status: **not reviewed externally**. This checklist is a release gate,
not evidence that the gate has passed.

- frozen `sigma-v2-1` wire and tree specifications;
- TH-01–TH-09, including freshness and joint-branch assumptions;
- domain separation and cross-use of Keccak-family functions;
- parser limits, denial-of-service surfaces and canonicality tests;
- StreamWide/CrossWide/TreeWide reductions and multiprocessing equivalence;
- complete (not smoke) EXP-01–10 data/configs/manifests;
- all negative, censored and statistically corrected results;
- release artifact checksums, SBOM and clean tagged commit.

Each finding must record reviewer, date, scope, severity, affected claim/code,
resolution commit and reviewer disposition. Unresolved high-severity findings
block the release. Absence of a report is “not reviewed”, never “no findings”.
