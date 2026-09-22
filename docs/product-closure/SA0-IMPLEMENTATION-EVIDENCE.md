# SA0 — Canonical Sigma Artifact Implementation Evidence

Status: **COMPLETE — RUNTIME GATE + INDEPENDENT ORACLE + ADVERSARIAL REVIEW PASSED**  
Executed SA0 baseline: `cabfb9be78faabf773deee9d25ddc04435597d3d`  
GitHub Actions run: `35789466377`  
Date: 2026-09-22

## 1. Scope

SA0 defines the canonical product artifact container without implementing SA1
verification composition.

Implemented:

- `sigma/artifact/ids.py`;
- `sigma/artifact/codec.py`;
- `sigma/artifact/record.py`;
- `sigma/artifact/__init__.py`;
- independent `ARTIFACT_WIRE_VERSION=1`;
- `reference/artifact_v1.py`;
- KAT generator/corpus;
- unit/differential/vector tests;
- `scripts/product_closure/sa0_gate.py`.

No SA1 Tree-AND-Trajectory verifier is introduced here.

## 2. Artifact format

Wires:

    SIGADSC1  ArtifactDescriptorV1
    SIGAIDN1  ArtifactIdentityV1
    SIGARTF1  SigmaArtifactV1

Artifact format version:

    1

The Artifact version axis is independent of package, Tree and Sigma suite
versions.

## 3. Exact profile semantics

TREE:

    TreeRoot present
    SigmaDigestV3 absent

TRAJECTORY:

    TreeRoot absent
    SigmaDigestV3 present

DUAL:

    TreeRoot present
    SigmaDigestV3 present

Any missing or extra primary evidence rejects.

DUAL also rejects if TreeRoot and SigmaDigestV3 commit different byte lengths.
This is a cheap structural consistency rule only; full dual verification remains
SA1.

## 4. Canonical descriptor

BASE_V1 descriptor contains:
- optional logical_name;
- optional media_type.

The name is NFC UTF-8, NUL-free and bounded.

Media type is lowercase canonical ASCII type/subtype without V1 parameters.

Descriptor wire is part of ArtifactIdentity and changes ArtifactId.

## 5. Non-circular ArtifactId

Canonical preimage:

    ArtifactIdentityV1 =
      profile
      descriptor
      primary TreeRoot/SigmaDigestV3
      optional ManifestId
      canonical parent IDs

Definition:

    ArtifactId =
      SHA256(
        b"SIGMA-ARTIFACT-ID-V1\0"
        || ArtifactIdentityV1.to_bytes()
      ).

The following are excluded:
- the stored ArtifactId itself;
- optional TrajectoryAudit;
- future signature;
- future provenance;
- verification receipts.

SigmaArtifactV1 stores ArtifactId in its envelope and the parser recomputes it.
600 deliberately corrupted stored IDs were rejected in the runtime gate.

## 6. Auxiliary TrajectoryAudit

TrajectoryAudit is auxiliary evidence.

For TRAJECTORY/DUAL:
- optional;
- its embedded digest must equal the primary SigmaDigestV3 exactly.

For TREE:
- forbidden.

The identity law is:

    ArtifactId(base)
      =
    ArtifactId(base+COMPACT)
      =
    ArtifactId(base+FULL).

The envelope wire does change.

Executed audit-stability cases:

    200 PASS.

This prevents evidence enrichment from renaming the logical artifact.

## 7. Manifest identity

Definition:

    ManifestId =
      SHA256(
        b"SIGMA-MANIFEST-ID-V1\0"
        || ManifestV1.to_bytes()
      ).

ManifestId is part of ArtifactIdentity.

Therefore manifest mutation changes ArtifactId, conditional on SHA-256 collision
resistance.

The helper forbids supplying both manifest and manifest_id simultaneously.

## 8. Parent binding

Parent IDs:
- exactly 32 bytes;
- maximum 1024;
- sorted;
- unique.

Parent set is part of ArtifactIdentity.

The helper canonicalizes input sequences to sorted+unique; direct canonical
construction/parser requires that form.

Parent-set mutation changes ArtifactId.

Reordered raw parent sequence rejects.

## 9. Independent oracle

`reference/artifact_v1.py` is stdlib-only and imports no Sigma package.

It independently implements:
- descriptor wire;
- identity wire;
- ArtifactId;
- ManifestId;
- artifact envelope.

Product/reference equality is required for all differential and KAT cases.

## 10. Frozen canonical corpus

File:

    specification/test-vectors/sigma-artifact-v1-sa0.json

Corpus SHA-256:

    60a0405516dd55b5ce52f14a442c12f836128357ac7b838a28f8d7b5eb748631

Frozen ArtifactIds:

tree-empty:

    b14cb16db8398a5fe4a7a0f20ae785510a14d72956d1e31adcf45018152bd149

tree-parents-manifest:

    d5297152ff1af91d687cb19b07a35c0b4064a68ef73aa0a01ffc2f8eae396238

trajectory:

    1c05715f6555a7c514b7995011d21e36ba995cc5cfb562d0785e91f379c8a732

trajectory-compact-audit:

    29368fd2f4b54384fb0333000da5c36e9cc16dcf264c53cf8920f9b87bbdd4b7

dual:

    8589309aec0720697b4d6b383122a7624c4b45fff1e019ff3aee22e1740b3503

dual-full-audit-manifest-parents:

    6a4f85ea85ee1e1ceb66e8291160ccb5de02c1e14eab222326ec5ef3bb9bed31

## 11. Runtime quality result

GitHub Actions run:

    35789466377

Result:

    compile PASS
    Ruff PASS
    Mypy PASS
    pytest 36 passed
    frozen vectors --check PASS
    SA0 gate PASS

The focused pytest set includes ST4 delta regression because SA0 closure also
cleaned old Tree typing debt.

## 12. Executed SA0 gate

Frozen report:

    SA0-GATE-REPORT.json

Report SHA-256:

    a80cea91b0f17e43af8513deba054ddf404ed637870c73164c9caba8b043d6f4

Result:

    passed = true
    closure_eligible = true
    differential_cases = 600
    identity_mutations = 1,800
    audit_stability_cases = 200
    stored_id_parser_rejections = 600

Profile coverage:

    TREE = 200
    TRAJECTORY = 200
    DUAL = 200

Frozen streams:

ArtifactId:

    93b8eba102bd9d980494a6db7c529fbc93a5d06590cb1f23fffa3ed77e2a8fac

Artifact envelope:

    fac9be3524100bcc974fd3b46d75263bf7ea1951af48553a00c0465d268db068

Identity mutations:

    59cda3e54e32d15683a9696da5de8b13b901c0f9fe4d4dd098b5ca1a1d8833ad

Explicit boundaries:

    artifact_id_includes_auxiliary_audit = false
    external_signature_in_artifact_identity = false
    security_width_claim = false
    empirical_performance_claims = false

## 13. Obligation review

### SA0-O01 — Exactly declared evidence

**PASS.**

All three profiles reject missing/extra primary evidence. DUAL also binds equal
committed length.

### SA0-O02 — ArtifactId non-circularity

**PASS.**

ArtifactId hashes only ArtifactIdentityV1 and excludes stored ID, optional audit
and future signature/provenance layers.

Stored-ID corruptions reject.

### SA0-O03 — Descriptor canonical

**PASS.**

NFC/name/media rules, strict TLV round-trip and structural mutations are covered.

### SA0-O04 — Parent artifacts bound

**PASS.**

Parents are canonical sorted+unique 32-byte IDs inside ArtifactIdentity; parent
set changes alter ArtifactId.

### SA0-O05 — Manifest identity bound

**PASS.**

ManifestId is a domain-separated SHA-256 over canonical ManifestV1 bytes and
belongs to ArtifactIdentity.

## 14. Auxiliary Tree findings

SA0 Mypy closure surfaced two pre-existing Tree engineering debts:

A. `manifest.py` used `DEFAULT_PROFILE` without importing it after a prior
memory optimization.

Status: **FIXED**.

B. ST4 rollback journals used sentinel-object unions that were semantically
correct but type-ambiguous.

Status: **FIXED** with typed existing-key rollback maps.

A further Ruff cleanup replaced successive `zip` with `itertools.pairwise`.

Regression coverage:
- ST1 Linux/macOS gate PASS after fixes;
- focused ST4 delta tests PASS in SA0 runtime suite.

No Tree wire semantics were changed.

## 15. Dependency closure

SA0 depends on ST1 and SV0.

SV0 was already COMPLETE.

ST1's final Darwin blocker was executed during SA0 closure:

    GitHub Actions run 35789236301
    macOS PASS
    Linux+Darwin cross-platform PASS

Both produced the same fixture hash:

    abc5d712225b89532320ee3ff9e7ac6ffe9aad5663fa61357adc2e729613ef83

Therefore both SA0 dependencies are COMPLETE.

## 16. Claim boundary

SA0 defines canonical presence/identity of Tree and/or Trajectory evidence.

It does not yet assert:

    VerifyDual(X,A)
      =
    VerifyTree(X,A.tree)
      AND
    VerifyTrajectory(X,A.trajectory).

That is SA1.

ArtifactId is a content identity and does not add nominal cryptographic bits.

External signature/provenance semantics remain SA2.

## 17. Complexity status

Structural contract:

    identity construction = O(descriptor + primary evidence + 32*parents)
    ArtifactId = O(identity wire size)
    envelope construction = O(identity + optional audit)

No source rehash is required if primary evidence is already materialized.

Empirical Artifact throughput is intentionally not claimed in SA0.

## 18. Final disposition

Independent oracle:

    PASS

Frozen corpus:

    PASS

Runtime gate:

    PASS

Manual O01..O05 adversarial review:

    PASS

Final status:

    SA0 COMPLETE
