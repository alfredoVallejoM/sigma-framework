# ST1 — Canonical Manifest Final Closure Evidence

Status: **COMPLETE — LINUX/macOS CROSS-PLATFORM GATE PASSED**  
GitHub Actions run: `35789236301`  
Cross-platform product baseline: `ea4a85b842a23378019b72e2dc41dc678b6022eb`  
Date: 2026-09-22

## 1. Previous state

ST1 implementation, independent reference, mutation gate and adversarial review
were already complete locally.

The only remaining blocking condition was physical reproduction of the canonical
filesystem fixture on macOS.

ST1 correctly remained CANDIDATE until this run.

## 2. Executed cross-platform gate

The closure workflow executed:

1. `st1_gate.py` on macOS/Darwin;
2. uploaded the Darwin report;
3. executed the full Linux gate with the Darwin report as `--peer-report`;
4. required `--require-cross-platform`.

Both platforms produced:

    fixture_manifest_sha256 =
    abc5d712225b89532320ee3ff9e7ac6ffe9aad5663fa61357adc2e729613ef83

Executed report:

    ST1-CROSS-PLATFORM-GATE-REPORT.json

Report SHA-256:

    86c2c7eeffc602a7d666033858cbd68815753cb27db5c4f6ae96afaad0aacda9

## 3. Closure-scale results

    path_cases = 50,000
    permutation_cases = 1,000
    differential_cases = 1,000
    fuzz_cases = 50,000
    schema_mutation_cases = 20
    fuzz_rejected = 20,923
    fuzz_changed_valid = 29,077
    symlink_checks = passed

Streams:

path:

    4f802fb653df818265581071c1b6ffb393834629da72723fd9f9e38369f9a6d9

independent manifest:

    a5d1ff4b6578665be462cac3ded50c0adbf4d1c69e397041961f2074dee1efe4

mutation:

    88e98c9062e5bd50593697882373a2454b330b36ce389c5f746b1c1b543293c9

Result:

    local_passed = true
    cross_platform_complete = true
    closure_eligible = true
    passed = true

## 4. Obligation disposition

ST1-O01 canonical relative paths — **PASS**  
ST1-O02 traversal independence — **PASS**  
ST1-O03 absolute root-path independence — **PASS**  
ST1-O04 duplicate path rejection — **PASS**  
ST1-O05 volatile metadata excluded — **PASS**  
ST1-O06 explicit symlink policy — **PASS**  
ST1-O07 content mutation changes manifest — **PASS**  
ST1-O08 optional trajectory wire exactly bound — **PASS**  
ST1-O09 UTF-8 canonical ordering — **PASS**  
ST1-O10 complexity contract — **PASS**

The previous CANDIDATE state was caused only by missing physical Darwin evidence;
that blocker is now removed.

## 5. Final disposition

    ST1 COMPLETE
