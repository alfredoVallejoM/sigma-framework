from pathlib import Path


def test_security_analysis_contains_every_v22_formal_obligation() -> None:
    analysis = (Path("specification") / "security-analysis.md").read_text(encoding="utf-8")
    for number in range(1, 11):
        assert f"FORM-{number:02d}" in analysis
    for game in ("G-COLL", "G-PRE", "G-2PRE", "G-SEG-COLL", "G-MULTI", "G-CONFORM", "G-SIG-REUSE"):
        assert game in analysis


def test_security_analysis_preserves_required_limitations() -> None:
    analysis = (Path("specification") / "security-analysis.md").read_text(encoding="utf-8")
    required = (
        "not a third-party proof",
        "No formula may substitute `w_phys`",
        "do not by themselves establish independent",
        "Python is not claimed constant-time",
        "External cryptographic review remains a release dependency",
        "No preimage lower bound",
        "not a proof of their prefix",
    )
    assert all(statement in analysis for statement in required)
