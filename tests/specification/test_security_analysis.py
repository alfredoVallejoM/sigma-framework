from pathlib import Path


def test_security_analysis_contains_each_required_obligation_once() -> None:
    analysis = (Path("specification") / "security-analysis.md").read_text(encoding="utf-8")
    for number in range(1, 10):
        assert analysis.count(f"## TH-{number:02d} ") == 1


def test_security_analysis_preserves_required_limitations() -> None:
    analysis = (Path("specification") / "security-analysis.md").read_text(encoding="utf-8")
    required = (
        "not a third-party cryptographic review",
        "effective collision strength",
        "domain separation, not a proof of independence",
        "Python is not constant-time",
        "External cryptographic review remains required",
    )
    assert all(statement in analysis for statement in required)
