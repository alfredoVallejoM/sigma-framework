from pathlib import Path


def test_paper_contains_required_sections_and_no_retired_claims() -> None:
    paper = (Path("paper") / "manuscript.md").read_text(encoding="utf-8")
    for section in (
        "## 1. Scope and contribution",
        "## 2. Threat models",
        "## 3. Construction",
        "## 4. Security analysis boundary",
        "## 6. Experimental method",
        "## 7. Confirmatory results",
        "## 8. Limitations and open validation",
        "## 9. Reproducibility",
    ):
        assert section in paper
    retired = ("breaks Markov chains", "entropy accumulation", "TSMC 45 nm")
    assert all(claim not in paper for claim in retired)


def test_paper_excludes_pilots_and_records_external_review_gate() -> None:
    paper = (Path("paper") / "manuscript.md").read_text(encoding="utf-8")
    assert "no complete canonical result set" in paper
    assert "pilot number" in paper
    assert "independent cryptographic review" in paper
    assert "72,013" not in paper
