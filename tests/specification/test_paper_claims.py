from pathlib import Path


def test_paper_contains_required_sections_and_no_retired_claims() -> None:
    paper = (Path("paper") / "manuscript.md").read_text(encoding="utf-8")
    for section in (
        "## 1. Introduction",
        "## 2. Preliminaries and threat models",
        "## 3. Construction",
        "## 4. Security analysis",
        "## 6. Experimental methodology",
        "## 7. Preliminary smoke results",
        "## 9. Limitations and open cryptanalysis",
        "## 10. Reproducibility",
    ):
        assert section in paper
    retired = ("breaks Markov chains", "entropy accumulation", "TSMC 45 nm")
    assert all(claim not in paper for claim in retired)


def test_paper_labels_preliminary_evidence_and_external_review() -> None:
    paper = (Path("paper") / "manuscript.md").read_text(encoding="utf-8")
    assert "preliminary smoke experiments" in paper
    assert "not an external security review" in paper
    assert "72,013" in paper
