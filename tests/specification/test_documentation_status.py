import re
from pathlib import Path

DOCUMENTATION_ROOTS = (
    Path("README.md"),
    Path("SECURITY.md"),
    Path("docs"),
    Path("experiments/README.md"),
    Path("experiments/preregistration-v2-2.md"),
    Path("paper"),
    Path("specification"),
)


def _markdown_files() -> list[Path]:
    files: list[Path] = []
    for root in DOCUMENTATION_ROOTS:
        files.extend(sorted(root.rglob("*.md")) if root.is_dir() else [root])
    return files


def test_current_status_and_normative_documentation_cover_v22() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    status = Path("docs/project-status-2026-09-03.md").read_text(encoding="utf-8")
    specification = Path("specification/sigma-v2.md").read_text(encoding="utf-8")
    assert "docs/project-status-2026-09-03.md" in readme
    assert all(f"| R{gate} " in status for gate in (1, 3, 4, 6))
    for required in ("DeepVector", "256 bytes", "SIGMASIG", "ResourcePolicy"):
        assert required in specification


def test_historical_audits_point_to_the_current_status() -> None:
    for name in ("audit-2026-09-02.md", "final-audit-2026-09-02.md"):
        text = (Path("docs") / name).read_text(encoding="utf-8")
        assert "histórico" in text
        assert "project-status-2026-09-03.md" in text


def test_all_local_markdown_links_resolve() -> None:
    missing: list[tuple[str, str]] = []
    for document in _markdown_files():
        text = document.read_text(encoding="utf-8")
        for raw_target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            target = raw_target.strip("<>").split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            if not (document.parent / target).resolve().exists():
                missing.append((str(document), target))
    assert not missing
