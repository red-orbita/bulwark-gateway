"""Prevent accidental publication of explicitly classified local records.

Uses Git's index and ignore rules so checks also work in a clean CI checkout.
This is a publication boundary, not a general credential/content scanner.
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def git_paths(*args, input_bytes=None):
    result = subprocess.run(  # noqa: S603
        ["git", *args], cwd=ROOT, input=input_bytes, capture_output=True, check=True, timeout=10,  # noqa: S607
    )
    return [p.decode("utf-8") for p in result.stdout.split(b"\0") if p]


def private_rules():
    text = (ROOT / ".gitignore").read_text()
    block = text.split("# --- Local-only planning and lab records (publication boundary) ---\n", 1)[1]
    block = block.split("# --- End local-only publication boundary ---", 1)[0]
    return [line.removeprefix("/") for line in block.splitlines() if line.startswith("/")]


def is_private(path, rules):
    return any(path.startswith(rule) if rule.endswith("/") else path == rule for rule in rules)


@pytest.mark.parametrize("path,expected", [
    ("docs/internal/notes.md", True), ("debates/review.md", True),
    ("docs/IMPROVEMENT-PLAN.md", True), ("docs/RELEASE-ACCEPTANCE-LATEST.md", True),
    ("docs/SECURITY-STANDARDS-ADOPTION.md", True),
    ("docs/RELEASE-VERIFICATION.md", False), ("docs/LIMITATIONS.md", False),
    ("docs/DEPLOYMENT.md", False), ("docs/ROADMAP.md", False),
    ("docs/SECURITY-HARDENING.md", False),
])
def test_explicit_classification(path, expected):
    assert is_private(path, private_rules()) is expected


def test_local_records_cannot_be_tracked_even_with_force_add():
    rules = private_rules()
    tracked = git_paths("ls-files", "-z")
    assert not [p for p in tracked if is_private(p, rules)], "Local-only material is tracked"


def test_git_ignores_every_classified_local_path():
    paths = [r + "publication-probe.md" if r.endswith("/") else r for r in private_rules()]
    ignored = git_paths("check-ignore", "--no-index", "-z", "--stdin",
                        input_bytes=("\0".join(paths) + "\0").encode())
    assert set(ignored) == set(paths)


def test_public_markdown_does_not_depend_on_local_records():
    rules = private_rules()
    private_names = {Path(r).name for r in rules if not r.endswith("/")}
    paths = git_paths("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    failures = []
    for relative in sorted(set(paths)):
        path = ROOT / relative
        if path.suffix != ".md" or is_private(relative, rules) or not path.is_file():
            continue
        # Existing developer instructions are not product documentation.
        if path.name == "AGENTS.md":
            continue
        text = path.read_text(encoding="utf-8")
        if any(name in text for name in private_names):
            failures.append(relative)
        if relative.startswith("docs/") and ("/media/rokitoh/" in text or "DATOS21" in text):
            failures.append(relative)
    assert not failures, "Public documentation references private records or workstation paths: " + ", ".join(failures)


def test_runtime_context_excludes_private_material_and_keeps_licenses():
    lines = (ROOT / ".dockerignore").read_text().splitlines()
    for entry in ("docs/", "shared/", "reports/", "debates/"):
        assert entry in lines
    for entry in ("!LICENSE", "!LICENSING.md", "!src/evaluation/data/NOTICE"):
        assert entry in lines
