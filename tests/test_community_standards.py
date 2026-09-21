"""Public community entry points must stay discoverable and privacy-conscious."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Documentation checks do not need an operator database."""


def test_community_files_and_readme_links():
    readme = (ROOT / "README.md").read_text()
    for filename in ("CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md"):
        assert (ROOT / filename).is_file()
        assert f"]({filename})" in readme
    assert (ROOT / "LICENSE").is_file()
    assert (ROOT / ".github/pull_request_template.md").is_file()


def test_issue_templates_and_private_security_route():
    directory = ROOT / ".github/ISSUE_TEMPLATE"
    for filename in ("bug_report.md", "feature_request.md"):
        text = (directory / filename).read_text()
        metadata = yaml.safe_load(text.split("---", 2)[1])
        assert metadata["name"] and metadata["about"]
        assert "SECURITY.md" in text
    config = yaml.safe_load((directory / "config.yml").read_text())
    assert config["blank_issues_enabled"] is True  # Conduct contact requests.
    url = "https://github.com/red-orbita/bulwark-gateway/security/advisories/new"
    assert config["contact_links"][0]["url"] == url
    assert url in (ROOT / "SECURITY.md").read_text()
