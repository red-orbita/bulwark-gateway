"""Hash-locked test and lint tools must not overwrite application dependencies."""

from pathlib import Path

import pytest

from tests.packaging_locks import ci_entries, lock_entries

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("name", ["requirements-test.lock", "requirements-lint.lock", "docker/requirements-test-cp314.lock"])
def test_tool_locks_have_hashes_and_do_not_overlap_runtime(name):
    entries = lock_entries((ROOT / name).read_text())
    assert entries and not entries.keys() & ci_entries().keys()


def test_ci_declared_tools_are_all_locked():
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    tools = lock_entries((ROOT / "requirements-test.lock").read_text())
    tools.update(lock_entries((ROOT / "requirements-lint.lock").read_text()))
    for requirement in project["project"]["optional-dependencies"]["dev"]:
        assert requirement.split(">=")[0] in tools
