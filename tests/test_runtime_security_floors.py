"""Prevent stale shipping locks from bypassing reviewed JWT/trust-store fixes."""

import re
import tomllib

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from tests.packaging_locks import ROOT, lock_entries


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Never open the admin database."""


@pytest.mark.parametrize("filename", ["requirements.lock", "requirements-admin.lock"])
@pytest.mark.parametrize("name,minimum", [("pyjwt", "2.15.1"), ("certifi", "2026.10.19")])
def test_shipping_lock_security_floor(filename, name, minimum):
    entry = lock_entries((ROOT / filename).read_text())[name]
    version = re.match(r"[\w-]+==([\w.]+)", entry)[1]
    assert Version(version) >= Version(minimum)
    assert "--hash=sha256:" in entry


def test_security_input_versions_match_shipping_admin_lock():
    entries = lock_entries((ROOT / "requirements-admin.lock").read_text())
    text = (ROOT / "docker/requirements-admin.in").read_text()
    for name, version in re.findall(r"^([\w-]+)==([\w.]+)$", text, re.M):
        name = name.lower()
        assert entries[name].startswith(f"{name}=={version} ")


def test_library_install_cannot_select_vulnerable_jwt_or_trust_store():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    requirements = {r.name.lower(): r for r in map(Requirement, project["project"]["dependencies"])}
    assert "2.13.0" not in requirements["pyjwt"].specifier
    assert "2.15.1" in requirements["pyjwt"].specifier
    assert "2026.5.20" not in requirements["certifi"].specifier
    assert "2026.10.19" in requirements["certifi"].specifier
