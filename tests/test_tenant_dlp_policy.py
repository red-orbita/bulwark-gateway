"""Tenant-bound DLP rules and fail-closed policy publication."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from src.guardrails.input_dlp import InputDlpPolicy, inspect_request
from src.models import Verdict
from src.policies.loader import PolicyLoader


def save_policy(path: Path, tenant: str, dlp: dict):
    path.write_text(yaml.safe_dump({"tenant": tenant, "agents": [{"id": "agent", "input_dlp": dlp}]}))


@pytest.mark.parametrize("config", [
    {"enabled": "false"}, {"redact_email": "true"}, {"max_bytes": True}, {"max_bytes": 0},
    {"max_bytes": 262145}, {"blocked_terms": ["x"]}, {"blocked_terms": ["   "]},
    {"blocked_terms": ["confidential"] * 33}, {"allow_secrets": True}, None,
])
def test_invalid_dlp_policy_rejected(config):
    with pytest.raises(ValidationError):
        InputDlpPolicy.model_validate(config)


async def test_policy_parse_is_tenant_isolated(tmp_path):
    save_policy(tmp_path / "a.yaml", "a", {"enabled": True, "redact_email": True, "blocked_terms": ["Project Falcon"]})
    save_policy(tmp_path / "b.yaml", "b", {})
    loader = PolicyLoader(tmp_path)
    await loader.load_all()
    assert loader.engine.get_policy("a", "agent").input_dlp.enabled
    assert loader.engine.get_policy("a", "agent").input_dlp.blocked_terms == ("project falcon",)
    assert not loader.engine.get_policy("b", "agent").input_dlp.enabled


async def test_one_invalid_file_cannot_remove_other_tenant_protection(tmp_path):
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    save_policy(a, "a", {"enabled": True})
    save_policy(b, "b", {"enabled": True})
    loader = PolicyLoader(tmp_path)
    await loader.load_all()
    engine, mtimes = loader.engine, dict(loader._file_mtimes)
    save_policy(a, "a", {"enabled": False})
    save_policy(b, "b", {"enabled": "invalid"})
    await loader.reload()
    assert loader.engine is engine
    assert loader.engine.get_policy("a", "agent").input_dlp.enabled
    assert loader.engine.get_policy("b", "agent").input_dlp.enabled
    assert loader._file_mtimes == mtimes
    save_policy(b, "b", {"enabled": True, "redact_email": True})
    await loader.reload()
    assert loader.engine is not engine
    assert loader.engine.get_policy("b", "agent").input_dlp.redact_email


async def test_invalid_startup_refuses_partial_policy_set(tmp_path):
    save_policy(tmp_path / "a.yaml", "a", {"enabled": True})
    save_policy(tmp_path / "b.yaml", "b", {"enabled": "yes"})
    loader = PolicyLoader(tmp_path)
    with pytest.raises(RuntimeError, match="partial startup"):
        await loader.load_all()
    assert loader.count == 0


async def test_duplicate_agent_cannot_replace_dlp_policy(tmp_path):
    save_policy(tmp_path / "a.yaml", "same", {"enabled": True})
    save_policy(tmp_path / "b.yaml", "same", {"enabled": False})
    with pytest.raises(RuntimeError):
        await PolicyLoader(tmp_path).load_all()


@pytest.mark.parametrize("text", ["PROJECT FALCON", "project falcon", "project\u200bfalcon"])
def test_classification_terms_block_without_disclosure(text):
    terms = ("project falcon", "projectfalcon")
    result = inspect_request({"content": text}, "a", "agent", "r", blocked_terms=terms)
    assert result.verdict == Verdict.BLOCK
    assert result.events[0].metadata["reason"] == "restricted_classification"
    assert "falcon" not in result.model_dump_json().lower()


def test_no_classification_match_preserves_benign_request():
    assert inspect_request({"content": "Weather today"}, "b", "agent", "r",
                           blocked_terms=("project falcon",)).verdict == Verdict.ALLOW


async def test_shipped_policy_directory_loads():
    loader = PolicyLoader(Path(__file__).parents[1] / "config/policies")
    await loader.load_all()
    assert loader.count > 0


async def test_file_replaced_after_read_is_not_published(tmp_path, monkeypatch):
    path = tmp_path / "tenant.yaml"
    save_policy(path, "a", {"enabled": True})
    loader = PolicyLoader(tmp_path)
    await loader.load_all()
    previous = loader.engine
    read = loader._read_policy_file
    def replacing_read(file):
        data, version = read(file)
        replacement = tmp_path / "replacement.tmp"
        save_policy(replacement, "a", {"enabled": True, "redact_email": True})
        replacement.replace(file)
        return data, version
    monkeypatch.setattr(loader, "_read_policy_file", replacing_read)
    await loader.reload()
    assert loader.engine is previous
    monkeypatch.setattr(loader, "_read_policy_file", read)
    await loader.reload()
    assert loader.engine.get_policy("a", "agent").input_dlp.redact_email


@pytest.mark.parametrize("text", ["ProjectFalcon", "Project\u200bFalcon"])
def test_terms_and_content_share_invisible_character_normalization(text):
    policy = InputDlpPolicy(blocked_terms=("Project\u200bFalcon",))
    assert inspect_request({"text": text}, "a", "agent", "r", blocked_terms=policy.blocked_terms).verdict == Verdict.BLOCK
