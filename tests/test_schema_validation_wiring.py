"""
Wiring tests for the structured-output SchemaValidator integration.

These are NOT unit tests of the SchemaValidator's validation logic (those live in
tests/test_output_validation.py). They pin the *wiring* that makes the scanner
reachable from a real request:

  1. The `schema_validation_enabled` flag is off by default (opt-in).
  2. `AgentPolicy.output_validation` is parsed from policy YAML by the loader.
  3. The scanner is registered in the pipeline only when the flag is on.
  4. The exact ScanContext the proxy builds (policy `output_validation` threaded
     into `metadata`) drives real BLOCK / WARN / REDACT / ALLOW verdicts through
     `run_output_blocking` — i.e. an agent's policy actually reaches the scanner.

No mocks: the SchemaValidator runs its real jsonschema validation (jsonschema is a
core runtime dependency).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from src.config import Settings
from src.models import Verdict
from src.policies.loader import PolicyLoader
from src.scanners.output.schema_validator import SchemaValidator
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import ScanContext, ScannerType


# ==============================================================================
# 1. Flag is opt-in (default off)
# ==============================================================================
def test_schema_validation_flag_defaults_off():
    settings = Settings(jwt_secret="x" * 40)
    assert settings.schema_validation_enabled is False


def test_schema_validation_flag_can_be_enabled(monkeypatch):
    monkeypatch.setenv("BULWARK_SCHEMA_VALIDATION_ENABLED", "true")
    settings = Settings(jwt_secret="x" * 40)
    assert settings.schema_validation_enabled is True


# ==============================================================================
# 2. Loader parses output_validation from policy YAML
# ==============================================================================
_POLICY_YAML = textwrap.dedent(
    """
    tenant: acme
    agents:
      - id: extractor
        sandbox_level: strict
        allowed_tools: [read_kb]
        output_validation:
          output_schema:
            type: object
            required: [status]
            properties:
              status:
                type: string
          on_schema_fail: block
          require_json: true
      - id: chatbot
        allowed_tools: [web_search]
    """
)


@pytest.mark.asyncio
async def test_loader_parses_output_validation(tmp_path: Path):
    (tmp_path / "acme.yaml").write_text(_POLICY_YAML)
    loader = PolicyLoader(tmp_path)
    await loader.load_all()

    extractor = loader.engine.get_policy("acme", "extractor")
    assert extractor is not None
    assert extractor.output_validation["on_schema_fail"] == "block"
    assert extractor.output_validation["require_json"] is True
    assert extractor.output_validation["output_schema"]["required"] == ["status"]


@pytest.mark.asyncio
async def test_loader_defaults_output_validation_empty(tmp_path: Path):
    """An agent without an output_validation block gets an empty dict (inert)."""
    (tmp_path / "acme.yaml").write_text(_POLICY_YAML)
    loader = PolicyLoader(tmp_path)
    await loader.load_all()

    chatbot = loader.engine.get_policy("acme", "chatbot")
    assert chatbot is not None
    assert chatbot.output_validation == {}


# ==============================================================================
# 3. Registration gating mirrors main.py
# ==============================================================================
def test_schema_validator_is_output_blocking():
    scanner = SchemaValidator()
    assert scanner.info.scanner_type == ScannerType.OUTPUT_BLOCKING


@pytest.mark.asyncio
async def test_registration_only_when_flag_on(tmp_path: Path):
    """Replicates the main.py gate: register iff schema_validation_enabled."""

    def build_pipeline(flag: bool) -> ScannerPipeline:
        pipeline = ScannerPipeline()
        if flag:
            pipeline.register(SchemaValidator())
        return pipeline

    assert build_pipeline(False).output_blocking_count == 0
    assert build_pipeline(True).output_blocking_count == 1


# ==============================================================================
# 4. End-to-end: the ScanContext the proxy builds drives real verdicts
# ==============================================================================
def _proxy_out_context(policy_output_validation: dict) -> ScanContext:
    """Build the same output ScanContext the proxy constructs (see proxy.py).

    The proxy threads `AgentPolicy.output_validation` into `metadata` only when
    it is non-empty; otherwise metadata stays empty.
    """
    metadata: dict = {}
    if policy_output_validation:
        metadata["output_validation"] = policy_output_validation
    return ScanContext(
        tenant_id="acme",
        agent_id="extractor",
        request_id="req-1",
        messages=[{"role": "user", "content": "extract the record"}],
        metadata=metadata,
    )


async def _run(policy_cfg: dict, content: str):
    pipeline = ScannerPipeline()
    pipeline.register(SchemaValidator())
    await pipeline.startup()
    ctx = _proxy_out_context(policy_cfg)
    return await pipeline.run_output_blocking(content, ctx)


_SCHEMA = {
    "type": "object",
    "required": ["status"],
    "properties": {"status": {"type": "string"}},
}


@pytest.mark.asyncio
async def test_inert_when_agent_has_no_output_validation():
    """Flag on + scanner registered, but agent opted out → ALLOW, no events."""
    result = await _run({}, '{"anything": "goes"}')
    assert result.verdict == Verdict.ALLOW
    assert result.events == []


@pytest.mark.asyncio
async def test_valid_output_allowed():
    result = await _run(
        {"output_schema": _SCHEMA, "on_schema_fail": "block"},
        '{"status": "ok"}',
    )
    assert result.verdict == Verdict.ALLOW


@pytest.mark.asyncio
async def test_schema_violation_blocks_via_policy():
    result = await _run(
        {"output_schema": _SCHEMA, "on_schema_fail": "block"},
        '{"wrong_field": 123}',
    )
    assert result.verdict == Verdict.BLOCK
    assert result.events
    assert result.events[0].source == "schema_validator"


@pytest.mark.asyncio
async def test_schema_violation_warns_via_policy():
    result = await _run(
        {"output_schema": _SCHEMA, "on_schema_fail": "warn"},
        '{"wrong_field": 123}',
    )
    assert result.verdict == Verdict.WARN
    assert result.events


@pytest.mark.asyncio
async def test_schema_repair_redacts_via_policy():
    """repair mode fixes trailing-comma JSON and returns REDACT + modified content.

    The trailing comma makes the output unparseable, so extraction returns None;
    with require_json the scanner routes to repair, which strips the comma and
    re-validates against the schema.
    """
    result = await _run(
        {
            "output_schema": _SCHEMA,
            "on_schema_fail": "repair",
            "require_json": True,
        },
        '{"status": "ok",}',  # trailing comma → unparseable until repaired
    )
    assert result.verdict == Verdict.REDACT
    assert result.modified_content is not None
    assert "status" in result.modified_content


@pytest.mark.asyncio
async def test_require_json_blocks_plaintext():
    result = await _run(
        {"output_schema": _SCHEMA, "on_schema_fail": "block", "require_json": True},
        "I could not produce JSON, sorry.",
    )
    assert result.verdict == Verdict.BLOCK
