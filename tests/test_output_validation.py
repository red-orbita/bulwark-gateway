"""
Tests for Phase 4: Output Validation Scanners.

Tests cover:
  - Hallucination detection (mocked NLI)
  - Schema validation (JSON Schema)
  - Grounding checker (mocked NLI)
  - Relevance scorer (mocked embeddings)
  - Policy configuration handling
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import GuardrailResult, Verdict
from src.scanners.protocol import ScanContext, ScannerType


def _make_context(**kwargs) -> ScanContext:
    defaults = {
        "tenant_id": "test-tenant",
        "agent_id": "test-agent",
        "request_id": "req-001",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"},
        ],
    }
    defaults.update(kwargs)
    return ScanContext(**defaults)


# ==============================================================================
# Hallucination Scanner Tests
# ==============================================================================
class TestHallucinationScanner:
    """Test HallucinationScanner."""

    @pytest.mark.asyncio
    async def test_info_properties(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner()
        assert scanner.info.name == "hallucination_detector"
        assert scanner.info.scanner_type == ScannerType.OUTPUT_ASYNC

    @pytest.mark.asyncio
    async def test_info_blocking_mode(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner(blocking=True)
        assert scanner.info.scanner_type == ScannerType.OUTPUT_BLOCKING

    @pytest.mark.asyncio
    async def test_allows_when_model_not_loaded(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner()
        ctx = _make_context()
        result = await scanner.scan("Paris is the capital of France.", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_allows_consistent_output(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner(contradiction_threshold=0.7)
        scanner._model_loaded = True

        # Mock NLI: entailment (consistent)
        with patch.object(
            scanner, "_check_entailment",
            return_value={"contradiction": 0.05, "neutral": 0.15, "entailment": 0.8},
        ):
            ctx = _make_context()
            result = await scanner.scan(
                "The capital of France is Paris. It is located in Europe.",
                ctx,
            )
            assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_warns_on_contradiction(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner(contradiction_threshold=0.7)
        scanner._model_loaded = True

        with patch.object(
            scanner, "_check_entailment",
            return_value={"contradiction": 0.85, "neutral": 0.1, "entailment": 0.05},
        ):
            ctx = _make_context(
                messages=[
                    {"role": "system", "content": "The budget for Q4 is $50,000."},
                    {"role": "user", "content": "What is the Q4 budget?"},
                ]
            )
            result = await scanner.scan(
                "The Q4 budget is $100,000 which represents a significant increase.",
                ctx,
            )
            assert result.verdict == Verdict.WARN

    @pytest.mark.asyncio
    async def test_blocks_multiple_contradictions(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner(contradiction_threshold=0.7)
        scanner._model_loaded = True

        # All claims contradict
        with patch.object(
            scanner, "_check_entailment",
            return_value={"contradiction": 0.9, "neutral": 0.05, "entailment": 0.05},
        ):
            ctx = _make_context(
                messages=[
                    {"role": "system", "content": "Company was founded in 2020."},
                    {"role": "user", "content": "When was the company founded?"},
                ]
            )
            # Multiple contradicting sentences
            result = await scanner.scan(
                "The company was founded in 1995. "
                "It has been operating for over 50 years. "
                "The original founders are no longer alive. "
                "The headquarters moved to Mars in 2010.",
                ctx,
            )
            assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_skips_when_disabled_in_policy(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner()
        scanner._model_loaded = True

        ctx = _make_context(
            metadata={"output_validation": {"hallucination_check": False}}
        )
        result = await scanner.scan("Anything", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_claim_extraction(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner

        scanner = HallucinationScanner()
        claims = scanner._extract_claims(
            "The sky is blue. What color is the grass? "
            "I think it depends. The temperature is 25 degrees Celsius."
        )
        # Should skip: question, "I think" prefix, nothing too short
        assert "The sky is blue." in claims
        assert "The temperature is 25 degrees Celsius." in claims
        assert "What color is the grass?" not in claims


# ==============================================================================
# Schema Validator Tests
# ==============================================================================
class TestSchemaValidator:
    """Test SchemaValidator."""

    @pytest.mark.asyncio
    async def test_info_properties(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        assert scanner.info.name == "schema_validator"
        assert scanner.info.scanner_type == ScannerType.OUTPUT_BLOCKING

    @pytest.mark.asyncio
    async def test_allows_when_no_schema_configured(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        await scanner.startup()

        ctx = _make_context()
        result = await scanner.scan("Just plain text response", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_validates_valid_json(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        await scanner.startup()

        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        ctx = _make_context(
            metadata={"output_validation": {"output_schema": schema}}
        )
        result = await scanner.scan('{"name": "Alice", "age": 30}', ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_warns_on_invalid_json(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator(default_on_fail="warn")
        await scanner.startup()

        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        ctx = _make_context(
            metadata={"output_validation": {"output_schema": schema}}
        )
        # Missing required 'age' field
        result = await scanner.scan('{"name": "Alice"}', ctx)
        assert result.verdict == Verdict.WARN

    @pytest.mark.asyncio
    async def test_blocks_on_invalid_when_configured(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        await scanner.startup()

        schema = {
            "type": "object",
            "required": ["result"],
            "properties": {"result": {"type": "number"}},
        }
        ctx = _make_context(
            metadata={
                "output_validation": {
                    "output_schema": schema,
                    "on_schema_fail": "block",
                }
            }
        )
        result = await scanner.scan('{"result": "not a number"}', ctx)
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_extracts_json_from_code_block(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        await scanner.startup()

        schema = {
            "type": "object",
            "required": ["answer"],
            "properties": {"answer": {"type": "string"}},
        }
        ctx = _make_context(
            metadata={"output_validation": {"output_schema": schema}}
        )
        content = 'Here is the result:\n```json\n{"answer": "42"}\n```\nDone!'
        result = await scanner.scan(content, ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_repair_mode(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        await scanner.startup()

        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        ctx = _make_context(
            metadata={
                "output_validation": {
                    "output_schema": schema,
                    "on_schema_fail": "repair",
                    "require_json": True,
                }
            }
        )
        # Trailing comma (common LLM error) — invalid JSON
        content = '{"name": "Alice", "age": 30,}'
        result = await scanner.scan(content, ctx)
        # Should repair (remove trailing comma) → REDACT
        assert result.verdict == Verdict.REDACT
        assert result.modified_content is not None

    @pytest.mark.asyncio
    async def test_skips_non_json_when_not_required(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()
        await scanner.startup()

        schema = {"type": "object", "properties": {"x": {"type": "number"}}}
        ctx = _make_context(
            metadata={"output_validation": {"output_schema": schema}}
        )
        result = await scanner.scan("This is just a plain text response.", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_json_extraction_methods(self):
        from src.scanners.output.schema_validator import SchemaValidator

        scanner = SchemaValidator()

        # Direct JSON
        assert scanner._extract_json('{"key": "value"}') is not None

        # Code block
        assert scanner._extract_json('```json\n{"key": "value"}\n```') is not None

        # Embedded in text
        assert scanner._extract_json('Result: {"key": "value"} done.') is not None

        # No JSON
        assert scanner._extract_json("No JSON here at all") is None


# ==============================================================================
# Grounding Scanner Tests
# ==============================================================================
class TestGroundingScanner:
    """Test GroundingScanner."""

    @pytest.mark.asyncio
    async def test_info_properties(self):
        from src.scanners.output.grounding_scanner import GroundingScanner

        scanner = GroundingScanner()
        assert scanner.info.name == "grounding_checker"
        assert scanner.info.scanner_type == ScannerType.OUTPUT_ASYNC

    @pytest.mark.asyncio
    async def test_allows_when_no_rag_context(self):
        from src.scanners.output.grounding_scanner import GroundingScanner

        scanner = GroundingScanner()
        scanner._model_loaded = True

        ctx = _make_context()
        result = await scanner.scan("Any response", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_allows_well_grounded_output(self):
        from src.scanners.output.grounding_scanner import GroundingScanner

        scanner = GroundingScanner(grounding_threshold=0.7)
        scanner._model_loaded = True

        # Mock: all claims are grounded (high entailment)
        with patch.object(scanner, "_score_grounding", return_value=0.9):
            ctx = _make_context(
                metadata={"rag_context": ["Paris is the capital of France."]}
            )
            result = await scanner.scan(
                "The capital of France is Paris. France is in Europe.",
                ctx,
            )
            assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_warns_poorly_grounded_output(self):
        from src.scanners.output.grounding_scanner import GroundingScanner

        scanner = GroundingScanner(grounding_threshold=0.7)
        scanner._model_loaded = True

        # Mock: claims are not grounded
        with patch.object(scanner, "_score_grounding", return_value=0.2):
            ctx = _make_context(
                metadata={"rag_context": ["The company sells software."]}
            )
            result = await scanner.scan(
                "The company was founded in Tokyo. They have 5000 employees worldwide.",
                ctx,
            )
            assert result.verdict in (Verdict.WARN, Verdict.BLOCK)

    @pytest.mark.asyncio
    async def test_extracts_rag_context_from_system(self):
        from src.scanners.output.grounding_scanner import GroundingScanner

        scanner = GroundingScanner()
        long_system = "Context: " + "x" * 300  # Long system = likely RAG context
        ctx = _make_context(
            messages=[
                {"role": "system", "content": long_system},
                {"role": "user", "content": "What?"},
            ]
        )
        result = scanner._get_rag_context(ctx)
        assert len(result) > 200


# ==============================================================================
# Relevance Scanner Tests
# ==============================================================================
class TestRelevanceScanner:
    """Test RelevanceScanner."""

    @pytest.mark.asyncio
    async def test_info_properties(self):
        from src.scanners.output.relevance_scanner import RelevanceScanner

        scanner = RelevanceScanner()
        assert scanner.info.name == "relevance_checker"
        assert scanner.info.scanner_type == ScannerType.OUTPUT_ASYNC

    @pytest.mark.asyncio
    async def test_allows_when_model_not_loaded(self):
        from src.scanners.output.relevance_scanner import RelevanceScanner

        scanner = RelevanceScanner()
        ctx = _make_context()
        result = await scanner.scan("Any response", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_allows_when_check_disabled(self):
        from src.scanners.output.relevance_scanner import RelevanceScanner

        scanner = RelevanceScanner()
        scanner._model_loaded = True

        ctx = _make_context(
            metadata={"output_validation": {"relevance_check": False}}
        )
        result = await scanner.scan("Any response", ctx)
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_allows_high_relevance(self):
        from src.scanners.output.relevance_scanner import RelevanceScanner

        scanner = RelevanceScanner(relevance_threshold=0.4)
        scanner._model_loaded = True

        with patch.object(scanner, "_compute_similarity", return_value=0.85):
            ctx = _make_context(
                metadata={"output_validation": {"relevance_check": True}}
            )
            result = await scanner.scan("Paris is the capital of France.", ctx)
            assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_warns_low_relevance(self):
        from src.scanners.output.relevance_scanner import RelevanceScanner

        scanner = RelevanceScanner(relevance_threshold=0.4)
        scanner._model_loaded = True

        with patch.object(scanner, "_compute_similarity", return_value=0.15):
            ctx = _make_context(
                metadata={"output_validation": {"relevance_check": True}}
            )
            result = await scanner.scan(
                "Here is a recipe for chocolate cake. Preheat the oven to 350F.",
                ctx,
            )
            assert result.verdict == Verdict.WARN

    @pytest.mark.asyncio
    async def test_extracts_user_question(self):
        from src.scanners.output.relevance_scanner import RelevanceScanner

        scanner = RelevanceScanner()
        ctx = _make_context(
            messages=[
                {"role": "system", "content": "Be helpful."},
                {"role": "user", "content": "What is Python?"},
                {"role": "assistant", "content": "Python is a language."},
                {"role": "user", "content": "How do I install it?"},
            ]
        )
        question = scanner._get_user_question(ctx)
        assert question == "How do I install it?"


# ==============================================================================
# Pipeline Integration
# ==============================================================================
class TestOutputPipelineIntegration:
    """Test output scanners in the pipeline."""

    @pytest.mark.asyncio
    async def test_output_scanners_register(self):
        from src.scanners.output.hallucination_scanner import HallucinationScanner
        from src.scanners.output.schema_validator import SchemaValidator
        from src.scanners.pipeline import ScannerPipeline

        pipeline = ScannerPipeline()
        pipeline.register(HallucinationScanner())
        pipeline.register(SchemaValidator())

        assert pipeline.output_async_count == 1
        assert pipeline.output_blocking_count == 1

    @pytest.mark.asyncio
    async def test_schema_blocks_in_output_pipeline(self):
        from src.scanners.output.schema_validator import SchemaValidator
        from src.scanners.pipeline import ScannerPipeline

        pipeline = ScannerPipeline()
        validator = SchemaValidator(default_on_fail="block")
        pipeline.register(validator)
        await pipeline.startup()

        schema = {
            "type": "object",
            "required": ["status"],
            "properties": {"status": {"type": "string"}},
        }
        ctx = _make_context(
            metadata={"output_validation": {"output_schema": schema, "on_schema_fail": "block"}}
        )
        result = await pipeline.run_output_blocking('{"wrong_field": 123}', ctx)
        assert result.verdict == Verdict.BLOCK
