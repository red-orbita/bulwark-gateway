"""
Schema Validator — JSON Schema validation for structured LLM outputs.

Validates that LLM responses conform to expected schemas. Supports:
  - JSON Schema validation (jsonschema library)
  - JSON repair for minor formatting issues
  - Configurable behavior: block, warn, or repair

Policy configuration per agent:
  output_validation:
    schema: schemas/extraction_output.json
    on_schema_fail: repair   # block | warn | repair
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import OutputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

# JSON code block extraction patterns
JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)
JSON_OBJECT_PATTERN = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


def _jsonschema_available() -> bool:
    try:
        import jsonschema  # noqa: F401
        return True
    except ImportError:
        return False


class SchemaValidator(OutputScanner):
    """Validates LLM output against JSON Schema definitions.

    Supports multiple schema sources:
      1. Inline schema in policy metadata (context.metadata["output_schema"])
      2. File path reference (context.metadata["output_schema_path"])
      3. Schema registry (per agent_id lookup)

    Behavior on validation failure (configurable):
      - "block": Return BLOCK verdict
      - "warn": Return WARN verdict (log but allow)
      - "repair": Attempt JSON repair, return REDACT with modified content

    JSON extraction: Handles LLM responses that wrap JSON in markdown code blocks.
    """

    def __init__(
        self,
        default_on_fail: str = "warn",
        schema_dir: Path | None = None,
    ) -> None:
        self._default_on_fail = default_on_fail
        self._schema_dir = schema_dir or Path("config/schemas")
        self._schemas: dict[str, dict] = {}  # agent_id → schema cache

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="schema_validator",
            version="1.0.0",
            scanner_type=ScannerType.OUTPUT_BLOCKING,
            description="JSON Schema validation for structured LLM outputs",
            author="sentinel",
            priority=10,
        )

    async def startup(self) -> None:
        """Load schema files from schema directory."""
        if self._schema_dir.exists():
            for schema_file in self._schema_dir.glob("*.json"):
                try:
                    schema = json.loads(schema_file.read_text())
                    self._schemas[schema_file.stem] = schema
                    logger.debug("schema_loaded", extra={"name": schema_file.stem})
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(
                        "schema_load_failed",
                        extra={"file": str(schema_file), "error": str(e)[:100]},
                    )

        logger.info(
            "schema_validator_ready",
            extra={"schemas_loaded": len(self._schemas)},
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Validate output against schema if configured for this agent.

        Returns ALLOW if:
          - No schema configured for this agent
          - Content is not JSON (plain text response)
          - Content validates against schema
        """
        # Get schema configuration
        output_config = context.metadata.get("output_validation", {})
        schema = self._resolve_schema(context, output_config)

        if schema is None:
            return GuardrailResult(verdict=Verdict.ALLOW)

        on_fail = output_config.get("on_schema_fail", self._default_on_fail)

        # Extract JSON from content (handles markdown code blocks)
        json_content = self._extract_json(content)
        if json_content is None:
            # Not JSON content — might be plain text response, skip
            if output_config.get("require_json", False):
                return self._handle_failure(
                    "Output is not valid JSON but JSON is required",
                    content, schema, on_fail, context,
                )
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Validate against schema
        errors = self._validate(json_content, schema)
        if not errors:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Validation failed
        error_summary = "; ".join(errors[:3])
        return self._handle_failure(error_summary, json_content, schema, on_fail, context)

    def _resolve_schema(self, context: ScanContext, output_config: dict) -> dict | None:
        """Resolve schema from config metadata."""
        # Inline schema
        if "output_schema" in output_config:
            schema = output_config["output_schema"]
            if isinstance(schema, dict):
                return schema

        # Schema file path reference
        schema_path = output_config.get("output_schema_path")
        if schema_path:
            path = Path(schema_path)
            if not path.is_absolute():
                path = self._schema_dir / path
            try:
                return json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                pass

        # Schema registry lookup by agent_id
        agent_schema = self._schemas.get(context.agent_id)
        if agent_schema:
            return agent_schema

        return None

    def _extract_json(self, content: str) -> str | None:
        """Extract JSON from LLM output (handles markdown code blocks)."""
        # Try direct JSON parse first
        stripped = content.strip()
        if stripped.startswith(("{", "[")):
            try:
                json.loads(stripped)
                return stripped
            except json.JSONDecodeError:
                pass

        # Try extracting from markdown code block
        match = JSON_BLOCK_PATTERN.search(content)
        if match:
            candidate = match.group(1).strip()
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                pass

        # Try finding first JSON object in text
        match = JSON_OBJECT_PATTERN.search(content)
        if match:
            candidate = match.group(0)
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                pass

        return None

    def _validate(self, json_content: str, schema: dict) -> list[str]:
        """Validate JSON content against schema. Returns list of error messages."""
        if not _jsonschema_available():
            logger.debug("jsonschema_not_available")
            return []

        import jsonschema

        try:
            parsed = json.loads(json_content)
            validator = jsonschema.Draft7Validator(schema)
            errors = list(validator.iter_errors(parsed))
            return [
                f"{e.path}: {e.message}" if e.path else e.message
                for e in errors[:10]
            ]
        except json.JSONDecodeError as e:
            return [f"Invalid JSON: {e}"]
        except jsonschema.SchemaError as e:
            logger.warning("invalid_schema", extra={"error": str(e)[:100]})
            return []

    def _handle_failure(
        self,
        error_msg: str,
        content: str,
        schema: dict,
        on_fail: str,
        context: ScanContext,
    ) -> GuardrailResult:
        """Handle validation failure based on configured behavior."""
        if on_fail == "repair":
            repaired = self._attempt_repair(content, schema)
            if repaired:
                return GuardrailResult(
                    verdict=Verdict.REDACT,
                    modified_content=repaired,
                    events=[
                        SecurityEvent(
                            tenant_id=context.tenant_id,
                            agent_id=context.agent_id,
                            verdict=Verdict.REDACT,
                            category=ThreatCategory.INSECURE_OUTPUT,
                            description=f"Schema validation failed, output repaired: {error_msg[:200]}",
                            source="schema_validator",
                            severity="low",
                            metadata={"on_fail": "repair", "errors": error_msg},
                        )
                    ],
                )

        if on_fail == "block":
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.INSECURE_OUTPUT,
                        description=f"Schema validation failed: {error_msg[:200]}",
                        source="schema_validator",
                        severity="medium",
                        metadata={"on_fail": "block", "errors": error_msg},
                    )
                ],
            )

        # Default: warn
        return GuardrailResult(
            verdict=Verdict.WARN,
            events=[
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.INSECURE_OUTPUT,
                    description=f"Schema validation failed: {error_msg[:200]}",
                    source="schema_validator",
                    severity="low",
                    metadata={"on_fail": "warn", "errors": error_msg},
                )
            ],
        )

    def _attempt_repair(self, content: str, schema: dict) -> str | None:
        """Attempt to repair common JSON issues.

        Handles:
          - Trailing commas
          - Single quotes instead of double
          - Missing closing brackets
          - Unquoted keys
        """
        try:
            # Try json_repair if available
            from json_repair import repair_json
            repaired = repair_json(content)
            if repaired:
                # Verify repaired JSON validates
                parsed = json.loads(repaired)
                if _jsonschema_available():
                    import jsonschema
                    jsonschema.validate(parsed, schema)
                return repaired
        except ImportError:
            pass
        except Exception:
            pass

        # Manual repair: common fixes
        try:
            fixed = content
            # Remove trailing commas before closing bracket
            fixed = re.sub(r",\s*([}\]])", r"\1", fixed)
            # Replace single quotes with double
            fixed = fixed.replace("'", '"')

            parsed = json.loads(fixed)
            if _jsonschema_available():
                import jsonschema
                jsonschema.validate(parsed, schema)
            return fixed
        except Exception:
            pass

        return None

    async def health(self) -> bool:
        return True

    async def shutdown(self) -> None:
        pass
