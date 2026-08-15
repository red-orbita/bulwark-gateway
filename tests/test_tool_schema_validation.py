"""
Tests for JSON Schema validation of tool-call arguments.

Covers both the standalone validator (src/guardrails/schema_validation.py)
and its enforcement inside the tool policy engine via
ToolPolicy.parameter_schema.
"""

import pytest

from src.guardrails import schema_validation as sv
from src.guardrails.tool_policy import AgentPolicy, ToolPolicy, ToolPolicyEngine
from src.models import ToolCall, Verdict


# ==============================================================================
# Standalone validator
# ==============================================================================
class TestValidatorTypes:
    def test_valid_object(self):
        schema = {"type": "object", "properties": {"q": {"type": "string"}}}
        assert sv.validate({"q": "hello"}, schema) == []

    def test_wrong_type_string_vs_integer(self):
        schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
        errors = sv.validate({"n": "not-a-number"}, schema)
        assert len(errors) == 1
        assert "expected type integer" in errors[0]

    def test_bool_is_not_integer(self):
        # bool is a subclass of int in Python — must be rejected as integer.
        schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
        assert sv.validate({"n": True}, schema) != []

    def test_bool_is_not_number(self):
        schema = {"type": "object", "properties": {"n": {"type": "number"}}}
        assert sv.validate({"n": False}, schema) != []

    def test_int_valued_float_accepted_as_integer(self):
        schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
        assert sv.validate({"n": 3.0}, schema) == []

    def test_null_type(self):
        schema = {"type": "object", "properties": {"x": {"type": "null"}}}
        assert sv.validate({"x": None}, schema) == []
        assert sv.validate({"x": 0}, schema) != []

    def test_union_type(self):
        schema = {"type": "object", "properties": {"x": {"type": ["string", "null"]}}}
        assert sv.validate({"x": "a"}, schema) == []
        assert sv.validate({"x": None}, schema) == []
        assert sv.validate({"x": 5}, schema) != []

    def test_non_dict_schema_is_noop(self):
        assert sv.validate({"anything": 1}, None) == []
        assert sv.validate({"anything": 1}, "not-a-schema") == []


class TestValidatorConstraints:
    def test_required_missing(self):
        schema = {"type": "object", "required": ["path"], "properties": {}}
        errors = sv.validate({}, schema)
        assert any("missing required property 'path'" in e for e in errors)

    def test_additional_properties_rejected(self):
        schema = {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "additionalProperties": False,
        }
        errors = sv.validate({"query": "hi", "evil": "smuggled"}, schema)
        assert any("additional property 'evil'" in e for e in errors)

    def test_additional_properties_allowed_by_default(self):
        schema = {"type": "object", "properties": {"query": {"type": "string"}}}
        assert sv.validate({"query": "hi", "extra": 1}, schema) == []

    def test_enum(self):
        schema = {"type": "object", "properties": {"mode": {"enum": ["r", "w"]}}}
        assert sv.validate({"mode": "r"}, schema) == []
        assert sv.validate({"mode": "x"}, schema) != []

    def test_const(self):
        schema = {"type": "object", "properties": {"v": {"const": 42}}}
        assert sv.validate({"v": 42}, schema) == []
        assert sv.validate({"v": 43}, schema) != []

    def test_number_range(self):
        schema = {
            "type": "object",
            "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 10}},
        }
        assert sv.validate({"n": 5}, schema) == []
        assert sv.validate({"n": 0}, schema) != []
        assert sv.validate({"n": 11}, schema) != []

    def test_exclusive_bounds(self):
        schema = {
            "type": "object",
            "properties": {"n": {"type": "number", "exclusiveMinimum": 0}},
        }
        assert sv.validate({"n": 0.1}, schema) == []
        assert sv.validate({"n": 0}, schema) != []

    def test_string_length(self):
        schema = {
            "type": "object",
            "properties": {"s": {"type": "string", "minLength": 2, "maxLength": 4}},
        }
        assert sv.validate({"s": "abc"}, schema) == []
        assert sv.validate({"s": "a"}, schema) != []
        assert sv.validate({"s": "abcdef"}, schema) != []

    def test_string_pattern(self):
        schema = {
            "type": "object",
            "properties": {"id": {"type": "string", "pattern": r"^[a-z]+$"}},
        }
        assert sv.validate({"id": "abc"}, schema) == []
        assert sv.validate({"id": "abc123"}, schema) != []

    def test_malformed_pattern_is_skipped(self):
        # A broken regex in the schema is a config error, not a data error.
        schema = {
            "type": "object",
            "properties": {"id": {"type": "string", "pattern": "([unclosed"}},
        }
        assert sv.validate({"id": "anything"}, schema) == []


class TestValidatorNested:
    def test_nested_object(self):
        schema = {
            "type": "object",
            "properties": {
                "cfg": {
                    "type": "object",
                    "properties": {"port": {"type": "integer"}},
                    "additionalProperties": False,
                }
            },
        }
        assert sv.validate({"cfg": {"port": 8080}}, schema) == []
        assert sv.validate({"cfg": {"port": "x"}}, schema) != []
        assert sv.validate({"cfg": {"port": 1, "rogue": 2}}, schema) != []

    def test_array_items(self):
        schema = {
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 3}
            },
        }
        assert sv.validate({"tags": ["a", "b"]}, schema) == []
        assert sv.validate({"tags": ["a", 1]}, schema) != []
        assert sv.validate({"tags": ["a", "b", "c", "d"]}, schema) != []

    def test_depth_guard_does_not_crash(self):
        # Deeply nested data should be handled without recursion errors.
        schema = {"type": "object"}
        data = {"a": {}}
        node = data["a"]
        for _ in range(100):
            node["a"] = {}
            node = node["a"]
        assert sv.validate(data, schema) == []


# ==============================================================================
# Tool policy engine integration
# ==============================================================================
@pytest.fixture
def engine():
    e = ToolPolicyEngine()
    e.register_policy(
        AgentPolicy(
            tenant_id="corp",
            agent_id="bot",
            allowed_tools=[],  # all allowed (so schema is the gate)
            denied_tools=[],
            allow_command_execution=True,
            allow_file_write=True,
            tool_policies={
                "web_search": ToolPolicy(
                    name="web_search",
                    parameter_schema={
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "maxLength": 200},
                            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                )
            },
        )
    )
    return e


class TestSchemaEnforcement:
    def test_valid_arguments_allowed(self, engine):
        tc = ToolCall(name="web_search", arguments={"query": "python", "limit": 5})
        result = engine.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.ALLOW

    def test_wrong_type_blocked(self, engine):
        tc = ToolCall(name="web_search", arguments={"query": "hi", "limit": "lots"})
        result = engine.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.BLOCK
        assert result.blocked_tools == ["web_search"]

    def test_smuggled_argument_blocked(self, engine):
        # additionalProperties:false blocks params the tool never declared.
        tc = ToolCall(
            name="web_search",
            arguments={"query": "hi", "__proto__": "x", "shell": "rm -rf /"},
        )
        result = engine.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.BLOCK

    def test_missing_required_blocked(self, engine):
        tc = ToolCall(name="web_search", arguments={"limit": 3})
        result = engine.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.BLOCK

    def test_out_of_range_blocked(self, engine):
        tc = ToolCall(name="web_search", arguments={"query": "hi", "limit": 999})
        result = engine.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.BLOCK

    def test_no_schema_means_no_schema_gate(self):
        e = ToolPolicyEngine()
        e.register_policy(
            AgentPolicy(
                tenant_id="corp",
                agent_id="bot",
                allowed_tools=[],
                denied_tools=[],
                tool_policies={"web_search": ToolPolicy(name="web_search")},
            )
        )
        tc = ToolCall(name="web_search", arguments={"anything": [1, 2, 3]})
        result = e.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.ALLOW

    def test_event_metadata_on_block(self, engine):
        tc = ToolCall(name="web_search", arguments={"query": 123})
        result = engine.evaluate_tool_call(tc, "corp", "bot")
        assert result.verdict == Verdict.BLOCK
        assert result.events
        ev = result.events[0]
        assert ev.tool_name == "web_search"
        assert ev.source == "tool_policy_engine.schema"
