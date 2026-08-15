"""
Minimal, dependency-free JSON Schema validator for tool-call arguments.

This is intentionally NOT a full JSON Schema (Draft 2020-12) implementation.
It is a small, bounded, DoS-safe validator covering the subset of keywords
that matter for tool-call security enforcement:

    - type            (string, integer, number, boolean, object, array, null,
                       or a list of those)
    - required        (list of required property names)
    - properties      (per-property subschemas)
    - additionalProperties: false  (reject undeclared arguments — the key
                       control that prevents parameter smuggling past regex
                       allowlists)
    - enum            (closed set of allowed values)
    - const           (exact required value)
    - minimum / maximum / exclusiveMinimum / exclusiveMaximum  (numbers)
    - minLength / maxLength                                    (strings)
    - pattern         (regex, with a length guard against ReDoS)
    - minItems / maxItems                                      (arrays)
    - items           (array element subschema)

Design rules (aligned with the hot-path conventions of this codebase):
    * No external dependencies, no network, no eval.
    * Bounded recursion (``max_depth``) and bounded error collection to keep
      validation cheap and predictable for adversarial inputs.
    * A malformed *schema* (config error) never raises — validation is simply
      skipped for the offending keyword, mirroring how ``argument_patterns``
      swallows ``re.error``. Malformed *data* produces errors.

The validator returns a list of human-readable error strings. An empty list
means the instance is valid.
"""

from __future__ import annotations

import re
from typing import Any

# Bounds to keep validation cheap and adversarial-input safe.
_MAX_DEPTH = 16
_MAX_ERRORS = 32
_MAX_PATTERN_LEN = 500
_MAX_PATTERN_INPUT = 10_000

# JSON Schema type name -> Python isinstance check.
# NOTE: bool is a subclass of int in Python; we handle that explicitly so that
# ``True`` is NOT accepted where an integer/number is required, and vice versa.
_TYPE_LABELS = {
    "string": "string",
    "integer": "integer",
    "number": "number",
    "boolean": "boolean",
    "object": "object",
    "array": "array",
    "null": "null",
}


def _matches_type(value: Any, type_name: str) -> bool:
    """Return True if ``value`` matches a single JSON Schema type name."""
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        # Reject bool (subclass of int); accept int-valued floats (e.g. 3.0).
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and value.is_integer()
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "null":
        return value is None
    # Unknown type keyword in schema -> don't fail the data on it.
    return True


def validate(instance: Any, schema: Any, *, max_depth: int = _MAX_DEPTH) -> list[str]:
    """Validate ``instance`` against ``schema``.

    Args:
        instance: The parsed data to validate (e.g. tool_call.arguments).
        schema: A JSON Schema dict (a subset of Draft 2020-12).
        max_depth: Maximum nesting depth to traverse (DoS guard).

    Returns:
        A list of error message strings. Empty means valid. A non-dict schema
        (config error) yields no errors — validation is skipped.
    """
    if not isinstance(schema, dict):
        return []
    errors: list[str] = []
    _validate(instance, schema, "$", 0, max_depth, errors)
    return errors


def _validate(
    value: Any,
    schema: dict[str, Any],
    path: str,
    depth: int,
    max_depth: int,
    errors: list[str],
) -> None:
    if len(errors) >= _MAX_ERRORS or depth > max_depth:
        return

    # --- type ---
    type_kw = schema.get("type")
    if type_kw is not None:
        type_names = type_kw if isinstance(type_kw, list) else [type_kw]
        if type_names and not any(_matches_type(value, t) for t in type_names):
            wanted = "/".join(str(t) for t in type_names)
            errors.append(f"{path}: expected type {wanted}, got {_typename(value)}")
            # If the type is wrong, deeper keyword checks are noise; stop here.
            return

    # --- const ---
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: value must equal const {schema['const']!r}")

    # --- enum ---
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        errors.append(f"{path}: value {_short(value)} not in allowed enum")

    # --- string constraints ---
    if isinstance(value, str):
        _validate_string(value, schema, path, errors)

    # --- numeric constraints ---
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        _validate_number(value, schema, path, errors)

    # --- object constraints ---
    if isinstance(value, dict):
        _validate_object(value, schema, path, depth, max_depth, errors)

    # --- array constraints ---
    if isinstance(value, list):
        _validate_array(value, schema, path, depth, max_depth, errors)


def _validate_string(
    value: str, schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and len(value) < min_len:
        errors.append(f"{path}: string shorter than minLength {min_len}")
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and len(value) > max_len:
        errors.append(f"{path}: string longer than maxLength {max_len}")
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and 0 < len(pattern) <= _MAX_PATTERN_LEN:
        try:
            compiled = re.compile(pattern)
        except re.error:
            return  # malformed schema pattern -> skip (config error, not data)
        if len(value) <= _MAX_PATTERN_INPUT and compiled.search(value) is None:
            errors.append(f"{path}: string does not match required pattern")


def _validate_number(
    value: float, schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    minimum = schema.get("minimum")
    if isinstance(minimum, (int, float)) and value < minimum:
        errors.append(f"{path}: value {value} < minimum {minimum}")
    maximum = schema.get("maximum")
    if isinstance(maximum, (int, float)) and value > maximum:
        errors.append(f"{path}: value {value} > maximum {maximum}")
    excl_min = schema.get("exclusiveMinimum")
    if isinstance(excl_min, (int, float)) and value <= excl_min:
        errors.append(f"{path}: value {value} <= exclusiveMinimum {excl_min}")
    excl_max = schema.get("exclusiveMaximum")
    if isinstance(excl_max, (int, float)) and value >= excl_max:
        errors.append(f"{path}: value {value} >= exclusiveMaximum {excl_max}")


def _validate_object(
    value: dict[str, Any],
    schema: dict[str, Any],
    path: str,
    depth: int,
    max_depth: int,
    errors: list[str],
) -> None:
    properties = schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}

    # required
    required = schema.get("required")
    if isinstance(required, list):
        for req in required:
            if req not in value:
                errors.append(f"{path}: missing required property '{req}'")

    # additionalProperties: false  -> reject undeclared keys (anti-smuggling)
    additional = schema.get("additionalProperties", True)
    if additional is False:
        for key in value:
            if key not in properties:
                errors.append(f"{path}: additional property '{key}' is not allowed")

    # recurse into declared properties that are present
    for key, subschema in properties.items():
        if key in value and isinstance(subschema, dict):
            if len(errors) >= _MAX_ERRORS:
                return
            _validate(
                value[key], subschema, f"{path}.{key}", depth + 1, max_depth, errors
            )


def _validate_array(
    value: list[Any],
    schema: dict[str, Any],
    path: str,
    depth: int,
    max_depth: int,
    errors: list[str],
) -> None:
    min_items = schema.get("minItems")
    if isinstance(min_items, int) and len(value) < min_items:
        errors.append(f"{path}: array shorter than minItems {min_items}")
    max_items = schema.get("maxItems")
    if isinstance(max_items, int) and len(value) > max_items:
        errors.append(f"{path}: array longer than maxItems {max_items}")

    items_schema = schema.get("items")
    if isinstance(items_schema, dict):
        for i, item in enumerate(value):
            if len(errors) >= _MAX_ERRORS:
                return
            _validate(
                item, items_schema, f"{path}[{i}]", depth + 1, max_depth, errors
            )


def _typename(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def _short(value: Any, limit: int = 40) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."
