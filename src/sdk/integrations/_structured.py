"""Bounded, eager data contracts shared by framework adapters.

Framework instances are trusted integration endpoints, not trusted payloads.
Payload inspection never calls serializers, properties, iterators or __str__.
"""

from __future__ import annotations

import json
from types import GetSetDescriptorType, SimpleNamespace
from typing import Any, Callable

from src.sdk.guard import SecurityError

MAX_NODES = 1024
MAX_DEPTH = 32
MAX_INPUT_BYTES = 16384
MAX_OUTPUT_BYTES = 65536


class StructuredValue:
    """Capture a detached, validated tree and its exact text replacement paths."""

    def __init__(self, value: Any, *, output: bool = False) -> None:
        self.texts: list[str] = []
        self._leaves: list[tuple[Any, ...]] = []
        self._contexts: list[tuple[int, int | None, str]] = []
        self._objects = False
        self._nodes = 0
        self._bytes = 0
        active: set[int] = set()
        limit = MAX_OUTPUT_BYTES if output else MAX_INPUT_BYTES
        self._limit = limit

        def visit(item: Any, path: tuple[Any, ...], depth: int) -> Any:
            self._nodes += 1
            if self._nodes > MAX_NODES or depth > MAX_DEPTH:
                raise SecurityError("Structured inspection limit exceeded")
            kind = type(item)
            if type(kind) is not type:
                raise SecurityError("Custom payload metaclasses are unsupported")
            if kind is str:
                if len(item) > limit:
                    raise SecurityError("Structured inspection limit exceeded")
                try:
                    self._bytes += len(item.encode("utf-8")) + bool(self.texts)
                except UnicodeError:
                    raise SecurityError("Invalid text encoding") from None
                if self._bytes > limit:
                    raise SecurityError("Structured inspection limit exceeded")
                self.texts.append(item)
                self._leaves.append(path)
                return item
            if item is None or kind in (bool, int, float):
                if kind is int and item.bit_length() > 256:
                    raise SecurityError("Numeric inspection limit exceeded")
                return item
            if id(item) in active:
                raise SecurityError("Cyclic payload is unsupported")
            identity = id(item)
            active.add(identity)
            try:
                if kind in (list, tuple):
                    if len(item) > MAX_NODES:
                        raise SecurityError("Structured inspection limit exceeded")
                    return kind(visit(child, (*path, index), depth + 1) for index, child in enumerate(item))
                if kind is not dict:
                    item = _record_fields(item)
                    self._objects = True
                if len(item) > MAX_NODES:
                    raise SecurityError("Structured inspection limit exceeded")
                fields: dict[str, Any] = {}
                for key, child in item.items():
                    if type(key) is not str:
                        raise SecurityError("Only string mapping keys are supported")
                    # Keys are content too, but cannot be renamed without changing semantics.
                    key_index = len(self.texts)
                    visit(key, (*path, None, key), depth + 1)
                    value_index = len(self.texts)
                    fields[key] = visit(child, (*path, key), depth + 1)
                    if type(child) is str:
                        self._contexts.append((key_index, value_index, ""))
                    elif type(child) in (bool, int, float):
                        self._contexts.append((key_index, None, str(child)))
                if kind is dict:
                    return fields
                # Allocate only already-validated passive records, bypassing all
                # constructors/copy hooks; never retain the original field dict.
                record = SimpleNamespace() if kind is SimpleNamespace else object.__new__(kind)
                vars(kind)["__dict__"].__get__(record, kind).update(fields)
                return record
            finally:
                active.remove(identity)

        try:
            self.value = visit(value, (), 0)
            self.contextual_texts()
        except SecurityError:
            raise
        except Exception:
            raise SecurityError("Unable to capture structured snapshot") from None

    def contextual_texts(self, replacements: list[str] | None = None) -> list[str]:
        texts = self.texts if replacements is None else replacements
        candidates: list[str] = []
        size = 0
        for key_index, value_index, scalar in self._contexts:
            key = texts[key_index]
            value = scalar if value_index is None else texts[value_index]
            size += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 1
            if size > self._limit:
                raise SecurityError("Contextual inspection limit exceeded")
            candidates.append(f"{key}={value}")
            encoded = json.dumps({key: value}, ensure_ascii=False, separators=(",", ":"))
            size += len(encoded.encode("utf-8"))
            if size > self._limit:
                raise SecurityError("Contextual inspection limit exceeded")
            candidates.append(encoded)
        return candidates

    @property
    def text(self) -> str:
        return "\n".join(self.texts)

    def replace(self, replacements: list[str]) -> Any:
        changes = {
            path: new for path, old, new in zip(self._leaves, self.texts, replacements, strict=True) if old != new
        }
        if not changes:
            return self.value
        if self._objects or any(None in path for path in changes):
            raise SecurityError("Ambiguous or object redaction requires an explicit adapter")

        def rebuild(item: Any, path: tuple[Any, ...]) -> Any:
            if path in changes:
                return changes[path]
            if type(item) is dict:
                return {key: rebuild(child, (*path, key)) for key, child in item.items()}
            if type(item) in (list, tuple):
                return type(item)(rebuild(child, (*path, i)) for i, child in enumerate(item))
            return item

        return rebuild(self.value, ())


def _record_fields(value: Any) -> dict[str, Any]:
    """Only passive records with ordinary storage, never arbitrary duck typing."""
    kind = type(value)
    if type(kind) is not type:
        raise SecurityError("Unsupported payload object")
    if kind is not SimpleNamespace:
        if kind.__bases__ != (object,):
            raise SecurityError("Unsupported payload object")
        allowed = {
            "__module__",
            "__doc__",
            "__dict__",
            "__weakref__",
            "__init__",
            "__annotations__",
            "__static_attributes__",
            "__firstlineno__",
        }
        if any(name not in allowed for name in vars(kind)):
            raise SecurityError("Dynamic payload objects are unsupported")
    descriptor = vars(kind).get("__dict__")
    if type(descriptor) is not GetSetDescriptorType:
        raise SecurityError("Unsupported payload storage")
    fields = descriptor.__get__(value, kind)
    if type(fields) is not dict or len(fields) > MAX_NODES or any(type(key) is not str for key in fields):
        raise SecurityError("Unsupported payload fields")
    if not any(key in fields for key in ("content", "raw", "response", "text", "query_str", "result", "output")):
        raise SecurityError("Unknown payload record")
    return fields


def checked_text(result: Any, text: str, *, output: bool) -> str:
    verdict = result.verdict.value
    if verdict == "block" or (verdict == "redact" and not output):
        raise SecurityError("Content blocked by adapter policy", result=result)
    if verdict == "redact":
        if type(result.modified_content) is not str:
            raise SecurityError("Redaction has no valid replacement", result=result)
        StructuredValue(result.modified_content, output=output)
        return result.modified_content
    if verdict not in ("allow", "warn"):
        raise SecurityError("Unknown scanner verdict")
    return text


def scan_structure(value: Any, scan: Callable[..., Any], *, output: bool = False, **context: Any) -> Any:
    tree = StructuredValue(value, output=output)
    try:
        if not output:
            for text in tree.texts:
                checked_text(scan(text, **context), text, output=False)
            if len(tree.texts) > 1:
                checked_text(scan(tree.text, **context), tree.text, output=False)
            for text in tree.contextual_texts():
                checked_text(scan(text, **context), text, output=False)
            return tree.value
        replacements: list[str] = []
        size = 0
        for text in tree.texts:
            replacement = checked_text(scan(text, **context), text, output=True)
            size += len(replacement.encode("utf-8")) + bool(replacements)
            if size > MAX_OUTPUT_BYTES:
                raise SecurityError("Redacted output exceeds inspection limit")
            replacements.append(replacement)
        safe = tree.replace(replacements)
        for text in tree.contextual_texts(replacements):
            checked_text(scan(text, **context), text, output=False)
        # A finding spanning leaves has no unambiguous field-level replacement.
        if len(replacements) > 1:
            joined = "\n".join(replacements)
            checked_text(scan(joined, **context), joined, output=False)
        return safe
    except SecurityError:
        raise
    except Exception:
        raise SecurityError("Adapter inspection failed") from None


async def scan_structure_async(value: Any, scan: Callable[..., Any], *, output: bool = False, **context: Any) -> Any:
    tree = StructuredValue(value, output=output)
    try:
        if not output:
            for text in tree.texts:
                checked_text(await scan(text, **context), text, output=False)
            if len(tree.texts) > 1:
                checked_text(await scan(tree.text, **context), tree.text, output=False)
            for text in tree.contextual_texts():
                checked_text(await scan(text, **context), text, output=False)
            return tree.value
        replacements: list[str] = []
        size = 0
        for text in tree.texts:
            replacement = checked_text(await scan(text, **context), text, output=True)
            size += len(replacement.encode("utf-8")) + bool(replacements)
            if size > MAX_OUTPUT_BYTES:
                raise SecurityError("Redacted output exceeds inspection limit")
            replacements.append(replacement)
        safe = tree.replace(replacements)
        for text in tree.contextual_texts(replacements):
            checked_text(await scan(text, **context), text, output=False)
        if len(replacements) > 1:
            joined = "\n".join(replacements)
            checked_text(await scan(joined, **context), joined, output=False)
        return safe
    except SecurityError:
        raise
    except Exception:
        raise SecurityError("Adapter inspection failed") from None
