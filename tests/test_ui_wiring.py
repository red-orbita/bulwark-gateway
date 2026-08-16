"""UI↔backend wiring regression test.

Parses every ``fetch('/admin/...')`` call in the admin page templates and
asserts a matching route (same HTTP method + path pattern) exists in the real
FastAPI app. This catches the class of bug where the UI points at a route that
does not exist or uses the wrong method (e.g. the onboarding wizard POSTing to a
GET-only ``/admin/siem/config``), which silently 404/405s at runtime.

The parser is concatenation-aware: ``fetch('/admin/x/' + id + '/toggle')`` and
template literals ``fetch(`/admin/x/${id}`)`` are reconstructed into a path
pattern where dynamic segments become wildcards matched against route ``{param}``
segments.
"""

from __future__ import annotations

import os

# Must be set before importing admin modules (config validates JWT secret length).
os.environ.setdefault("ADMIN_DEBUG", "true")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")
os.environ.setdefault("BULWARK_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")
os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "unit-test-key-0123456789abcdef-xyz")

import glob  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from admin.main import app  # noqa: E402

# ruff: noqa: I001 - imports intentionally follow required env setup above

_WILD = "\x01"  # sentinel marking a dynamic path segment
_PAGES_DIR = Path(__file__).resolve().parent.parent / "admin" / "templates" / "pages"
_METHOD_RE = re.compile(r"method\s*:\s*['\"](\w+)['\"]")
_STRING_RE = re.compile(r"`([^`]*)`|'([^']*)'|\"([^\"]*)\"")


def _route_segments(path: str) -> list[str]:
    """Split a route path into segments; ``{param}`` becomes a wildcard."""
    return [
        "*" if (s.startswith("{") and s.endswith("}")) else s
        for s in path.strip("/").split("/")
    ]


def _build_route_index() -> dict[str, list[list[str]]]:
    index: dict[str, list[list[str]]] = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        if not path:
            continue
        for method in getattr(route, "methods", None) or set():
            index.setdefault(method.upper(), []).append(_route_segments(path))
    return index


def _iter_fetch_args(text: str):
    """Yield ``(line, arg_list)`` for every ``fetch(...)`` call.

    Splits the call's top-level comma-separated arguments while respecting
    nested brackets and string literals, so the URL expression (arg 0) and the
    options object (arg 1, holding ``method:``) are separated cleanly.
    """
    i = 0
    while True:
        k = text.find("fetch(", i)
        if k < 0:
            return
        j = k + len("fetch(")
        depth = 1
        cur: list[str] = []
        args: list[str] = []
        in_str: str | None = None
        esc = False
        while j < len(text) and depth > 0:
            c = text[j]
            if in_str:
                cur.append(c)
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == in_str:
                    in_str = None
            else:
                if c in "'\"`":
                    in_str = c
                    cur.append(c)
                elif c in "([{":
                    depth += 1
                    cur.append(c)
                elif c in ")]}":
                    depth -= 1
                    if depth == 0:
                        args.append("".join(cur))
                        break
                    cur.append(c)
                elif c == "," and depth == 1:
                    args.append("".join(cur))
                    cur = []
                else:
                    cur.append(c)
            j += 1
        line = text[:k].count("\n") + 1
        yield line, args
        i = j if j > i else i + 1


def _reconstruct_path(expr: str) -> str:
    """Rebuild a URL from a JS expression, inserting wildcards for variables.

    ``'/a/' + id + '/b'`` -> ``/a/<WILD>/b``; ```/a/${id}``` -> ``/a/<WILD>``.
    """
    out: list[str] = []
    pos = 0
    for m in _STRING_RE.finditer(expr):
        gap = expr[pos:m.start()]
        if re.search(r"[A-Za-z0-9_.$]", gap):
            out.append(_WILD)
        inner = next(g for g in m.groups() if g is not None)
        inner = re.sub(r"\$\{[^}]*\}", _WILD, inner)  # template interpolation
        out.append(inner)
        pos = m.end()
    if re.search(r"[A-Za-z0-9_.$]", expr[pos:]):
        out.append(_WILD)
    return "".join(out)


def _ui_segments(path: str) -> list[str]:
    path = path.split("?")[0]  # drop query string
    return ["*" if _WILD in s else s for s in path.strip("/").split("/")]


def _segments_match(route_segs: list[str], ui_segs: list[str]) -> bool:
    if len(route_segs) != len(ui_segs):
        return False
    return all(a == "*" or b == "*" or a == b for a, b in zip(route_segs, ui_segs, strict=False))


def _collect_ui_calls() -> list[tuple[str, int, str, str]]:
    """Return (file, line, method, reconstructed_path) for every admin fetch."""
    calls: list[tuple[str, int, str, str]] = []
    for f in sorted(glob.glob(str(_PAGES_DIR / "*.html"))):
        text = Path(f).read_text()
        for line, args in _iter_fetch_args(text):
            if not args:
                continue
            path = _reconstruct_path(args[0])
            if not path.startswith("/admin/"):
                continue
            method_match = _METHOD_RE.search(",".join(args[1:]))
            method = (method_match.group(1) if method_match else "GET").upper()
            calls.append((os.path.basename(f), line, method, path))
    return calls


_ROUTE_INDEX = _build_route_index()
_UI_CALLS = _collect_ui_calls()


def test_ui_calls_were_discovered():
    """Guard against the parser silently finding nothing (e.g. path change)."""
    assert len(_UI_CALLS) > 30, f"expected many admin fetch() calls, found {len(_UI_CALLS)}"


@pytest.mark.parametrize(
    "page,line,method,path",
    _UI_CALLS,
    ids=[f"{c[0]}:{c[1]}:{c[2]}" for c in _UI_CALLS],
)
def test_ui_fetch_has_matching_route(page, line, method, path):
    ui_segs = _ui_segments(path)
    matched = any(
        _segments_match(route_segs, ui_segs)
        for route_segs in _ROUTE_INDEX.get(method, [])
    )
    pretty = path.replace(_WILD, "{*}")
    assert matched, (
        f"{page}:{line} calls {method} {pretty} but no matching admin route exists "
        f"(broken UI→backend wiring)"
    )
