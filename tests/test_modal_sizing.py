"""Guard against the modal-clipping regression.

Root cause: the vendored ``tailwind.min.css`` is a fixed build that does NOT
include arbitrary-value classes like ``max-h-[90vh]``. Modal panels relying on
them therefore had no height cap, grew past the viewport, and were clipped at
the top by the ``items-center`` overlay with no way to scroll. The fix caps the
panels with an inline ``style="max-height:..vh"`` (which works regardless of the
CSS build) so the existing ``overflow-y-auto`` can scroll the panel internally.

These tests fail if anyone reintroduces a dead ``max-h-[..vh]`` class.
"""

from __future__ import annotations

import re
from pathlib import Path

PAGES = Path(__file__).resolve().parent.parent / "admin" / "templates" / "pages"

_DEAD_VH = re.compile(r"max-h-\[\d+vh\]")

# Pages whose add/edit modals were clipping and must now carry an inline cap.
_FIXED_MODAL_PAGES = [
    "siem.html",
    "notifications.html",
    "guardrails.html",
    "policies.html",
    "tenants.html",
    "plugins.html",
]


def test_no_dead_viewport_max_height_classes_anywhere():
    offenders = []
    for path in PAGES.glob("*.html"):
        if _DEAD_VH.search(path.read_text(encoding="utf-8")):
            offenders.append(path.name)
    assert not offenders, (
        "Dead arbitrary max-h-[..vh] classes found (not in the vendored CSS "
        f"build; use inline style=\"max-height:..vh\" instead): {offenders}"
    )


def test_fixed_modals_use_inline_max_height():
    for name in _FIXED_MODAL_PAGES:
        src = (PAGES / name).read_text(encoding="utf-8")
        assert "max-height:" in src, f"{name} modal lost its inline max-height cap"


def test_capped_panels_can_scroll_internally():
    # Every inline max-height cap must sit on an element that can scroll, so the
    # capped panel is never itself the thing that clips content.
    for name in _FIXED_MODAL_PAGES:
        src = (PAGES / name).read_text(encoding="utf-8")
        for line in src.splitlines():
            if "max-height:" in line:
                assert ("overflow-y-auto" in line) or ("overflow-hidden flex flex-col" in line), (
                    f"{name}: capped panel must scroll (overflow-y-auto) or be a "
                    f"flex-col shell with a scrolling body: {line.strip()[:120]}"
                )
