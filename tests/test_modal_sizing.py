"""Guard against the modal-clipping regression.

Two independent root causes were behind modals whose top was clipped and
unreachable:

1. **Dead height class.** The vendored ``tailwind.min.css`` is a fixed build
   that does NOT include arbitrary-value classes like ``max-h-[90vh]``. Modal
   panels relying on them had no height cap, grew past the viewport, and were
   clipped by the ``items-center`` overlay with no way to scroll. Fixed by
   capping panels with an inline ``style="max-height:..vh"`` so the existing
   ``overflow-y-auto`` can scroll the panel internally.

2. **Fixed containing-block trap (the real killer).** ``<main id="main-content"
   class="sg-page-enter">`` wraps every page's modals. ``.sg-page-enter`` ran
   ``sg-page-settle`` with ``animation-fill-mode: both``, whose resting keyframe
   was ``transform: translateY(0)``. Per the CSS Transforms spec, ANY transform
   other than ``none`` makes the element the containing block for
   ``position: fixed`` descendants — so every modal overlay (``fixed inset-0``)
   anchored to <main> (offset below the header, sized to content) instead of the
   viewport, clipping the top with no viewport-level scroll. Fixed by resting the
   keyframe at ``transform: none``.

These tests fail if either regression is reintroduced.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
PAGES = _ROOT / "admin" / "templates" / "pages"
_CSS = _ROOT / "admin" / "static" / "css"

_DEAD_VH = re.compile(r"max-h-\[\d+vh\]")

# Pages whose add/edit modals were clipping and must now carry an inline cap,
# plus pages capped preventively in the same sweep so no add/edit modal can clip.
_FIXED_MODAL_PAGES = [
    "siem.html",
    "notifications.html",
    "guardrails.html",
    "policies.html",
    "tenants.html",
    "plugins.html",
    "iocs.html",
    "agents.html",
    "rbac.html",
    "quotas.html",
    "rate_limits.html",
    "gdpr.html",
    "cost.html",
    "virtual_keys.html",
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


def test_main_content_settle_rests_at_transform_none():
    """<main class="sg-page-enter"> must NOT hold a transform at rest.

    A resting ``translateY(0)`` (or any non-``none`` transform) turns
    #main-content into the containing block for ``position: fixed`` modal
    overlays, anchoring them to <main> instead of the viewport and clipping the
    top of tall modals. The settle keyframe must rest at ``transform: none``.
    """
    dead = re.compile(r"@keyframes\s+sg-page-settle\b[^}]*?to\s*\{\s*transform\s*:\s*translateY\(0\)")
    good = re.compile(r"@keyframes\s+sg-page-settle\b.*?to\s*\{\s*transform\s*:\s*none\s*;?\s*\}", re.DOTALL)
    for css_name in ("input.css", "tailwind.min.css"):
        css = (_CSS / css_name).read_text(encoding="utf-8")
        assert "sg-page-settle" in css, f"{css_name}: sg-page-settle keyframes missing"
        assert not dead.search(css), (
            f"{css_name}: sg-page-settle rests at translateY(0) — this re-traps "
            "fixed modal overlays inside #main-content. Use `transform: none`."
        )
        assert good.search(css), (
            f"{css_name}: sg-page-settle must rest at `transform: none`."
        )
