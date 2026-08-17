"""Accessibility (WCAG 2.1 AA) regression guards for the admin UI shell.

The admin console is a single-page-style shell where every page extends
``base.html``. A regression in that shared template degrades accessibility
across the entire product, so these tests pin the concrete invariants that
were previously missing:

* 3.1.1  Language of Page      — <html lang> present.
* 2.4.1  Bypass Blocks         — a skip-to-content link targeting <main>.
* 1.3.1  Info & Relationships  — <main> landmark exists and is the skip target.
* 4.1.2  Name, Role, Value     — icon-only nav links / header buttons carry an
                                 accessible name (aria-label), and decorative
                                 icons are hidden from assistive tech.
* 1.3.1  Landmarks             — multiple <nav> elements are disambiguated with
                                 aria-label.

These are static-template assertions (no browser needed): the template ships
inside the admin image, so Docker Compose and Kubernetes render identically.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_HTML = REPO_ROOT / "admin" / "templates" / "base.html"


@pytest.fixture(scope="module")
def base_src() -> str:
    return BASE_HTML.read_text(encoding="utf-8")


# ─── Document-level ──────────────────────────────────────────────────────────


def test_html_declares_language(base_src):
    """WCAG 3.1.1 — the page language must be programmatically set."""
    assert re.search(r"<html[^>]*\blang=", base_src)


def test_skip_link_present_and_targets_main(base_src):
    """WCAG 2.4.1 — a keyboard user must be able to bypass the nav."""
    assert 'href="#main-content"' in base_src
    assert "skip-link" in base_src
    # The skip link must be styled to become visible on focus (not display:none).
    assert ".skip-link:focus" in base_src


def test_main_landmark_is_skip_target(base_src):
    """WCAG 1.3.1 — the skip link target landmark must exist."""
    assert re.search(r"<main[^>]*\bid=\"main-content\"", base_src)


# ─── Landmarks ───────────────────────────────────────────────────────────────


def test_all_nav_landmarks_are_labelled(base_src):
    """Multiple <nav> elements must be disambiguated (WCAG 1.3.1)."""
    navs = re.findall(r"<nav\b[^>]*>", base_src)
    assert len(navs) >= 2, "expected primary + breadcrumb nav"
    for nav in navs:
        assert "aria-label=" in nav, f"unlabelled nav landmark: {nav}"


# ─── Icon-only controls (WCAG 4.1.2) ─────────────────────────────────────────


def test_every_sidebar_nav_link_has_accessible_name(base_src):
    """Collapsed sidebar hides text labels; each link needs an aria-label so it
    is never an unnamed icon-only control."""
    links = re.findall(r'<a\b[^>]*class="nav-item"[^>]*>', base_src)
    assert links, "no nav-item links found — template structure changed"
    unnamed = [a for a in links if "aria-label=" not in a]
    assert not unnamed, f"nav links missing accessible name: {unnamed}"


def test_decorative_nav_icons_are_hidden(base_src):
    """Icon glyphs adjacent to a text/aria label must not be announced twice."""
    icons = re.findall(r'<i\b[^>]*class="nav-icon"[^>]*>', base_src)
    assert icons, "no nav icons found — template structure changed"
    exposed = [i for i in icons if 'aria-hidden="true"' not in i]
    assert not exposed, f"decorative icons exposed to AT: {exposed}"


def test_icon_only_header_buttons_have_labels(base_src):
    """The sidebar toggle and notifications buttons render only an icon."""
    # Sidebar toggle
    assert re.search(r'<button[^>]*aria-label="Toggle sidebar"', base_src)
    # Notifications bell
    assert re.search(
        r'<button[^>]*id="notification-btn"[^>]*aria-label=|'
        r'<button[^>]*aria-label="Notifications"[^>]*id="notification-btn"',
        base_src,
    )


def test_sidebar_toggle_exposes_expanded_state(base_src):
    """WCAG 4.1.2 — a disclosure control should expose aria-expanded."""
    assert "aria-expanded" in base_src
    assert 'aria-controls="main-nav"' in base_src


# ─── Login page (unauthenticated entry point) ────────────────────────────────

LOGIN_HTML = REPO_ROOT / "admin" / "templates" / "pages" / "login.html"


@pytest.fixture(scope="module")
def login_src() -> str:
    return LOGIN_HTML.read_text(encoding="utf-8")


def test_login_declares_language(login_src):
    assert re.search(r"<html[^>]*\blang=", login_src)


def test_login_credential_labels_are_associated(login_src):
    """WCAG 1.3.1 / 3.3.2 — labels must be programmatically tied to inputs."""
    # Every for= must have a matching id= on an input.
    fors = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', login_src))
    ids = set(re.findall(r'<input[^>]*\bid="([^"]+)"', login_src))
    assert {"login-username", "login-password"} <= fors
    assert {"login-username", "login-password"} <= ids
    assert fors <= ids, f"labels reference missing input ids: {fors - ids}"


def test_login_password_toggle_has_accessible_name(login_src):
    """The show/hide password button is icon-only and must be named."""
    assert "aria-label" in login_src
    assert "Show password" in login_src and "Hide password" in login_src


def test_login_mfa_input_has_accessible_name(login_src):
    """The one-time-code field has no visible <label>; needs an aria-label."""
    assert re.search(
        r'<input[^>]*autocomplete="one-time-code"[^>]*aria-label=|'
        r'<input[^>]*aria-label="[^"]*"[^>]*autocomplete="one-time-code"',
        login_src,
    )


# ---------------------------------------------------------------------------
# Motion / design-system invariants (login pilot)
#
# The Bulwark motion system mandates: (a) transitions animate EXPLICIT
# properties, never the catch-all `all`/`transition-all` (avoids janky reflows);
# (b) interactive surfaces give a tactile `:active` press; (c) all non-essential
# motion is disabled under prefers-reduced-motion (WCAG 2.3.3 / 2.2.2).
# ---------------------------------------------------------------------------

def test_login_has_no_catchall_transitions(login_src):
    """Negative: the login view must not ship `transition: all` / `transition-all`."""
    assert "transition-all" not in login_src
    assert not re.search(r"transition:\s*all\b", login_src)


def test_login_uses_expo_easing_token(login_src):
    """Positive: the signature ease-out-expo curve drives the page motion."""
    assert "cubic-bezier(0.16, 1, 0.3, 1)" in login_src
    assert "--sg-ease" in login_src


def test_login_honors_reduced_motion(login_src):
    """WCAG 2.3.3 — entrance/idle animation must collapse under reduced motion."""
    assert "prefers-reduced-motion: reduce" in login_src
    # the reveal/float/aurora animations are explicitly neutralised
    assert re.search(r"prefers-reduced-motion[^}]*animation:\s*none", login_src, re.S)


def test_login_primary_cta_has_tactile_press(login_src):
    """Interactive CTA gives a scale-down press using the motion token."""
    assert re.search(r"\.sg-cta:active[^{]*{[^}]*transform:\s*scale\(", login_src)
    # and the CTA class is actually wired onto the submit buttons
    assert 'class="sg-cta' in login_src


def test_login_has_staggered_entrance(login_src):
    """Branding + card animate in via staggered reveal hooks (not a hard cut)."""
    assert "@keyframes sg-reveal" in login_src
    assert len(re.findall(r"\breveal reveal-\d", login_src)) >= 4


# ---------------------------------------------------------------------------
# Global cascade — the pilot's motion language promoted to the shared layer.
#
# The design language must live in the shared design system (input.css) and app
# shell (base.html) so EVERY authenticated view inherits it, not just the login.
# These pin: (a) reusable entrance choreography, (b) a single authoritative
# reduced-motion guard covering all app motion, (c) the shell wiring.
# ---------------------------------------------------------------------------

INPUT_CSS = REPO_ROOT / "admin" / "static" / "css" / "input.css"


@pytest.fixture(scope="module")
def input_css() -> str:
    return INPUT_CSS.read_text(encoding="utf-8")


def test_design_system_defines_reusable_entrance(input_css):
    """The reveal choreography is promoted to input.css for app-wide reuse."""
    assert "@keyframes sg-reveal" in input_css
    assert ".reveal " in input_css or ".reveal{" in input_css
    # staggered delay hooks exist
    assert len(re.findall(r"\.reveal-\d", input_css)) >= 4
    # a layout-safe page-enter for dense content regions
    assert ".sg-page-enter" in input_css


def test_design_system_uses_expo_easing_token(input_css):
    """Shared components animate on the signature ease-out-expo curve."""
    assert "cubic-bezier(0.16, 1, 0.3, 1)" in input_css
    assert "--sg-ease" in input_css


def test_design_system_has_global_reduced_motion_guard(input_css):
    """WCAG 2.3.3 — one authoritative guard neutralises ALL app motion.

    This is the accessibility fix that the shell previously lacked (pulse-live,
    shimmer, toast, sidebar transitions had no reduced-motion handling)."""
    assert "prefers-reduced-motion: reduce" in input_css
    # the guard clamps animation + transition durations globally
    guard = re.search(
        r"prefers-reduced-motion:\s*reduce\s*\)\s*{(.+?)}\s*}",
        input_css,
        re.S,
    )
    assert guard, "reduced-motion media block not found"
    body = guard.group(1)
    assert "animation-duration" in body
    assert "transition-duration" in body


def test_design_system_has_no_catchall_transitions(input_css):
    """Negative: the shared stylesheet must not animate the catch-all `all`."""
    assert not re.search(r"transition:\s*all\b", input_css)
    assert "transition-property: all" not in input_css


def test_shell_wires_page_entrance(base_src):
    """The main content region opts into the one-shot entrance animation."""
    assert re.search(r'<main[^>]*\bclass="[^"]*sg-page-enter', base_src)


def test_design_system_has_card_cascade(input_css):
    """Cards — the primary content unit — cascade in on load for a crafted,
    sequenced reveal without any per-view markup."""
    assert "@keyframes sg-card-in" in input_css
    # staggered per-nth-child delays give the sequential ripple
    delays = re.findall(r"#main-content\s+\.sg-card:nth-child\(\d+\)", input_css)
    assert len(delays) >= 4, "expected staggered card cascade delays"


def test_card_cascade_is_scoped_to_main_content(input_css):
    """Negative: the cascade must NOT animate cards in shell chrome (modals,
    command palette reuse .sg-card) — it is scoped to #main-content only."""
    cascade = re.search(
        r"@keyframes sg-card-in.+?(?=@keyframes|@media|\Z)", input_css, re.S
    )
    assert cascade, "card cascade block not found"
    block = cascade.group(0)
    # every animation binding in the cascade block is qualified by #main-content
    bindings = re.findall(r"([^{}]*)\{[^{}]*animation[^{}]*\}", block)
    assert bindings, "no animation bindings found in cascade block"
    for selector in bindings:
        assert "#main-content" in selector, (
            f"card cascade selector not scoped to #main-content: {selector!r}"
        )


def test_card_cascade_respects_reduced_motion(input_css):
    """WCAG 2.3.3 — the global guard's wildcard clamps the card cascade too."""
    guard = re.search(
        r"prefers-reduced-motion:\s*reduce\s*\)\s*{(.+?)}\s*}", input_css, re.S
    )
    assert guard, "reduced-motion media block not found"
    assert re.search(r"\*,\s*\*::before,\s*\*::after", guard.group(1))


def test_shell_backdrop_is_present(base_src):
    """The operational shell keeps a calm radial backdrop (not the vivid login
    aurora) — present but low-contrast so it never harms data legibility."""
    assert re.search(r"body::before\s*{[^}]*radial-gradient", base_src, re.S)


# ─── Semantic security palette (consistency) ─────────────────────────────────

PAGES_DIR = REPO_ROOT / "admin" / "templates" / "pages"

# The security domain has two orthogonal scales. Every view must speak this one
# language rather than hand-rolling colours per page.
VERDICTS = ("allow", "warn", "block", "redact")
SEVERITIES = ("low", "medium", "high", "critical")


def test_design_system_defines_semantic_tokens(input_css):
    """Each verdict/severity maps to a single authoritative :root token so a
    palette change propagates everywhere (badges, dots, future charts)."""
    for name in VERDICTS:
        assert f"--sg-{name}:" in input_css, f"missing verdict token --sg-{name}"
        assert f"--sg-{name}-rgb:" in input_css, f"missing --sg-{name}-rgb triplet"
    for name in SEVERITIES:
        assert f"--sg-sev-{name}:" in input_css, f"missing severity token {name}"


def test_design_system_defines_semantic_badges(input_css):
    """Token-driven badge classes exist for every verdict and severity."""
    for name in (*VERDICTS, *SEVERITIES):
        assert f".sg-badge-{name}" in input_css, f"missing .sg-badge-{name}"
    # the previously-dangling alias is now defined (was referenced, unstyled)
    assert ".sg-badge-info" in input_css


def test_semantic_badges_reference_tokens_not_hardcoded(input_css):
    """Negative: semantic badges must derive colour from the shared tokens,
    not re-hardcode hex values (which would drift out of the single source)."""
    block = re.search(r"\.sg-badge-block\s*{([^}]*)}", input_css)
    assert block and "var(--sg-block" in block.group(1)
    allow = re.search(r"\.sg-badge-allow\s*{([^}]*)}", input_css)
    assert allow and "var(--sg-allow" in allow.group(1)


def test_no_template_references_undefined_badge_class(input_css):
    """Consistency audit — every `sg-badge-<variant>` used anywhere in the page
    templates must resolve to a class defined in the design system. This is the
    regression guard for the bug where `sg-badge-info` rendered unstyled."""
    defined = set(re.findall(r"\.sg-badge-([a-z]+)\b", input_css))
    assert defined, "no sg-badge variants found in stylesheet"
    referenced: set[str] = set()
    for page in PAGES_DIR.glob("*.html"):
        referenced |= set(
            re.findall(r"sg-badge-([a-z]+)\b", page.read_text(encoding="utf-8"))
        )
    dangling = referenced - defined
    assert not dangling, f"templates reference undefined badge classes: {dangling}"


# ─── Data-state coverage (loading / empty / error) ───────────────────────────

# The key data-heavy views must never degrade to a silent blank. Each one has
# to cover the four async states so the product reads as finished, not a demo.
STATE_VIEWS = ("dashboard", "events", "iocs", "audit")


def test_design_system_defines_error_state(input_css):
    """The fourth data state needs a reusable component (was previously absent —
    views either showed a blank or a bespoke red box)."""
    for cls in (".sg-error", ".sg-error-icon", ".sg-error-title", ".sg-error-action"):
        assert cls in input_css, f"missing {cls}"
    # the error icon derives from the shared verdict token (matches block signal)
    icon = re.search(r"\.sg-error-icon\s*{([^}]*)}", input_css)
    assert icon and "var(--sg-block" in icon.group(1)


def test_key_views_cover_all_data_states():
    """Consistency audit — every key view ships loading + empty + error."""
    for name in STATE_VIEWS:
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        assert "sg-skeleton" in src, f"{name}: no loading skeleton"
        assert "sg-error" in src, f"{name}: no error state"
        assert "sg-empty" in src, f"{name}: no empty state"


def test_error_states_offer_a_retry_affordance():
    """An error with no recovery path is a dead end — each must offer retry."""
    for name in STATE_VIEWS:
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        assert "sg-error-action" in src, f"{name}: error state has no action"
        # the retry must invoke a loader, not be a decorative button
        assert re.search(r"@click=\"load\w*\(\)|@click=\"refresh\(\)", src), (
            f"{name}: retry button does not call a loader"
        )


# ─── Data table system (sg-table) ────────────────────────────────────────────

# Tables are where a security gateway is actually operated (events/audit/iocs).
# The table system must feel like a product: anchored headers on long lists,
# honest sorting, adjustable density, and keyboard-reachable controls.


def test_table_system_defines_sticky_header(input_css):
    """Long triage lists must keep column labels anchored while the body scrolls."""
    scroll = re.search(r"\.sg-table-scroll\s*{([^}]*)}", input_css)
    assert scroll and "overflow" in scroll.group(1), "no scroll container"
    sticky = re.search(r"\.sg-table-scroll thead th\s*{([^}]*)}", input_css)
    assert sticky and "position: sticky" in sticky.group(1), "header not sticky"
    # sticky header must be opaque or body rows bleed through underneath it
    assert "background:" in sticky.group(1)


def test_table_system_defines_density_and_sort(input_css):
    """Compact density + a sortable-header affordance are part of the system."""
    assert ".sg-table-compact" in input_css
    assert ".sg-th-sort" in input_css
    # the sort indicator's direction is driven by aria-sort, not a JS class swap
    assert 'th[aria-sort="descending"] .sg-th-sort-icon' in input_css


def test_sortable_headers_are_keyboard_operable(input_css):
    """Sort controls must be real buttons with a visible focus ring (WCAG 2.4.7)."""
    focus = re.search(r"\.sg-th-sort:focus-visible\s*{([^}]*)}", input_css)
    assert focus and "outline" in focus.group(1), "no focus-visible ring on sort control"


def test_events_table_uses_sticky_and_accessible_sort():
    """Events (single 100-row fetch) exposes honest, accessible column sorting."""
    src = (PAGES_DIR / "events.html").read_text(encoding="utf-8")
    assert "sg-table-scroll" in src, "events table not wrapped for sticky header"
    # sortable columns wire aria-sort + a real <button>, not a click on a bare <th>
    assert ':aria-sort="ariaSort(' in src, "no aria-sort binding"
    assert re.search(r'<button class="sg-th-sort" @click="sortBy\(', src), (
        "sort headers are not real buttons"
    )
    # rows must render through the sorted view, not the raw array
    assert 'x-for="evt in displayEvents()"' in src


def test_events_density_toggle_is_wired_and_persisted():
    """The density toggle must be a live control (persisted), not decorative."""
    src = (PAGES_DIR / "events.html").read_text(encoding="utf-8")
    assert '@click="toggleDensity()"' in src
    assert ":class=\"{ 'sg-table-compact': compact }\"" in src
    # persisted across reloads + reflects state to assistive tech
    assert "localStorage.setItem('sg-events-density'" in src
    assert ':aria-pressed=' in src


def test_paginated_tables_do_not_fake_global_sort():
    """audit/iocs page on the server; adding client sort headers there would only
    sort the visible page — a misleading control. They get sticky headers, not sort."""
    for name in ("audit", "iocs"):
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        assert "sg-table-scroll" in src, f"{name}: table not wrapped for sticky header"
        assert "sg-th-sort" not in src, (
            f"{name}: server-paginated table must not expose per-page sort headers"
        )


# ─── Management tables adopt the sg-table system ─────────────────────────────

MANAGEMENT_TABLE_VIEWS = ("plugins", "tenants", "rbac")


def test_management_tables_adopt_sticky_sg_table():
    """plugins/tenants/rbac(users+sessions) must use the shared sg-table design
    system with sticky headers — not hand-rolled or bare-scroll tables."""
    for name in MANAGEMENT_TABLE_VIEWS:
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        assert "sg-table-scroll" in src, f"{name}: table not wrapped for sticky header"
        assert 'class="sg-table' in src, f"{name}: table does not use sg-table"


def test_management_tables_drop_bespoke_table_markup():
    """No raw `w-full text-*` tables or redundant overflow-x-auto wrappers should
    survive the migration to sg-table (visual-consistency regression guard)."""
    for name in MANAGEMENT_TABLE_VIEWS:
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        assert '<table class="w-full' not in src, (
            f"{name}: bespoke table markup must be replaced by sg-table"
        )
        assert "overflow-x-auto" not in src, (
            f"{name}: overflow-x-auto is superseded by sg-table-scroll"
        )


def test_client_paginated_users_table_does_not_fake_sort():
    """rbac users are client-paginated; we deliberately ship sticky headers without
    sort controls so no header implies an ordering it does not apply globally."""
    src = (PAGES_DIR / "rbac.html").read_text(encoding="utf-8")
    assert "sg-th-sort" not in src, (
        "rbac: users table must not expose sort headers it does not honour"
    )


# ─── Visual-identity guards (avoid the "generic AI console" look) ─────────────

# Emoji / pictograph blocks — deliberately excludes the arrows block (U+2190–21FF)
# so typographic arrows like "→" in copy remain allowed.
_EMOJI = re.compile(
    "["
    "\U0001f300-\U0001faff"  # symbols, pictographs, emoticons, transport, extended-A
    "\U00002600-\U000027bf"  # misc symbols + dingbats (✓ ✗ ⚙ ✈ …)
    "\U00002b00-\U00002bff"  # misc symbols and arrows (stars, etc.)
    "\U0000fe00-\U0000fe0f"  # variation selectors (emoji presentation)
    "\U00002190-\U000021ff"  # arrows — checked separately, allowed only in text
    "]"
)


def test_templates_use_vector_icons_not_emoji():
    """Emoji rendered as UI icons are the hallmark of a generic, machine-made
    console. The admin UI ships a vendored Lucide icon set; every glyph must come
    from it. Typographic arrows (→ ←) are tolerated inside copy but nothing else."""
    offenders: list[str] = []
    allowed_arrows = {"\u2192", "\u2190", "\u2194", "\u21b5", "\u21d2"}
    for page in PAGES_DIR.glob("*.html"):
        for lineno, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            hits = [c for c in _EMOJI.findall(line) if c not in allowed_arrows]
            if hits:
                offenders.append(f"{page.name}:{lineno} {hits!r}")
    assert not offenders, "Emoji used as iconography (use Lucide instead):\n" + "\n".join(
        offenders
    )


def test_notification_channel_icons_are_lucide_names():
    """The notification channel glyphs must resolve to Lucide icon names, not the
    emoji set that previously shipped (💬 🟦 📟 …)."""
    src = (PAGES_DIR / "notifications.html").read_text(encoding="utf-8")
    assert ':data-lucide="typeIcon(' in src, (
        "notification channel icon must render via <i :data-lucide=...>, not emoji"
    )
    assert "slack: 'slack'" in src and "email: 'mail'" in src, (
        "typeIcon must map channel types to Lucide icon names"
    )


def test_discovery_scan_tabs_have_loading_and_empty_states():
    """A scan tool that renders a blank void after a zero-result scan reads as
    unfinished. Each discovery tab must show a loading skeleton while scanning and
    an empty/pre-scan state when there is nothing to display."""
    src = (PAGES_DIR / "discovery.html").read_text(encoding="utf-8")
    assert src.count("sg-empty") >= 3, "each discovery tab needs an empty/pre-scan state"
    assert 'x-show="scanning"' in src and "sg-skeleton" in src, (
        "discovery must render a loading state while a scan is in flight"
    )
    # Distinguishes 'not scanned yet' from 'scanned, nothing found'.
    for flag in ("netScanned", "shadowScanned"):
        assert flag in src, f"discovery must track {flag} to phrase its empty state"




