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


# ─── Dashboard: no dead controls, only real telemetry ────────────────────────


def test_dashboard_has_no_dead_period_selector():
    """A period selector (1h/24h/7d/30d) that no endpoint honours is a deceptive
    control: it looks like a filter but changes nothing. It must be gone, replaced
    by a status that reflects the real SSE stream."""
    src = (PAGES_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert "period = p.value" not in src, "dead period selector must be removed"
    assert "periods:" not in src, "the fake period list must be removed from state"
    # Replaced by a genuine live-connection indicator driven by the SSE stream.
    assert "connected" in src and "Reconnecting" in src, (
        "header must show a real SSE connection state instead of a fake filter"
    )


def test_dashboard_does_not_mislabel_total_as_queue_depth():
    """The backend overwrites queue_depth_memory with total requests, so a card
    labelled 'Queue Depth' would misreport. That card must instead surface a real,
    correctly-named metric (detection rate)."""
    src = (PAGES_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert "Queue Depth" not in src, "must not label total-requests as queue depth"
    assert 'data-metric="detection_rate"' in src, "detection rate KPI must be present"


def test_dashboard_surfaces_verdict_distribution():
    """Allowed/warned/blocked counters are computed server-side but were never
    shown. The dashboard must surface the full verdict split, not just blocks."""
    src = (PAGES_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert "Verdict Distribution" in src
    for kind in ("allowed", "warned", "blocked"):
        assert f"verdicts.{kind}" in src, f"verdict distribution must show {kind}"
    assert "verdictPct(" in src, "distribution must be proportional, not raw only"


def test_dashboard_tenant_activity_uses_real_endpoint_with_states():
    """Tenant Activity must consume the real per-tenant usage endpoint and cover
    the loading / empty / error states like the other data-heavy panels."""
    src = (PAGES_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert "/admin/health/tenant-usage" in src, "must use the real tenant endpoint"
    assert "tenantsLoading" in src and "sg-skeleton" in src, "needs a loading state"
    assert "sg-empty" in src and "No tenant traffic" in src, "needs an empty state"
    assert "tenantsError" in src and "loadTenantUsage()" in src, (
        "needs an error state with a retry affordance"
    )


# ─── Policies: version history is a real panel, not a toast ───────────────────


def test_policies_version_history_opens_a_real_panel():
    """The version-history control previously only fired a toast with a count
    ('N version(s) available') — a control that implies a viewer but shows none.
    It must now open a real modal that lists the actual versions."""
    src = (PAGES_DIR / "policies.html").read_text(encoding="utf-8")
    assert "version(s) available" not in src, (
        "the deceptive count-only toast must be gone"
    )
    assert 'x-show="showVersions"' in src, "a real version-history modal must exist"
    # It renders the actual version records returned by the backend.
    assert 'x-for="(v, idx) in versions"' in src
    for field in ("v.checksum", "formatVersionTime(v)", "formatBytes(v.size)"):
        assert field in src, f"version rows must surface {field}"


def test_policies_version_history_consumes_real_endpoint_with_states():
    """The panel must fetch the real versions endpoint and cover
    loading / empty / error states like the rest of the console."""
    src = (PAGES_DIR / "policies.html").read_text(encoding="utf-8")
    assert "/versions`" in src and "loadVersions(" in src, "must fetch real versions"
    assert "versionsLoading" in src and "sg-skeleton" in src, "needs a loading state"
    assert "versionsError" in src, "needs an error state"
    # Distinguishes 'only current, no backups' from a failure.
    assert "No previous versions" in src, "needs an empty (no-backups) state"


def test_policies_restore_calls_rollback_and_is_permission_gated():
    """Restore must hit the rollback endpoint with the version key, and the
    control must be gated on the admin-only config:rollback permission rather
    than presented to roles that would only ever get a 403."""
    src = (PAGES_DIR / "policies.html").read_text(encoding="utf-8")
    assert "restoreVersion(" in src and "/rollback?version=" in src, (
        "restore must call the real rollback endpoint with the version key"
    )
    # Gated client-side (honest affordance) and still enforced server-side.
    assert "canRollback" in src and "bulwark_role" in src, (
        "restore button must be gated on the admin role"
    )
    assert 'x-if="v.version !== \'current\' && canRollback"' in src, (
        "restore must be hidden for the current version and for non-admins"
    )


# ─── Visual consistency: all data tables share the design-system table ────────


def test_all_data_tables_use_the_design_system_table_class():
    """Hand-rolled `<table class="w-full text-sm">` blocks with bespoke padding
    and border utilities were the tell of piecemeal, inconsistent styling. Every
    table must go through the shared `.sg-table` component so density, hover,
    borders and sticky headers stay uniform across the console."""
    offenders = []
    for page in PAGES_DIR.glob("*.html"):
        for tag in re.findall(r"<table\b[^>]*>", page.read_text(encoding="utf-8")):
            if "sg-table" not in tag:
                offenders.append(f"{page.name}: {tag}")
    assert not offenders, "raw tables must adopt .sg-table:\n" + "\n".join(offenders)


# ─── Icon-only controls carry an accessible name (WCAG 4.1.2) ────────────────

# A <button> or <a> whose ONLY child is a single Lucide icon (no text, no
# x-text) is invisible to screen readers unless it carries an accessible name.
# This regex matches exactly that shape so the guard is exhaustive across every
# page — it catches new unlabelled icon buttons the moment they are added.
_ICON_ONLY_CONTROL = re.compile(
    r"<(?P<tag>button|a)(?P<attrs>[^>]*)>\s*"
    r"<i\b[^>]*?:?data-lucide[^>]*>\s*</i>\s*"
    r"</(?P=tag)>",
    re.DOTALL,
)


def _has_accessible_name(attrs: str) -> bool:
    # aria-label / :aria-label (dynamic) / title / aria-labelledby all provide a name.
    return bool(re.search(r'(?::?aria-label|title|aria-labelledby)\s*=', attrs))


def test_all_icon_only_controls_have_accessible_names():
    """WCAG 4.1.2 — every icon-only button/link across the admin pages (and the
    shared shell) must expose an accessible name. Regression guard for the sweep
    that labelled modal-close, refresh, and row-action icon buttons."""
    offenders: list[str] = []
    targets = list(PAGES_DIR.glob("*.html")) + [BASE_HTML]
    for page in targets:
        src = page.read_text(encoding="utf-8")
        for m in _ICON_ONLY_CONTROL.finditer(src):
            if not _has_accessible_name(m.group("attrs")):
                lineno = src.count("\n", 0, m.start()) + 1
                snippet = re.sub(r"\s+", " ", m.group(0))[:100]
                offenders.append(f"{page.name}:{lineno} {snippet}")
    assert not offenders, (
        "Icon-only controls missing an accessible name (add aria-label/title):\n"
        + "\n".join(offenders)
    )


# ─── Interactive non-button elements are keyboard operable (WCAG 2.1.1) ───────


def test_interactive_divs_are_keyboard_operable():
    """A <div> that activates behaviour on @click must also be reachable and
    operable by keyboard (role=button + tabindex + a key handler). Guards the
    two enhancement widgets that are not native buttons: the evaluation result
    row and the plugin upload dropzone."""
    cases = [
        ("evaluation.html", "expandedRow = expandedRow === idx"),
        ("plugins.html", "$refs.fileInput.click()"),
    ]
    for page, action in cases:
        src = (PAGES_DIR / page).read_text(encoding="utf-8")
        # locate the interactive div block that owns the @click action
        m = re.search(r"<div\b[^>]*@click=\"[^\"]*"
                      + re.escape(action) + r"[^\"]*\"[^>]*>", src, re.DOTALL)
        assert m, f"{page}: interactive div for {action!r} not found"
        block = m.group(0)
        assert 'role="button"' in block, f"{page}: interactive div needs role=button"
        assert 'tabindex="0"' in block, f"{page}: interactive div needs tabindex=0"
        assert "@keydown.enter" in block, f"{page}: interactive div needs an enter handler"


def test_profile_chip_has_single_canonical_control():
    """The sidebar profile chip previously carried three redundant open-profile
    affordances (clickable avatar div, clickable name div, gear button). The two
    non-semantic clickable divs are removed; the labelled gear button is the one
    keyboard-accessible control."""
    src = BASE_HTML.read_text(encoding="utf-8")
    # the avatar/name text is presentational now — no click handlers on those divs
    assert 'flex-1 min-w-0 cursor-pointer' not in src, (
        "profile name div must not be a non-semantic clickable"
    )
    # the real control remains: a labelled icon button
    assert re.search(
        r'<button[^>]*@click="showProfile = true; loadProfile\(\)"[^>]*title="Profile Settings"',
        src,
    ), "the canonical profile button must remain"


# ─── Live-filter controls carry an accessible name (WCAG 1.3.1 / 4.1.2) ───────

# Toolbar filters and search boxes reload data on change/input via a loader.
# They sit in filter bars with no adjacent field label, so — unlike modal form
# fields — a screen reader has nothing to announce unless the control itself
# carries a name (aria-label) or is wired to a <label for=…>. This guard matches
# exactly that "live filter" shape so new unlabelled filters are caught on sight.
_LIVE_FILTER_CONTROL = re.compile(
    r"<(?:select|input|textarea)\b[^>]*"
    r'@(?:change|input)(?:\.[a-z0-9.]+)?="[^"]*'
    r"(?:load\w*|applyFilters|page\s*=)\s*\("
    r"[^>]*>",
    re.IGNORECASE,
)


def _control_is_named(tag: str, for_ids: set[str]) -> bool:
    # A direct name wins; otherwise the control's id must be a <label for=…> target.
    if re.search(r"(?::?aria-label|aria-labelledby|title)\s*=", tag):
        return True
    cid = re.search(r'\bid="([^"]+)"', tag)
    return bool(cid and cid.group(1) in for_ids)


def test_live_filter_controls_have_accessible_names():
    """WCAG 1.3.1/4.1.2 — every data-reloading filter/search control across the
    admin pages must expose an accessible name, either directly (aria-label) or
    via a programmatically associated <label for=…>. Regression guard for the
    sweep that named the tenant/severity/type/search filters."""
    offenders: list[str] = []
    for page in list(PAGES_DIR.glob("*.html")) + [BASE_HTML]:
        src = page.read_text(encoding="utf-8")
        for_ids = set(re.findall(r'for="([^"]+)"', src))
        for m in _LIVE_FILTER_CONTROL.finditer(src):
            if not _control_is_named(m.group(0), for_ids):
                lineno = src.count("\n", 0, m.start()) + 1
                snippet = re.sub(r"\s+", " ", m.group(0))[:100]
                offenders.append(f"{page.name}:{lineno} {snippet}")
    assert not offenders, (
        "Live-filter controls missing an accessible name "
        "(add aria-label or a <label for=…>):\n" + "\n".join(offenders)
    )


# ─── Visible field labels are programmatically associated (WCAG 1.3.1) ────────

# A modal form field whose label is a plain <label>TEXT</label> sitting next to
# the control is a visual-only association: screen readers do not connect them
# unless the label carries for=… pointing at the control's id (or the control
# carries its own aria-label). This guard matches every "label then bare
# control" pair across all pages + the shell and asserts the pairing is real.
_LABEL_RE = re.compile(r"<label\b(?P<attrs>[^>]*)>(?P<body>.*?)</label>", re.DOTALL)
_LEAD_SKIP = re.compile(r"\s*(?:<!--.*?-->\s*)*", re.DOTALL)
_CTRL_OPEN = re.compile(r"<(?P<tag>input|select|textarea)\b(?P<attrs>[^>]*?)>", re.DOTALL)


def test_field_labels_are_programmatically_associated():
    """WCAG 1.3.1 — every visible <label> immediately followed by a form control
    must be wired to it (for=… ↔ id, or a dynamic :for, or the control owns an
    aria-label). Regression guard for the sweep that associated ~146 modal
    fields across the admin UI."""
    offenders: list[str] = []
    for page in list(PAGES_DIR.glob("*.html")) + [BASE_HTML]:
        src = page.read_text(encoding="utf-8")
        ids = set(re.findall(r'\bid="([^"]+)"', src))
        for m in _LABEL_RE.finditer(src):
            attrs, body = m.group("attrs"), m.group("body")
            # dynamic labels wire themselves with :for / x-text bound ids
            if "x-text" in attrs or ":for" in attrs:
                continue
            if not re.sub(r"<[^>]+>", " ", body).strip():
                continue  # empty/icon-only label, nothing to associate
            j = _LEAD_SKIP.match(src, m.end()).end()
            cm = _CTRL_OPEN.match(src, j)
            if not cm:
                continue  # label is a section heading, not a field label
            catt = cm.group("attrs")
            typ = (re.search(r'type="([^"]+)"', catt) or [None, "text"])[1]
            if typ in ("checkbox", "radio", "hidden"):
                continue  # wrapping-label / toggle patterns handled elsewhere
            form = re.search(r'\bfor="([^"]+)"', attrs)
            named = (
                (form and form.group(1) in ids)
                or "aria-label" in catt
                or ":id" in catt
            )
            if not named:
                lineno = src.count("\n", 0, m.start()) + 1
                label_txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
                offenders.append(f"{page.name}:{lineno} label={label_txt!r}")
    assert not offenders, (
        "Visible field labels not associated with their control "
        "(add for=…/id or aria-label):\n" + "\n".join(offenders)
    )


# ─── Pointer/touch target sizing (WCAG 2.5.5 / 2.5.8) ─────────────────────────

# The admin UI is deliberately dense (input.css documents a 24px AA floor for
# row/toolbar actions rather than a blanket 44px, which would wreck the density
# pillar). Two invariants keep that honest: (1) every button *size* class the
# templates use is actually defined — `sg-btn-xs` was referenced in 11 places
# while undefined, so those buttons silently fell back to the 38px base; and
# (2) isolated icon actions (modal close) get a real 44px pointer target via an
# invisible ::after overlay, without inflating the visible glyph.

TAILWIND_CSS = REPO_ROOT / "admin" / "static" / "css" / "tailwind.min.css"

# WCAG 2.5.8 (AA) minimum target size; input.css treats this as the dense floor.
_AA_TARGET_FLOOR_PX = 24
# WCAG 2.5.5 (AAA) enhanced target size for standalone actions.
_AAA_TARGET_PX = 44


@pytest.fixture(scope="module")
def served_css() -> str:
    """The single minified stylesheet actually shipped to the browser (guarded
    by SRI). Design-system rules live in input.css but must be mirrored here or
    they never reach a user — this fixture lets tests assert the served copy."""
    return TAILWIND_CSS.read_text(encoding="utf-8")


def _min_height_px(css: str, cls: str) -> int | None:
    """Return the min-height (px) declared for a `.cls` rule, if any. Tolerant
    of both the pretty source and the minified served form."""
    m = re.search(rf"\.{re.escape(cls)}\s*{{([^}}]*)}}", css)
    if not m:
        return None
    h = re.search(r"min-height:\s*(\d+)px", m.group(1))
    return int(h.group(1)) if h else None


def test_button_size_classes_meet_aa_target_floor(input_css):
    """WCAG 2.5.8 — the dense button sizes must still clear the 24px AA floor
    that input.css documents. Guards against a future 'shrink it more' edit."""
    for cls in ("sg-btn-xs", "sg-btn-sm"):
        h = _min_height_px(input_css, cls)
        assert h is not None, f".{cls} must declare an explicit min-height"
        assert h >= _AA_TARGET_FLOOR_PX, (
            f".{cls} min-height {h}px is below the {_AA_TARGET_FLOOR_PX}px AA floor"
        )


def test_no_template_references_undefined_button_size(input_css):
    """Consistency audit — every `sg-btn-<variant>` used in the templates must
    resolve to a defined class. Direct regression guard for `sg-btn-xs`, which
    was referenced in 11 places while undefined (buttons fell back to base)."""
    defined = set(re.findall(r"\.sg-btn-([a-z]+)\b", input_css))
    assert defined, "no sg-btn variants found in stylesheet"
    referenced: set[str] = set()
    for page in list(PAGES_DIR.glob("*.html")) + [BASE_HTML]:
        referenced |= set(
            re.findall(r"\bsg-btn-([a-z]+)\b", page.read_text(encoding="utf-8"))
        )
    dangling = referenced - defined
    assert not dangling, f"templates reference undefined button classes: {dangling}"


def test_icon_button_expands_pointer_target_via_overlay(input_css):
    """WCAG 2.5.5 — `.sg-icon-btn` keeps a compact glyph for density but must
    expand the actual pointer/touch target to ≥44px through a positioned
    ::after overlay. Assert the mechanism (relative host + negative inset ≥8px)
    rather than a computed pixel size we can't derive from CSS alone."""
    host = re.search(r"\.sg-icon-btn\s*{([^}]*)}", input_css)
    assert host, ".sg-icon-btn must be defined"
    assert "position: relative" in host.group(1) or "position:relative" in host.group(1), (
        ".sg-icon-btn must be a positioned host so its ::after overlay anchors to it"
    )
    overlay = re.search(r"\.sg-icon-btn::after\s*{([^}]*)}", input_css)
    assert overlay, ".sg-icon-btn needs an ::after overlay to enlarge the hit area"
    body = overlay.group(1)
    assert "position: absolute" in body or "position:absolute" in body
    inset = re.search(r"inset:\s*-(\d+)px", body)
    assert inset and int(inset.group(1)) >= 8, (
        "::after must extend the target by ≥8px on each side "
        f"(6px padding + ~20px glyph + 2×8px ≈ 48px ≥ {_AAA_TARGET_PX}px)"
    )


def test_served_css_mirrors_touch_target_rules(served_css):
    """The touch-target work is only real if it ships: the minified stylesheet
    that carries the SRI hash must contain both the resurrected `sg-btn-xs`
    size and the `sg-icon-btn` overlay, not just the source input.css."""
    assert _min_height_px(served_css, "sg-btn-xs") is not None, (
        "served tailwind.min.css is missing .sg-btn-xs — rebuild the CSS"
    )
    assert re.search(r"\.sg-icon-btn::after\{[^}]*inset:-\d+px", served_css), (
        "served tailwind.min.css is missing the .sg-icon-btn overlay — rebuild"
    )


def test_isolated_modal_close_buttons_adopt_icon_button():
    """Adoption guard — the standalone modal-close buttons that were converted
    to the 44px `sg-icon-btn` target must keep using it (not regress to a bare
    `p-1.5` tap area). Scoped to the dialogs touched in the touch-target pass."""
    for name in ("guardrails", "policies"):
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        closes = re.findall(r'<button[^>]*aria-label="Close dialog"[^>]*>', src)
        assert closes, f"{name}.html should have labelled modal-close buttons"
        for btn in closes:
            assert "sg-icon-btn" in btn, (
                f"{name}.html modal-close must use sg-icon-btn for a 44px target: {btn[:80]}"
            )


# ─── Motion consistency: no catch-all `transition-all` in templates ───────────

# `transition-all` is a double footgun: it animates *every* property that ever
# changes (including geometry → reflow, and any property added later) on
# Tailwind's default curve instead of the design easing token. Every prior use
# was replaced by one of two intent-revealing helpers — `.sg-interactive`
# (paint-only hover/selection) or `.sg-meter-fill` (data-bound bar geometry on
# the poll cadence). These guards keep the anti-pattern from creeping back.

_CATCHALL_CLASS = re.compile(r"\btransition-all\b")
_CATCHALL_STYLE = re.compile(r"transition:\s*all\b")


def test_no_page_template_uses_catchall_transition():
    """No admin page or the shell may use `transition-all` / `transition: all`.
    Regression guard for the sweep that moved 21 uses onto explicit helpers."""
    offenders: list[str] = []
    for page in list(PAGES_DIR.glob("*.html")) + [BASE_HTML]:
        src = page.read_text(encoding="utf-8")
        for pat in (_CATCHALL_CLASS, _CATCHALL_STYLE):
            for m in pat.finditer(src):
                lineno = src.count("\n", 0, m.start()) + 1
                offenders.append(f"{page.name}:{lineno}")
    assert not offenders, (
        "Catch-all transitions found (use .sg-interactive or .sg-meter-fill):\n"
        + "\n".join(offenders)
    )


def test_motion_helpers_are_token_driven(input_css):
    """Both replacement helpers must exist, animate an EXPLICIT property list
    (never `all`), and use the shared easing token — so motion stays uniform."""
    for cls in ("sg-interactive", "sg-meter-fill"):
        m = re.search(rf"\.{cls}\s*{{([^}}]*)}}", input_css)
        assert m, f".{cls} must be defined in the design system"
        body = m.group(1)
        assert "transition-property:" in body, f".{cls} must list its properties"
        assert "all" not in re.search(
            r"transition-property:\s*([^;]+)", body
        ).group(1), f".{cls} must not animate the catch-all `all`"
        assert "var(--sg-ease)" in body, f".{cls} must use the --sg-ease token"


def test_meter_fill_uses_dedicated_duration_token(input_css):
    """The data-viz cadence is its own named token (defined in :root), distinct
    from the 180ms pointer-feedback duration — not a magic number."""
    assert re.search(r"--sg-dur-slow:\s*\d+", input_css), (
        ":root must define the --sg-dur-slow data-viz duration token"
    )
    fill = re.search(r"\.sg-meter-fill\s*{([^}]*)}", input_css)
    assert fill and "var(--sg-dur-slow)" in fill.group(1), (
        ".sg-meter-fill must consume the --sg-dur-slow token"
    )
    props = re.search(r"transition-property:\s*([^;]+)", fill.group(1)).group(1)
    assert "width" in props and "height" in props, (
        ".sg-meter-fill must transition its data-bound geometry"
    )


def test_served_css_mirrors_motion_helpers(served_css):
    """The helpers must ship in the SRI-guarded minified stylesheet, including
    the new duration token — otherwise the templates reference dead classes."""
    assert "--sg-dur-slow:" in served_css, "served CSS missing --sg-dur-slow token"
    for cls in (".sg-interactive", ".sg-meter-fill"):
        assert re.search(
            re.escape(cls) + r"\{[^}]*transition-property[^}]*var\(--sg-ease\)",
            served_css,
        ), f"served tailwind.min.css missing {cls} — rebuild the CSS"


# ─── Modal viewport anchoring: teleport to <body> (containing-block safety) ───

# A `position: fixed` overlay only anchors to the viewport if no ancestor
# establishes a containing block (transform / filter / contain / will-change /
# perspective). Rather than police every possible ancestor of every page
# forever, page-level modals are teleported to <body> so they escape the page
# subtree entirely — the same reason the shell modals (command palette, profile
# drawer) never suffered the mis-position bug. These guards keep new modals from
# regressing to in-tree overlays.

_MODAL_PAGES = {"policies": 2, "guardrails": 2, "notifications": 1}
_TELEPORT = '<template x-teleport="body">'
# Outer modal overlay: a fixed full-bleed layer that owns the z-50 stacking
# context (the separate `bg-black/60` backdrop divs carry no z-50 → excluded).
_MODAL_OVERLAY = re.compile(
    r'<div[^>]*\bclass="[^"]*\bfixed inset-0\b[^"]*\bz-50\b[^"]*"[^>]*>'
)


def test_page_modals_are_teleported_to_body():
    """Every page-level modal overlay must sit inside a
    `<template x-teleport="body">` so its `fixed inset-0` layer anchors to the
    viewport regardless of any transformed/contained ancestor in the page."""
    for name, expected in _MODAL_PAGES.items():
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        assert src.count(_TELEPORT) == expected, (
            f"{name}.html should teleport exactly {expected} modal(s) to <body>, "
            f"found {src.count(_TELEPORT)}"
        )
        overlays = list(_MODAL_OVERLAY.finditer(src))
        assert len(overlays) == expected, (
            f"{name}.html expected {expected} z-50 modal overlay(s), "
            f"found {len(overlays)}"
        )
        for m in overlays:
            head = src[: m.start()].rstrip()
            assert head.endswith(_TELEPORT), (
                f"{name}.html modal overlay is not wrapped in x-teleport=body: "
                f"...{head[-80:]!r}"
            )


def test_no_page_modal_relies_on_removed_x_if_wrapper():
    """Negative guard — the notifications modal was converted from an in-tree
    `<template x-if>` to a teleported `x-show`; no page modal overlay may sit
    directly inside an `x-if` template (which keeps it in the page subtree)."""
    for name in _MODAL_PAGES:
        src = (PAGES_DIR / f"{name}.html").read_text(encoding="utf-8")
        # An x-if template immediately wrapping a fixed inset-0 z-50 overlay is
        # the in-tree pattern we replaced.
        assert not re.search(
            r'<template\s+x-if="[^"]*"\s*>\s*<div[^>]*\bfixed inset-0\b[^>]*\bz-50\b',
            src,
        ), f"{name}.html still wraps a modal overlay in an in-tree x-if template"


# ─── Entrance keyframes must rest at `none` (fixed containing-block safety) ────

# A resting keyframe that holds a non-`none` transform (translateY(0), scale(1))
# OR a non-`none` filter (blur(0)) — pinned by animation-fill-mode: both —
# permanently turns the element into the containing block for `position: fixed`
# descendants. The author documented this on sg-page-settle; sg-reveal and
# sg-card-in must obey the same rule so a modal nested under `.reveal`/`.sg-card`
# can never be trapped. `none` is visually identical to translateY(0)/scale(1).


def _keyframe_rest(css: str, name: str) -> str | None:
    """Return the `to`/`100%` resting block of a named @keyframes. Isolates the
    keyframe body by brace-matching first, so it works on both pretty (with
    comments) and minified CSS and never bleeds into an adjacent keyframe."""
    idx = css.find("@keyframes " + name)
    if idx < 0:
        return None
    open_brace = css.find("{", idx)
    if open_brace < 0:
        return None
    depth = 0
    end = None
    for i in range(open_brace, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return None
    body = css[open_brace : end + 1]
    m = re.search(r"\b(?:to|100%)\s*{([^}]*)}", body)
    return m.group(1) if m else None


def test_entrance_keyframes_are_containing_block_safe(input_css):
    """sg-reveal and sg-card-in must rest at `transform: none` (never
    translateY(0)/scale(1)) so they never establish a fixed containing block."""
    for name in ("sg-reveal", "sg-card-in"):
        rest = _keyframe_rest(input_css, name)
        assert rest is not None, f"{name} keyframe missing a resting frame"
        assert "transform: none" in rest, (
            f"{name} must rest at `transform: none` (input.css)"
        )
        assert "translateY(0)" not in rest and "scale(1)" not in rest, (
            f"{name} resting frame must not hold a non-none transform"
        )
    reveal = _keyframe_rest(input_css, "sg-reveal")
    assert "filter: none" in reveal and "blur(" not in reveal, (
        "sg-reveal must rest at `filter: none` — a non-none filter also "
        "creates a containing block for fixed descendants"
    )


def test_served_css_entrance_keyframes_are_containing_block_safe(served_css):
    """The containing-block-safe keyframes must ship in the SRI-guarded minified
    stylesheet, not just the source input.css."""
    for name in ("sg-reveal", "sg-card-in"):
        rest = _keyframe_rest(served_css, name)
        assert rest is not None, f"served CSS missing {name} keyframe — rebuild"
        assert "transform:none" in rest, (
            f"{name} must rest at `transform:none` in served CSS"
        )
        assert "translateY(0)" not in rest and "scale(1)" not in rest, (
            f"{name} served resting frame must not hold a non-none transform"
        )
    reveal = _keyframe_rest(served_css, "sg-reveal")
    assert "filter:none" in reveal and "blur(" not in reveal, (
        "served sg-reveal must rest at `filter:none`"
    )


# ─── Motion tokenisation (Fase 2) ────────────────────────────────────────────
#
# Every appear/dismiss animation must flow through the design-system tokens
# (--sg-dur, --sg-ease) so the whole product shares ONE curve and ONE duration.
# Before this pass the templates carried a spread of ad-hoc Tailwind utilities
# (`transition duration-150/200 ease-in/ease-out`) that produced three easings
# and two durations — a genuine "generic AI UI" tell. The `.sg-trans` helper
# replaces them; these guards keep the regression from creeping back.

# Alpine x-transition attributes carry the motion utilities. We only inspect the
# *class-string* forms (`x-transition:enter="…"`), never the ambient CSS loops
# (pulse-live / float) which are intentional, symmetric, opacity/transform-only
# keyframes and are covered by their own reduced-motion guard.
_X_TRANSITION_ATTR = re.compile(r'x-transition[:\.][a-z-]*(?:=\s*"([^"]*)")?')


def _motion_templates() -> list[Path]:
    return list(PAGES_DIR.glob("*.html")) + [BASE_HTML]


def test_sg_trans_helper_is_token_driven(input_css):
    """`.sg-trans` must be defined once, purely from tokens, animating only the
    two compositor-friendly properties (opacity + transform) — never `all`."""
    m = re.search(r"\.sg-trans\s*{([^}]*)}", input_css)
    assert m, ".sg-trans helper missing from input.css"
    body = m.group(1)
    assert "transition-property: opacity, transform" in body, (
        ".sg-trans must animate only opacity + transform (no reflow, no `all`)"
    )
    assert "all" not in body, ".sg-trans must never use `transition-property: all`"
    assert "var(--sg-dur)" in body, ".sg-trans duration must be token-driven"
    assert "var(--sg-ease)" in body, ".sg-trans easing must be token-driven"
    # No hard-coded ms/s literals or literal easing curves leaking past the token.
    assert "cubic-bezier(" not in body, ".sg-trans must reference --sg-ease, not a literal curve"
    assert not re.search(r"\b\d+m?s\b", body), ".sg-trans must not hard-code a duration"


def test_served_sg_trans_helper_is_token_driven(served_css):
    """The token-driven helper must ship in the SRI-guarded minified stylesheet,
    not just the source — otherwise the deployed image diverges from intent."""
    m = re.search(r"\.sg-trans{([^}]*)}", served_css)
    assert m, ".sg-trans helper missing from served tailwind.min.css — rebuild"
    body = m.group(1)
    assert "transition-property:opacity,transform" in body, (
        "served .sg-trans must animate only opacity + transform"
    )
    assert "var(--sg-dur)" in body and "var(--sg-ease)" in body, (
        "served .sg-trans must be token-driven"
    )


def test_alpine_x_transitions_use_sg_trans_not_ad_hoc_utilities():
    """No Alpine `x-transition` may carry ad-hoc Tailwind timing utilities
    (`duration-N`, `ease-in/out/linear`, a bare `transition` class) or a
    `.duration.*` modifier — they must delegate to the `.sg-trans` helper."""
    offenders: list[str] = []
    for page in _motion_templates():
        src = page.read_text(encoding="utf-8")
        for m in _X_TRANSITION_ATTR.finditer(src):
            full = m.group(0)
            # `.duration.200ms` style modifier bypasses the token entirely.
            if ".duration" in full:
                offenders.append(f"{page.name}: {full}")
            classes = (m.group(1) or "").split()
            if any(
                c == "transition"
                or c.startswith("duration-")
                or re.fullmatch(r"ease-(in|out|linear|in-out)", c)
                for c in classes
            ):
                offenders.append(f"{page.name}: {full}")
    assert not offenders, (
        "x-transition still uses ad-hoc timing utilities instead of `sg-trans`:\n"
        + "\n".join(offenders)
    )


def test_no_ad_hoc_duration_utilities_in_templates():
    """Belt-and-braces: the `duration-N` Tailwind utility must not appear
    anywhere in the templates (it is the fingerprint of un-tokenised motion)."""
    offenders: list[str] = []
    for page in _motion_templates():
        src = page.read_text(encoding="utf-8")
        for lineno, line in enumerate(src.splitlines(), 1):
            if re.search(r"\bduration-\d", line):
                offenders.append(f"{page.name}:{lineno}: {line.strip()}")
    assert not offenders, "ad-hoc `duration-N` utilities remain:\n" + "\n".join(offenders)


def test_base_html_inline_transitions_are_tokenized(base_src):
    """The shared shell's inline CSS (skip-link, sidebar, toast, content wrapper)
    must express its transitions through the motion tokens — no literal
    `cubic-bezier(...)` curve and no bespoke transition timing."""
    assert "cubic-bezier(" not in base_src, (
        "base.html must reference --sg-ease, never inline a literal easing curve"
    )
    # The four shell transitions we tokenised must still be token-driven.
    for needle in (
        "transition: top var(--sg-dur) var(--sg-ease)",          # skip-link
        "transition: width var(--sg-dur) var(--sg-ease)",        # sidebar
        "slide-in-right var(--sg-dur-slow) var(--sg-ease)",      # toast
        "transition: margin-left var(--sg-dur) var(--sg-ease)",  # content wrapper
    ):
        assert needle in base_src, f"shell transition lost its tokens: {needle!r}"


# ─── Functional integrity — no dead/deceptive controls (Fase 3) ──────────────
#
# A control that *looks* interactive but does nothing is a deceptive UI tell the
# product forbids. These guards pin the two functional defects fixed in Fase 3.

EVAL_HTML = PAGES_DIR / "evaluation.html"


def test_notification_bell_is_wired_to_a_handler(base_src):
    """The top-bar notification bell must invoke a real handler (not be a dead
    button). Previously it had an aria-label but no @click and a badge that was
    permanently `hidden` with no data source."""
    # The button must carry a click handler.
    btn = re.search(r'<button[^>]*id="notification-btn"[^>]*>', base_src)
    assert btn, "notification-btn button missing"
    assert "@click" in btn.group(0), (
        "notification bell must have an @click handler — it was a dead control"
    )
    # The appShell component must define the wiring.
    for token in ("toggleNotifications", "loadNotifications", "notifBlocks"):
        assert token in base_src, f"notification wiring missing: {token}"


def test_notification_badge_is_data_driven_not_permanently_hidden(base_src):
    """The red badge must be bound to real data (recent-blocks count), not a
    static `class=\"hidden\"` that nothing ever toggles."""
    assert 'id="notification-badge"' in base_src, "notification-badge missing"
    assert 'x-show="notifBlocks.length > 0"' in base_src, (
        "badge visibility must be driven by notifBlocks length"
    )
    # It must no longer ship the dead permanent `hidden` utility class.
    assert "hidden absolute top-1.5" not in base_src, (
        "badge must not be permanently hidden with no data source"
    )


def test_notifications_use_real_recent_blocks_endpoint(base_src):
    """The dropdown must pull from the real Redis-backed endpoint, not fabricate
    entries."""
    assert "/admin/health/recent-blocks" in base_src, (
        "notifications must fetch real data from /admin/health/recent-blocks"
    )


def test_evaluation_log_filter_actually_filters():
    """The Execution-Log filter must resolve `logFilter` from the scope that owns
    it. `filteredLog` previously read `this.logFilter` from the OUTER component
    while `logFilter` lived in a NESTED x-data, so it was always undefined and
    the Blocked/Missed buttons never filtered. The method must take the filter as
    an argument and the template must pass the in-scope `logFilter`."""
    src = EVAL_HTML.read_text(encoding="utf-8")
    assert "filteredLog(logFilter)" in src, (
        "template must pass the in-scope logFilter into filteredLog()"
    )
    # Negative: the method must not read logFilter off the wrong (outer) `this`.
    assert "this.logFilter" not in src, (
        "filteredLog must not read this.logFilter (wrong scope) — take a param"
    )
    # The parameter-driven branches must exist.
    assert re.search(r"filteredLog\(\s*filter\s*\)", src), (
        "filteredLog must accept a `filter` parameter"
    )


# ─── Load/error states — failures must not masquerade as empty (Fase 3) ──────
#
# When an async fetch fails, a page that silently shows its empty state tells the
# operator "nothing here" when the truth is "the API is down". Each data page
# must distinguish a genuine empty result from a load failure and offer a retry.

@pytest.mark.parametrize(
    "page,error_var,retry_call",
    [
        ("tenants.html", "loadError", "init()"),
        ("siem.html", "loadError", "init()"),
        ("notifications.html", "loadError", "loadChannels()"),
        ("plugins.html", "loadError", "loadPlugins()"),
        ("rbac.html", "usersError", "loadUsers()"),
    ],
)
def test_async_pages_distinguish_error_from_empty(page, error_var, retry_call):
    src = (PAGES_DIR / page).read_text(encoding="utf-8")
    # A dedicated error flag must exist and be reset/populated in the loader.
    assert error_var in src, f"{page} must track a load-error flag ({error_var})"
    # There must be a retry affordance wired to re-run the fetch.
    assert f'@click="{retry_call}"' in src, (
        f"{page} error state must offer a Retry that calls {retry_call}"
    )
    # The empty state must be suppressed while an error is showing, otherwise the
    # failure still reads as "nothing configured".
    assert re.search(rf"!\s*{error_var}", src), (
        f"{page} empty state must be gated on !{error_var}"
    )


def test_icon_only_times_close_buttons_have_accessible_name():
    """Every bare `×` close button must carry an accessible name; an unnamed
    icon-only control is invisible to assistive tech (WCAG 4.1.2)."""
    offenders: list[str] = []
    for page in PAGES_DIR.glob("*.html"):
        src = page.read_text(encoding="utf-8")
        for m in re.finditer(r"<button\b([^>]*)>\s*&times;", src):
            attrs = m.group(1)
            if "aria-label=" not in attrs:
                offenders.append(f"{page.name}: <button{attrs}>&times;")
    assert not offenders, (
        "bare × close buttons without aria-label:\n" + "\n".join(offenders)
    )


def test_guardrail_module_toggles_expose_switch_semantics():
    """The guardrail on/off switches are icon-only buttons; without ARIA switch
    semantics a screen reader announces an empty, stateless button."""
    src = (PAGES_DIR / "guardrails.html").read_text(encoding="utf-8")
    toggles = re.findall(r'<button[^>]*class="sg-toggle"[^>]*>', src)
    assert toggles, "no sg-toggle buttons found — structure changed"
    for t in toggles:
        assert 'role="switch"' in t, f"toggle missing role=switch: {t}"
        assert ":aria-checked=" in t, f"toggle missing :aria-checked: {t}"
        assert "aria-label=" in t, f"toggle missing aria-label: {t}"


def test_guardrail_row_actions_reveal_on_keyboard_focus():
    """Row actions hidden with group-hover must also reveal on keyboard focus,
    or they are unreachable without a mouse."""
    src = (PAGES_DIR / "guardrails.html").read_text(encoding="utf-8")
    assert "group-hover:opacity-100" in src
    assert "group-focus-within:opacity-100" in src, (
        "hover-revealed row actions must also reveal on group-focus-within"
    )


def test_skills_history_row_is_keyboard_operable():
    """A clickable table row must be reachable and activatable by keyboard."""
    src = (PAGES_DIR / "skills.html").read_text(encoding="utf-8")
    row = re.search(r'<tr class="cursor-pointer[^>]*@click="viewScan[^>]*>', src)
    assert row, "clickable scan-history row not found"
    tag = row.group(0)
    assert 'tabindex="0"' in tag, "clickable row must be focusable (tabindex=0)"
    assert 'role="button"' in tag, "clickable row must expose role=button"
    assert "@keydown.enter" in tag and "@keydown.space" in tag, (
        "clickable row must activate on Enter/Space"
    )


def test_dashboard_fp_rate_meter_is_data_bound():
    """The False-Positive-Rate meter bar binds to `fpRate`; that variable must be
    assigned from the live SSE payload, otherwise the bar is permanently 0."""
    src = (PAGES_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert "this.fpRate = data.false_positive_rate" in src, (
        "fpRate must be assigned from data.false_positive_rate in updateMetrics"
    )


