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

