"""Anti-regression guards for the LOW-severity admin UI integrity fixes.

These template-level assertions lock in two honesty fixes that have no server
round-trip to unit-test directly:

1. notifications.html — ``formTypeChanged`` was a dead stub; switching channel
   type left stale type-specific values in the shared ``form`` object, which
   ``saveChannel`` then submitted wholesale. It must now clear those fields.
2. onboarding.html — the review step showed a hardcoded green "Password changed"
   badge regardless of state. It must now reflect the real wizard password state.
"""

from __future__ import annotations

from pathlib import Path

PAGES = Path(__file__).resolve().parent.parent / "admin" / "templates" / "pages"


def _read(name: str) -> str:
    return (PAGES / name).read_text(encoding="utf-8")


# ─── notifications.formTypeChanged ───────────────────────────────────────────


def test_notifications_form_type_changed_is_not_a_dead_stub():
    src = _read("notifications.html")
    # The empty placeholder stub must be gone.
    assert "/* Reset type-specific fields if needed */" not in src
    # It must actually reset the shared form's type-specific fields.
    assert "Object.assign(this.form" in src


def test_notifications_form_type_changed_clears_cross_type_fields():
    src = _read("notifications.html")
    # Narrow to the Object.assign body inside the handler definition.
    body = src.split("formTypeChanged() {", 1)[1].split("});", 1)[0]
    # A representative field from each other channel type must be cleared so it
    # is never submitted after the user switches type.
    for field in ("url:", "routing_key:", "api_key:", "bot_token:", "smtp_host:", "auth_type:"):
        assert field in body, f"formTypeChanged must reset {field}"


def test_notifications_form_type_changed_preserves_common_fields():
    src = _read("notifications.html")
    body = src.split("formTypeChanged() {", 1)[1].split("});", 1)[0]
    # Common routing/filter fields must NOT be wiped on a type change.
    for field in ("min_severity", "verdicts", "tenants_raw", "dedup_window_seconds", "name:"):
        assert field not in body, f"formTypeChanged must not touch common field {field}"


# ─── onboarding password badge ───────────────────────────────────────────────


def test_onboarding_password_badge_is_not_hardcoded_green():
    src = _read("onboarding.html")
    # The always-green fabricated badge must be gone.
    assert '<span class="sg-badge sg-badge-success">Password changed</span>' not in src


def test_onboarding_password_badge_reflects_real_state():
    src = _read("onboarding.html")
    # A getter exposes the real wizard password state and drives the badge class.
    assert "passwordConfigured" in src
    assert "passwordConfigured ? 'sg-badge-success' : 'sg-badge-neutral'" in src
    assert "passwordConfigured ? 'Password set' : 'Password not set'" in src


def test_onboarding_canproceed_reuses_password_getter():
    src = _read("onboarding.html")
    # Single source of truth: step-0 gating uses the same getter as the badge.
    step0 = src.split("if (this.currentStep === 0) {", 1)[1].split("}", 1)[0]
    assert "passwordConfigured" in step0
