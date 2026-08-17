"""Regression guard: mutating admin controls must honour the server response.

A recurring class of defect in the admin UI was the "fire-and-forget" handler:
a button POSTs/PUTs to the backend, then unconditionally mutates local state and
toasts success — even when the request failed. The operator is then shown a lie
(pattern saved, policy toggled, password changed) while the server rejected it.

The correct in-repo pattern (siem.html toggleTransport, guardrails toggleModule)
is: check ``resp.ok``, apply the server's *authoritative* returned state, and
revert + error-toast on failure.

These tests assert the previously-defective handlers keep doing that, by reading
the template source. They fail if anyone regresses to the optimistic pattern.
"""

from __future__ import annotations

import re
from pathlib import Path

_PAGES = Path(__file__).resolve().parent.parent / "admin" / "templates" / "pages"


def _read(name: str) -> str:
    return (_PAGES / name).read_text(encoding="utf-8")


def _handler(src: str, name: str) -> str:
    """Return the body of an Alpine method ``name(...) { ... }`` (brace-matched)."""
    m = re.search(rf"\b{name}\s*\([^)]*\)\s*\{{", src)
    assert m, f"handler {name} not found"
    i = m.end() - 1
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise AssertionError(f"unbalanced braces in {name}")


# --- guardrails.html ---------------------------------------------------------


def test_guardrails_save_pattern_applies_server_state_and_guards_failure():
    body = _handler(_read("guardrails.html"), "savePattern")
    assert "if (!resp.ok)" in body, "savePattern must check resp.ok"
    assert "await resp.json()" in body, "savePattern must apply the server's returned pattern"
    # Must NOT optimistically apply the local edit form before the request.
    assert "Object.assign(this.editingPattern, this.editForm)" not in body, (
        "savePattern must not apply the local edit form before knowing the server accepted it"
    )
    assert "error" in body, "savePattern must surface an error toast on failure"


def test_guardrails_update_params_guards_failure_and_reverts():
    body = _handler(_read("guardrails.html"), "updateParams")
    assert "if (!resp.ok)" in body, "updateParams must check resp.ok"
    assert "this.params = previous" in body, "updateParams must revert on failure"
    assert "'error'" in body, "updateParams must error-toast on failure"


def test_guardrails_toggle_pattern_trusts_server_and_reverts():
    body = _handler(_read("guardrails.html"), "togglePattern")
    assert "data.enabled" in body, "togglePattern must read the authoritative enabled state"
    assert "pattern.enabled = previous" in body, "togglePattern must revert on failure"
    # No blind optimistic flip.
    assert "pattern.enabled = !pattern.enabled" not in body


# --- onboarding.html ---------------------------------------------------------


def test_onboarding_apply_checks_every_step():
    body = _handler(_read("onboarding.html"), "apply")
    # The critical admin-password change must not be swallowed.
    assert "pwResp.ok" in body, "onboarding must verify the password change succeeded"
    # No bare, unchecked change-password fetch.
    assert re.search(r"await fetch\('/admin/auth/change-password'[^;]*\);\s*//", body) is None
    # Finalization must be gated too, so a partial setup can't report success.
    assert "doneResp.ok" in body, "onboarding must verify onboarding-complete succeeded"


# --- policies.html -----------------------------------------------------------


def test_policies_toggle_trusts_server_and_reverts():
    body = _handler(_read("policies.html"), "togglePolicy")
    assert "data.active" in body, "togglePolicy must read the authoritative active state"
    assert "policy.active = previous" in body, "togglePolicy must revert on failure"
    assert "policy.active = !policy.active" not in body, "no optimistic flip"
    assert "'error'" in body, "togglePolicy must error-toast on failure"


# --- dashboard.html ----------------------------------------------------------


def test_dashboard_latency_badge_is_bound_to_real_p95():
    src = _read("dashboard.html")
    # The badge must be data-driven, not a hardcoded "On target".
    assert ":class=\"latencyP95 === null" in src, "latency badge must bind to the live P95"
    assert "latencyP95 <= latencyTarget" in src, "badge must compare P95 to the stated target"
    # The old static success badge markup must be gone.
    assert re.search(
        r'sg-badge sg-badge-success">\s*<i data-lucide="trending-down"[^>]*>\s*</i>\s*On target',
        src,
    ) is None, "static hardcoded 'On target' badge must not be reintroduced"
    # updateMetrics must feed the real value into latencyP95.
    assert "this.latencyP95 = data.latency_p95_ms" in src


# --- consistency: no native browser dialogs ----------------------------------

_NATIVE_DIALOG = re.compile(r"(?<![.\w])(?:confirm|alert)\s*\(")
# discovery.html contains the message text "shadow AI alert(s) detected" — not a dialog call.
_DIALOG_ALLOW = {"discovery.html"}


def test_no_native_browser_dialogs_in_admin_pages():
    offenders = []
    for path in sorted(_PAGES.glob("*.html")):
        if path.name in _DIALOG_ALLOW:
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _NATIVE_DIALOG.search(line):
                offenders.append(f"{path.name}:{i}: {line.strip()[:80]}")
    assert not offenders, (
        "Native confirm()/alert() found — use the app's showConfirm()/showToast() "
        f"for consistent, themed dialogs: {offenders}"
    )


# --- low-severity toggles must surface failures ------------------------------


def test_reload_after_post_toggles_error_toast_on_failure():
    cases = [
        ("agents.html", "togglePause"),
        ("tenants.html", "togglePause"),
        ("notifications.html", "toggleChannel"),
    ]
    for page, handler in cases:
        body = _handler(_read(page), handler)
        assert (".ok" in body) or ("resp.ok" in body) or ("res.ok" in body), (
            f"{page}:{handler} must check the response status"
        )
        assert "'error'" in body, f"{page}:{handler} must error-toast on failure"


# --- mutating handlers must gate on resp.ok AND surface failure ---------------

# Handlers that previously either ignored the HTTP status entirely (deceptive
# success) or gated on resp.ok but stayed silent on failure. Each must now both
# check the response status and error-toast when the server rejects the request.
_MUST_GATE_AND_TOAST = [
    ("iocs.html", "deleteIoc"),
    ("iocs.html", "deleteFeed"),
    ("rbac.html", "revokeSession"),
    ("rbac.html", "resetRole"),
    ("dashboard.html", "triggerTask"),
    ("notifications.html", "reloadChannels"),
    ("tenants.html", "deleteTenant"),
    ("tenants.html", "pauseAgent"),
    ("tenants.html", "deleteAgent"),
]


def test_mutating_handlers_gate_on_status_and_error_toast():
    for page, handler in _MUST_GATE_AND_TOAST:
        body = _handler(_read(page), handler)
        assert re.search(r"\b(?:resp|res|r)\.ok\b", body), (
            f"{page}:{handler} must check the HTTP response status (resp.ok) before "
            f"treating the mutation as successful"
        )
        assert "'error'" in body, f"{page}:{handler} must surface an error toast on failure"


def test_toggle_mfa_disable_branch_gates_and_toasts():
    # toggleMfa has two branches; the disable (DELETE) branch previously ignored
    # the response and always claimed success on a security-sensitive action.
    body = _handler(_read("rbac.html"), "toggleMfa")
    disable_branch = body.split("} else {", 1)[0]
    assert "resp.ok" in disable_branch, "MFA disable branch must check resp.ok"
    assert "'error'" in disable_branch, "MFA disable branch must error-toast on failure"


def test_no_fire_and_forget_delete_in_iocs_and_rbac():
    # A bare `await fetch(..., { method: 'DELETE' });` followed immediately by a
    # success toast is the deceptive pattern we removed. Guard against its return.
    for page in ("iocs.html", "rbac.html"):
        src = _read(page)
        assert not re.search(
            r"await fetch\([^;]*method:\s*'DELETE'[^;]*\);\s*\n\s*await[^\n]*\n\s*showToast\([^,]*,\s*'success'",
            src,
        ), f"{page}: found fire-and-forget DELETE that toasts success without checking status"


