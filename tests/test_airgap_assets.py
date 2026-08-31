"""Air-gap / no-CDN regression test.

Enterprise and government deployments frequently run fully air-gapped: the
admin UI must render with ZERO outbound network calls. A single ``<script>`` or
``<link>`` pointing at a CDN (jsdelivr, unpkg, Google Fonts, ...) silently
breaks the UI in those environments — MFA QR codes fail to render, fonts fall
back, and the browser leaks the deployment's existence to a third party.

This test locks the air-gap posture in place:

  * No admin template may reference an external origin.
  * The Content-Security-Policy served by the app must not allow any remote
    origin (every fetch directive is ``'self'`` only).
  * The assets that USED to come from CDNs (qrcodejs, the Inter / JetBrains
    Mono fonts) must be vendored under ``admin/static`` and carry an SRI hash
    both in the template and in ``sri-hashes.json``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _ROOT / "admin" / "templates"
_STATIC = _ROOT / "admin" / "static"

# Any absolute http(s) URL that is not the local app itself is forbidden.
_EXTERNAL_URL_RE = re.compile(r"https?://(?!localhost|127\.0\.0\.1)[^\s'\"()]+")
# Known CDN hosts we explicitly migrated away from.
_FORBIDDEN_HOSTS = (
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
)


def _template_files() -> list[Path]:
    return sorted(_TEMPLATES.rglob("*.html"))


def test_templates_exist():
    assert _template_files(), "no admin templates found — path wrong?"


@pytest.mark.parametrize("host", _FORBIDDEN_HOSTS)
def test_no_forbidden_cdn_host_in_templates(host):
    offenders = []
    for tpl in _template_files():
        text = tpl.read_text(encoding="utf-8")
        if host in text:
            offenders.append(tpl.relative_to(_ROOT).as_posix())
    assert offenders == [], f"CDN host '{host}' still referenced in: {offenders}"


def test_no_external_url_anywhere_in_templates():
    """Catch *any* new external origin, not just the known CDN hosts.

    Allowlist: schema/namespace URLs (w3.org SVG namespace) and the OWASP/docs
    style comment links are not asset loads; we only fail on http(s) URLs that
    appear inside src=/href= asset attributes.
    """
    asset_attr_re = re.compile(
        r"""(?:src|href)\s*=\s*['"](https?://[^'"]+)['"]""", re.IGNORECASE
    )
    offenders: list[str] = []
    for tpl in _template_files():
        for m in asset_attr_re.finditer(tpl.read_text(encoding="utf-8")):
            url = m.group(1)
            if url.startswith(("http://localhost", "http://127.0.0.1")):
                continue
            offenders.append(f"{tpl.relative_to(_ROOT).as_posix()}: {url}")
    assert offenders == [], f"external asset URLs must be vendored: {offenders}"


def test_csp_header_has_no_remote_origins():
    """The served CSP must confine every fetch directive to 'self'."""
    import os

    os.environ.setdefault("ADMIN_DEBUG", "true")
    os.environ.setdefault("ADMIN_JWT_SECRET", "airgap-test-secret-32-characters-minimum!!")
    os.environ.setdefault("BULWARK_JWT_SECRET", "airgap-test-secret-32-characters-minimum!!")
    os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "airgap-test-encryption-32-chars-minimum!")

    from fastapi.testclient import TestClient

    from admin.main import app

    with TestClient(app) as client:
        resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp, "no CSP header served"
    for host in _FORBIDDEN_HOSTS:
        assert host not in csp, f"CSP still allows remote origin '{host}': {csp}"
    # No absolute remote origin should appear at all.
    assert "https://" not in csp, f"CSP contains a remote origin: {csp}"


def test_vendored_assets_present():
    """The former-CDN assets must physically exist in the repo."""
    assert (_STATIC / "js" / "vendor" / "qrcode.min.js").is_file()
    assert (_STATIC / "css" / "fonts.css").is_file()
    fonts = list((_STATIC / "fonts").glob("*.woff2"))
    assert fonts, "self-hosted woff2 fonts are missing"


def test_fonts_css_is_self_contained():
    """fonts.css must reference only local /static font files."""
    css = (_STATIC / "css" / "fonts.css").read_text(encoding="utf-8")
    external = _EXTERNAL_URL_RE.findall(css)
    assert external == [], f"fonts.css still points at remote URLs: {external}"
    assert "/static/fonts/" in css, "fonts.css does not reference local fonts"


def test_vendored_assets_have_sri_entries():
    sri = json.loads((_STATIC / "sri-hashes.json").read_text(encoding="utf-8"))
    for asset in ("qrcode.min.js", "fonts.css"):
        assert asset in sri, f"{asset} missing from sri-hashes.json"
        assert sri[asset].startswith("sha384-"), f"{asset} SRI malformed"


def _sri_for(path: Path) -> str:
    import base64
    import hashlib

    return "sha384-" + base64.b64encode(
        hashlib.sha384(path.read_bytes()).digest()
    ).decode()


@pytest.mark.parametrize("asset", ["tailwind.min.css", "fonts.css"])
def test_stylesheet_sri_matches_file_contents(asset):
    """A stale SRI hash silently breaks the UI: the browser refuses to apply a
    stylesheet whose integrity doesn't match, so editing the CSS without
    re-hashing ships a blank/unstyled admin. Lock the hash to the bytes."""
    css_path = _STATIC / "css" / asset
    actual = _sri_for(css_path)

    sri = json.loads((_STATIC / "sri-hashes.json").read_text(encoding="utf-8"))
    assert sri.get(asset) == actual, (
        f"sri-hashes.json[{asset}] is stale — recompute after editing the CSS"
    )

    base = (_TEMPLATES / "base.html").read_text(encoding="utf-8")
    m = re.search(
        rf"""/static/css/{re.escape(asset)}['"][^>]*integrity=['"](sha384-[^'"]+)['"]""",
        base,
    )
    assert m, f"base.html does not load {asset} with an integrity attribute"
    assert m.group(1) == actual, (
        f"base.html integrity for {asset} is stale — recompute after editing CSS"
    )


def test_qrcode_referenced_with_integrity():
    rbac = (_TEMPLATES / "pages" / "rbac.html").read_text(encoding="utf-8")
    assert "/static/js/vendor/qrcode.min.js" in rbac
    m = re.search(
        r"qrcode\.min\.js[^>]*integrity=['\"](sha384-[^'\"]+)['\"]", rbac
    )
    assert m, "qrcode script tag must carry an SRI integrity attribute"


# ── H-1: nonce-based script-src CSP hardening ────────────────────────────────

_SCRIPT_OPEN_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)


def _script_src_directive(csp: str) -> str:
    """Extract the script-src directive body from a CSP header string."""
    for part in csp.split(";"):
        part = part.strip()
        if part.startswith("script-src"):
            return part
    return ""


def _boot_admin_app():
    import os

    os.environ.setdefault("ADMIN_DEBUG", "true")
    os.environ.setdefault("ADMIN_JWT_SECRET", "airgap-test-secret-32-characters-minimum!!")
    os.environ.setdefault("BULWARK_JWT_SECRET", "airgap-test-secret-32-characters-minimum!!")
    os.environ.setdefault("BULWARK_KEY_ENCRYPTION_KEY", "airgap-test-encryption-32-chars-minimum!")

    from fastapi.testclient import TestClient

    from admin.main import app

    return TestClient(app)


def test_every_inline_script_block_carries_a_nonce():
    """A bare inline <script> (no src) that lacks a nonce would be BLOCKED once
    'unsafe-inline' is dropped from script-src — the page's Alpine component
    function would never register and the screen would break. Lock every inline
    block to the per-request nonce so this can never regress silently."""
    offenders: list[str] = []
    for path in _template_files():
        text = path.read_text(encoding="utf-8")
        for tag in _SCRIPT_OPEN_RE.findall(text):
            if "src=" in tag:
                continue  # external/self-hosted script, covered by 'self'
            if 'nonce="{{ csp_nonce() }}"' not in tag:
                offenders.append(f"{path.relative_to(_ROOT)}: {tag}")
    assert not offenders, (
        "inline <script> blocks missing the CSP nonce (would be blocked by CSP):\n"
        + "\n".join(offenders)
    )


def test_csp_script_src_is_nonce_based_and_drops_unsafe_inline():
    """script-src must authenticate inline scripts via a per-request nonce and
    must NOT contain 'unsafe-inline' (which would defeat the nonce). 'unsafe-eval'
    is the documented, honest residual required by the Alpine.js runtime."""
    with _boot_admin_app() as client:
        resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp, "no CSP header served"

    script_src = _script_src_directive(csp)
    assert script_src, f"no script-src directive in CSP: {csp}"
    assert "'nonce-" in script_src, f"script-src is not nonce-based: {script_src}"
    assert "'unsafe-inline'" not in script_src, (
        f"script-src still allows 'unsafe-inline' — nonce is defeated: {script_src}"
    )
    # unsafe-eval is intentionally retained for Alpine (documented in main.py).
    assert "'unsafe-eval'" in script_src


def test_csp_nonce_rotates_per_request():
    """A static/reused nonce is worthless. Two requests must mint distinct
    nonce values."""
    with _boot_admin_app() as client:
        n1 = _script_src_directive(client.get("/login").headers.get("Content-Security-Policy", ""))
        n2 = _script_src_directive(client.get("/login").headers.get("Content-Security-Policy", ""))
    m1 = re.search(r"'nonce-([^']+)'", n1)
    m2 = re.search(r"'nonce-([^']+)'", n2)
    assert m1 and m2, "nonce missing from script-src"
    assert m1.group(1) != m2.group(1), "CSP nonce did not rotate between requests"


def test_rendered_inline_script_nonce_matches_header():
    """End-to-end wiring: the nonce emitted by the Jinja csp_nonce() global into
    the rendered HTML must equal the nonce advertised in the CSP header, or the
    browser rejects the script."""
    with _boot_admin_app() as client:
        resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    header_m = re.search(r"'nonce-([^']+)'", _script_src_directive(csp))
    assert header_m, "no nonce in CSP header"
    header_nonce = header_m.group(1)

    body = resp.text
    # The login page ships an inline <script>; it must carry the header's nonce.
    assert f'<script nonce="{header_nonce}">' in body, (
        "rendered inline <script> nonce does not match the CSP header nonce"
    )


# Signature of a malformed bound attribute: a single-quoted value that is
# immediately followed by a stray double-quote, e.g.
#   :class="cond ? 'a' : 'b'"">   (the extra " terminates into an empty attr)
# This is distinct from a legitimate empty attribute (value="").
_MALFORMED_ATTR_RE = re.compile(r"'\"\"")


def test_no_malformed_double_quote_attributes():
    """Regression guard: no template may contain a stray doubled closing quote on
    a single-quoted (Alpine/Vue) bound attribute. Regression for the enrichment.html
    filter buttons which rendered `...hover:text-white'"">` (empty spurious attr)."""
    offenders = []
    for tpl in _template_files():
        text = tpl.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _MALFORMED_ATTR_RE.search(line):
                offenders.append(f"{tpl.relative_to(_ROOT).as_posix()}:{lineno}")
    assert offenders == [], f"malformed doubled-quote attributes found: {offenders}"


def test_enrichment_filter_buttons_are_well_formed():
    """Positive check: the three enrichment regex-filter buttons keep exactly one
    closing quote on their :class binding and remain wired to loadCandidates()."""
    text = (_TEMPLATES / "pages" / "enrichment.html").read_text(encoding="utf-8")
    for verdict in ("pending", "approved", "rejected"):
        assert f"regexFilter = '{verdict}'; loadCandidates()" in text, (
            f"enrichment {verdict} filter button lost its click handler"
        )
    assert "hover:text-white'\">" in text, "expected well-formed single closing quote"
    assert "hover:text-white'\"\">" not in text, "stray doubled closing quote present"


# ── Static-asset cache-busting ───────────────────────────────────────────────
#
# The vendored CSS/JS are served under stable URLs, so a browser can hold a
# stale copy across an image rebuild (the URL never changes even when the bytes
# do). main._asset_url() appends a content-hash ?v= marker so any byte change
# forces a fresh fetch. These tests lock that wiring so a future edit can't
# silently drop it and reintroduce the stale-cache class of bug.


def test_asset_url_appends_content_hash_version():
    """asset_url() must return the same path plus a stable ?v=<hash> marker for
    a real static file, so browsers cache-key on content."""
    from admin.main import _asset_url

    out = _asset_url("/static/css/tailwind.min.css")
    m = re.match(r"^/static/css/tailwind\.min\.css\?v=([0-9a-f]{12})$", out)
    assert m, f"expected a ?v=<12 hex> cache-buster, got: {out!r}"
    # Deterministic: same content → same version on repeat calls.
    assert _asset_url("/static/css/tailwind.min.css") == out


def test_asset_url_version_tracks_content():
    """Two assets with different bytes must get different version markers, and
    the marker must equal the leading 12 hex of the file's SHA-256."""
    import hashlib

    from admin.main import _asset_url

    css = _asset_url("/static/css/tailwind.min.css")
    js = _asset_url("/static/js/vendor/lucide.min.js")
    assert css.split("v=")[1] != js.split("v=")[1], "distinct files share a version"

    expected = hashlib.sha256(
        (_STATIC / "css" / "tailwind.min.css").read_bytes()
    ).hexdigest()[:12]
    assert css.endswith(f"?v={expected}"), "version is not the file's SHA-256 prefix"


def test_asset_url_is_safe_on_missing_or_escaping_paths():
    """A lookup failure or path-traversal attempt must degrade to the original
    path — never raise, never read outside the static root."""
    from admin.main import _asset_url

    # Non-static path is passed through untouched.
    assert _asset_url("https://example.com/x.js") == "https://example.com/x.js"
    # Missing file → unchanged (no crash).
    assert _asset_url("/static/does/not/exist.css") == "/static/does/not/exist.css"
    # Traversal outside the static root → unchanged.
    assert (
        _asset_url("/static/../../../etc/passwd")
        == "/static/../../../etc/passwd"
    )


def test_rendered_pages_carry_cache_busted_asset_urls():
    """End-to-end: the login and dashboard HTML must ship the tailwind stylesheet
    with a ?v= cache-buster, and no bare (unversioned) /static asset link may
    survive in the rendered <head>."""
    with _boot_admin_app() as client:
        login = client.get("/login").text
    assert re.search(
        r"/static/css/tailwind\.min\.css\?v=[0-9a-f]{12}", login
    ), "login page did not cache-bust the tailwind stylesheet"
    # No unversioned asset src/href should remain in the rendered page.
    bare = re.findall(r"""(?:src|href)=["']/static/[^"'?]+["']""", login)
    assert bare == [], f"rendered login page has unversioned static assets: {bare}"
