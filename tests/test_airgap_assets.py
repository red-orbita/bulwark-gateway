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


def test_qrcode_referenced_with_integrity():
    rbac = (_TEMPLATES / "pages" / "rbac.html").read_text(encoding="utf-8")
    assert "/static/js/vendor/qrcode.min.js" in rbac
    m = re.search(
        r"qrcode\.min\.js[^>]*integrity=['\"](sha384-[^'\"]+)['\"]", rbac
    )
    assert m, "qrcode script tag must carry an SRI integrity attribute"
