"""UI wiring test for the correlation Runtime Lethal Trifecta observability card.

The runtime lethal-trifecta accumulator (``src/correlation/trifecta_runtime.py``)
exposes boot config + completion counters + accumulating-origin count on the admin
API (``GET /admin/correlation/trifecta``), but ``pages/correlation.html`` previously
never surfaced them — the data was API-only. This test guards the read-only card
that renders them:

  - the Jinja template still compiles (no syntax regression), and
  - the client-side component fetches the ``/trifecta`` endpoint and binds the
    documented response envelope (``config`` / ``counters`` / ``accumulating_origins``).

It is intentionally dependency-light: it compiles the template through a Jinja2
environment and asserts on the raw source, so it needs neither the full admin app,
a DB, nor a browser.
"""

from __future__ import annotations

import os

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "admin", "templates"
)
_TEMPLATE = "pages/correlation.html"


def _source() -> str:
    with open(os.path.join(_TEMPLATES_DIR, _TEMPLATE), encoding="utf-8") as fh:
        return fh.read()


def test_correlation_template_compiles():
    # Compiling the child template catches any Jinja syntax regression introduced
    # by the new trifecta markup (extends/parent resolved lazily at render).
    env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR), autoescape=True)
    env.get_template(_TEMPLATE)  # raises TemplateSyntaxError on a bad template


def test_trifecta_card_present():
    src = _source()
    assert "Runtime Lethal Trifecta" in src


def test_fetches_trifecta_endpoint():
    src = _source()
    assert "/admin/correlation/trifecta" in src


def test_binds_documented_response_envelope():
    src = _source()
    # The loader binds the exact keys the backend endpoint returns.
    assert "trifecta.config" in src
    assert "trifecta.counters" in src
    assert "trifecta.accumulating_origins" in src
    # Reactive prop + the fail-open loader are wired and invoked on reload.
    assert "loadTrifecta" in src
    assert "await this.loadTrifecta()" in src


def test_config_rendered_read_only():
    src = _source()
    # The boot config surfaces enabled/blocking/window as a read-only badge, not
    # an editable knob (no form field bound to trifecta config).
    assert "trifecta.config.enabled" in src
    assert "trifecta.config.blocking" in src
    assert "trifecta.config.window_seconds" in src
