"""UI wiring test for the integrations background-worker observability cards.

The three fail-open background workers (sighting dispatcher, reconcile poller,
event-webhook delivery) each expose an observability ``/status`` snapshot on the
admin API, but ``pages/integrations.html`` previously never consumed them — the
data was API-only. This test guards the UI wiring that surfaces them as
read-only cards:

  - the Jinja template still compiles (no syntax regression), and
  - the client-side component fetches all three ``/status`` endpoints and binds
    the documented response envelopes (``dispatcher`` / ``poller`` / ``emitter``).

It is intentionally dependency-light: it compiles the template through a Jinja2
environment and asserts on the raw source, so it needs neither the full admin
app, a DB, nor a browser.
"""

from __future__ import annotations

import os

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "admin", "templates"
)
_TEMPLATE = "pages/integrations.html"


def _source() -> str:
    with open(os.path.join(_TEMPLATES_DIR, _TEMPLATE), encoding="utf-8") as fh:
        return fh.read()


def test_integrations_template_compiles():
    # Compiling the child template catches any Jinja syntax regression introduced
    # by the new observability markup (extends/parent resolved lazily at render).
    env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR), autoescape=True)
    env.get_template(_TEMPLATE)  # raises TemplateSyntaxError on a bad template


def test_observability_card_present():
    src = _source()
    assert "Background Worker Observability" in src
    # The three worker panels.
    assert "Sighting Dispatcher" in src
    assert "Reconcile Poller" in src
    assert "Webhook Delivery" in src


def test_fetches_all_three_status_endpoints():
    src = _source()
    assert "/admin/integrations/sightings/status" in src
    assert "/admin/integrations/reconcile/status" in src
    assert "/admin/integrations/webhooks/status" in src


def test_binds_documented_response_envelopes():
    src = _source()
    # The loaders unwrap the exact keys the backend endpoints return.
    assert ".dispatcher" in src
    assert ".poller" in src
    assert ".emitter" in src
    # Reactive props + the fail-open loader are wired.
    assert "sightingsStatus" in src
    assert "reconcileStatus" in src
    assert "webhookDeliveryStatus" in src
    assert "loadWorkerObservability" in src


def test_worker_badge_helpers_present():
    src = _source()
    # Health badge derives from enabled/running without throwing on null.
    assert "workerBadge" in src
    assert "workerLabel" in src
