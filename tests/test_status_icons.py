"""Status glyphs stay on Alpine-owned nodes instead of Lucide replacements."""

from html.parser import HTMLParser
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Template checks do not require the user database."""


@pytest.mark.parametrize("page,expression", [
    ("siem", "pageTestResult?.success"),
    ("siem", "modalTestResult?.success"),
    ("settings", "validationResult?.valid"),
    ("policies", "validationResult?.valid"),
    ("guardrails", "regexValidation?.valid"),
    ("guardrails", "patternTest.matched"),
    ("guardrails", "editTestResult"),
    ("status", "overallHealthy"),
])
def test_status_icon_has_complementary_reactive_shapes(page, expression):
    icons = []

    class Icons(HTMLParser):
        current = None

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "svg":
                self.current = {"attrs": attrs, "conditions": []}
                icons.append(self.current)
            if self.current is not None:
                assert "data-lucide" not in attrs and ":data-lucide" not in attrs
                if "x-show" in attrs:
                    self.current["conditions"].append(attrs["x-show"])

        def handle_endtag(self, tag):
            if tag == "svg":
                self.current = None

    text = (Path(__file__).parents[1] / f"admin/templates/pages/{page}.html").read_text()
    Icons().feed(text)
    matching = [icon for icon in icons if expression in icon["conditions"]]
    assert len(matching) == 1
    assert "!" + expression in matching[0]["conditions"]
    assert matching[0]["attrs"]["aria-hidden"] == "true"
    assert matching[0]["attrs"]["stroke"] == "currentColor"
    assert f':data-lucide="{expression} ' not in text
