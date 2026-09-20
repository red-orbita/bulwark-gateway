"""DLP before upstream delivery, including structured and encoded secret channels."""

import base64
import copy

import pytest

from src.guardrails import input_dlp
from src.guardrails.input_dlp import inspect_request
from src.models import GuardrailResult, Verdict

SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Pure DLP tests do not initialize the admin database."""


@pytest.mark.parametrize("body", [
    {"messages": [{"role": "user", "content": SECRET}]},
    {"messages": [{"role": "tool", "content": [{"type": "text", "text": SECRET}]}]},
    {"tools": [{"parameters": {"properties": {"key": {"default": SECRET}}}}]},
    {SECRET: "hidden in a key"},
    {"content": base64.b64encode(SECRET.encode()).decode()},
    {"content": "AKIA\u200bIOSFODNN7EXAMPLE"},
    {"password": "R8!mQ2#vL9"},
    {"credit_card": 4111111111111111},
    {"auths": {"registry.example": {"auth": "dXNlcjpwYXNzd29yZDEyMw=="}}},
])
def test_known_secret_never_approved(body):
    result = inspect_request(body, "tenant-a", "agent-a", "request-a")
    assert result.verdict == Verdict.BLOCK
    assert SECRET not in result.model_dump_json()
    assert result.events[0].tenant_id == "tenant-a"
    assert result.events[0].request_id == "request-a"


@pytest.mark.parametrize("body", [
    {"messages": [{"role": "user", "content": "Explain how API keys should be rotated"}]},
    {"model": "local", "messages": [{"role": "user", "content": "Hello"}]},
    {"tools": [{"name": "weather", "description": "Weather for a city"}]},
])
def test_clean_input_allowed(body):
    assert inspect_request(body, "t", "a", "r").verdict == Verdict.ALLOW


def test_email_is_explicit_opt_in():
    body = {"content": "Reach john.smith@example.com"}
    assert inspect_request(body, "t", "a", "r").verdict == Verdict.ALLOW
    assert inspect_request(body, "t", "a", "r", redact_email=True).verdict == Verdict.BLOCK


@pytest.mark.parametrize("body", [{"content": "a" * 65537}, {"items": ["a"] * 5000}])
def test_incomplete_scan_blocks(body):
    result = inspect_request(body, "t", "a", "r")
    assert result.verdict == Verdict.BLOCK
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"


def test_contextual_candidates_do_not_double_charge_data_budget(monkeypatch):
    monkeypatch.setattr(input_dlp.OutputFilter, "inspect_and_redact",
                        lambda *args: GuardrailResult(verdict=Verdict.ALLOW))
    body = {"messages": [{"role": "user", "content": [{"type": "text", "text": "a" * 12000} for _ in range(3)]}]}
    assert inspect_request(body, "t", "a", "r", max_bytes=65536).verdict == Verdict.ALLOW
    assert inspect_request(body, "t", "a", "r", max_bytes=32768).verdict == Verdict.BLOCK


@pytest.fixture
def clean_detector(monkeypatch):
    scanned = []

    def scan(self, text, tenant, agent):
        scanned.append(text)
        return GuardrailResult(verdict=Verdict.ALLOW)

    monkeypatch.setattr(input_dlp.OutputFilter, "inspect_and_redact", scan)
    return scanned


@pytest.mark.parametrize("text", ["a " * 10000, "\U0001f600\u00e9 " * 4000])
def test_byte_bounded_windows_cover_entire_value(text, clean_detector):
    body = {"": [text]}
    assert inspect_request(body, "t", "a", "r", max_bytes=len(text.encode())).verdict == Verdict.ALLOW
    assert len(clean_detector) > 1
    rebuilt = clean_detector[0]
    for previous, window in zip(clean_detector, clean_detector[1:], strict=False):
        assert previous[-256:] == window[:256]
        rebuilt += window[256:]
    assert rebuilt == text
    assert all(len(window.encode()) <= 16384 for window in clean_detector)


@pytest.mark.parametrize("maximum", [32768, 65536, 262144])
def test_exact_global_budget_counts_raw_keys_and_values_once(maximum, clean_detector):
    body = {"text": "a " * ((maximum - 4) // 2)}
    assert inspect_request(body, "t", "a", "r", max_bytes=maximum).verdict == Verdict.ALLOW
    assert "text=" in clean_detector[0]
    result = inspect_request(body, "t", "a", "r", max_bytes=maximum - 1)
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"


def test_context_budget_is_separate_and_finite(clean_detector):
    body = {"long-key-" * 400: "a " * 10000}
    raw_size = sum(len(key.encode()) + len(value.encode()) for key, value in body.items())
    assert inspect_request(body, "t", "a", "r", max_bytes=raw_size).verdict == Verdict.ALLOW
    clean_detector.clear()
    result = inspect_request({"a": "x" * 3000, "b": "x" * 3000}, "t", "a", "r", max_bytes=1000)
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"
    assert not clean_detector


@pytest.mark.parametrize("position", [16374, 20000, 32490])
@pytest.mark.parametrize("field", ["value", "key"])
def test_real_secret_at_seam_or_tail(position, field):
    text = "a " * (position // 2) + SECRET + " report"
    body = {"text": text} if field == "value" else {text: "report"}
    result = inspect_request(body, "t", "a", "r")
    assert result.verdict == Verdict.BLOCK
    assert result.events[0].metadata["reason"] == "sensitive_input"
    assert SECRET not in result.model_dump_json()


def test_long_scalar_retains_credential_context():
    result = inspect_request({"password": "R8!mQ2#vL9 " + "report " * 3000}, "t", "a", "r")
    assert result.events[0].metadata["reason"] == "sensitive_input"


@pytest.mark.parametrize("kwargs, marker", [
    ({"redact_email": True}, "john.smith@example.com"),
    ({"redact_phone": True}, "+12025550199"),
    ({}, "4111-1111-1111-1111"),
    ({}, "password=R8!mQ2#vL9"),
])
def test_pii_and_contextual_secrets_cross_window_seam(kwargs, marker):
    body = {"": ["a " * 8188 + marker + " report " * 1000]}
    result = inspect_request(body, "t", "a", "r", **kwargs)
    assert result.events[0].metadata["reason"] == "sensitive_input"
    assert marker not in result.model_dump_json()


@pytest.mark.parametrize("term", ["restricted project", "r" * 128, "project\u200bfalcon"])
def test_classification_seams_normalize_without_disclosure(term, clean_detector):
    text = "a " * 8188 + term.upper() + " report " * 1000
    result = inspect_request({"text": text}, "t", "a", "r", blocked_terms=(term,))
    assert result.verdict == Verdict.BLOCK
    assert result.events[0].metadata["reason"] == "restricted_classification"
    assert term not in result.model_dump_json()


def test_window_count_is_global_and_fails_closed(clean_detector):
    assert inspect_request({"": ["report"] * 128}, "t", "a", "r").verdict == Verdict.ALLOW
    clean_detector.clear()
    result = inspect_request({"": ["report"] * 129}, "t", "a", "r")
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"
    assert len(clean_detector) == 128


@pytest.mark.parametrize("failure", ["exception", "block", "timeout"])
def test_detector_failure_is_private_and_incomplete(monkeypatch, failure):
    clock = [0.0]
    monkeypatch.setattr(input_dlp, "monotonic", lambda: clock[0])

    def scan(*args):
        if failure == "exception":
            raise RuntimeError("private document")
        if failure == "timeout":
            clock[0] = input_dlp._MAX_INSPECTION_SECONDS + 0.01
        return GuardrailResult(verdict=Verdict.BLOCK if failure == "block" else Verdict.ALLOW)

    monkeypatch.setattr(input_dlp.OutputFilter, "inspect_and_redact", scan)
    result = inspect_request({"": ["private document"]}, "t", "a", "r")
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"
    assert "private document" not in result.model_dump_json()


def test_elapsed_budget_applies_across_windows(monkeypatch):
    clock = [0.0]
    calls = []
    monkeypatch.setattr(input_dlp, "monotonic", lambda: clock[0])

    def scan(self, text, tenant, agent):
        calls.append(text)
        clock[0] += input_dlp._MAX_INSPECTION_SECONDS * 0.6
        return GuardrailResult(verdict=Verdict.ALLOW)

    monkeypatch.setattr(input_dlp.OutputFilter, "inspect_and_redact", scan)
    result = inspect_request({"": ["report " * 5000]}, "t", "a", "r")
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"
    assert len(calls) == 2


def test_elapsed_budget_checked_before_detector(monkeypatch, clean_detector):
    clock = iter([0.0, input_dlp._MAX_INSPECTION_SECONDS + 0.01])
    monkeypatch.setattr(input_dlp, "monotonic", lambda: next(clock))
    result = inspect_request({"text": "report"}, "t", "a", "r")
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"
    assert not clean_detector


@pytest.mark.parametrize("body, maximum", [
    ({"text": "\ud800"}, 65536), ({"text": "\u00e9" * 10000}, 20003),
    ({"text": "report"}, 262145), ({"text": "report"}, 0),
])
def test_invalid_utf8_or_byte_budget_fails_closed(body, maximum, clean_detector):
    result = inspect_request(body, "t", "a", "r", max_bytes=maximum)
    assert result.verdict == Verdict.BLOCK
    assert result.events[0].metadata["reason"] == "input_dlp_incomplete"


@pytest.mark.parametrize("sensitive", [False, True])
def test_request_and_nested_references_unchanged(sensitive, clean_detector):
    child = {"text": "report " * 3000}
    values = [child, child]
    body = {"messages": values}
    original = copy.deepcopy(body)
    result = inspect_request(body, "t", "a", "r", blocked_terms=("report",) if sensitive else ())
    assert result.verdict == (Verdict.BLOCK if sensitive else Verdict.ALLOW)
    assert body == original
    assert body["messages"] is values
    assert values[0] is values[1] is child
