"""Tests for output filter."""

import pytest
from src.guardrails.output_filter import OutputFilter
from src.models import Verdict


@pytest.fixture
def filter():
    return OutputFilter(redact_pii=True, redact_secrets=True)


class TestSecretRedaction:
    def test_aws_key_redacted(self, filter):
        content = "Your key is AKIAIOSFODNN7EXAMPLE"
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "AKIAIOSFODNN7EXAMPLE" not in result.modified_content

    def test_stripe_key_redacted(self, filter):
        content = "Token: sk_test_1234567890abcdefFAKEKEY00"
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "sk_test_" not in result.modified_content

    def test_github_token_redacted(self, filter):
        content = "Use ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT

    def test_db_url_redacted(self, filter):
        content = "Connection: postgresql://admin:secret@db.internal:5432/app"
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "[REDACTED:DB_URL]" in result.modified_content

    def test_private_key_detected(self, filter):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT

    def test_clean_output_allowed(self, filter):
        content = "Here are the Python deployment best practices..."
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.ALLOW


class TestToolCallArgumentFiltering:
    """AC-01: Verify output filter catches secrets in tool call argument strings."""

    def test_aws_key_in_tool_args(self, filter):
        """Secrets in tool_call arguments must be redacted."""
        args_str = '{"path": "/tmp/out.txt", "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}'
        result = filter.inspect_and_redact(args_str)
        assert result.verdict == Verdict.REDACT
        assert "AKIAIOSFODNN7EXAMPLE" not in result.modified_content

    def test_private_key_in_tool_args(self, filter):
        args_str = '{"data": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAK..."}'
        result = filter.inspect_and_redact(args_str)
        assert result.verdict == Verdict.REDACT

    def test_db_url_in_tool_args(self, filter):
        args_str = '{"connection": "postgresql://admin:secret@db.internal:5432/app"}'
        result = filter.inspect_and_redact(args_str)
        assert result.verdict == Verdict.REDACT
        assert "secret" not in result.modified_content

    def test_clean_tool_args_allowed(self, filter):
        args_str = '{"query": "SELECT id, name FROM users WHERE active = true"}'
        result = filter.inspect_and_redact(args_str)
        assert result.verdict == Verdict.ALLOW


class TestPIIRedaction:
    def test_credit_card_redacted(self, filter):
        content = "Card number: 4111111111111111"
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "[REDACTED:CC]" in result.modified_content

    def test_ssn_redacted(self, filter):
        content = "SSN: 123-45-6789"
        result = filter.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "[REDACTED:SSN]" in result.modified_content


class TestEmailPhoneOptInRedaction:
    """Email/phone are high-false-positive PII types: redaction is opt-in.

    By default (matching the proxy's default OutputFilter) they must NOT be
    redacted so legitimate agent output (e.g. a support bot returning a contact
    address) is preserved. When the operator explicitly enables the flag, they
    must be redacted with a real placeholder. This guards against the previous
    dead-control behaviour where the patterns matched but silently did nothing.
    """

    # --- Email ---
    def test_email_not_redacted_by_default(self):
        f = OutputFilter(redact_pii=True, redact_secrets=True)
        content = "Contact support at agent-oncall@example.com for help."
        result = f.inspect_and_redact(content)
        assert result.verdict == Verdict.ALLOW
        # ALLOW => content is unchanged (modified_content stays None).
        assert result.modified_content is None
        assert not any(e.matched_pattern == "EMAIL" for e in result.events)

    def test_email_redacted_when_enabled(self):
        f = OutputFilter(redact_pii=True, redact_secrets=True, redact_email=True)
        content = "Contact support at agent-oncall@example.com for help."
        result = f.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "agent-oncall@example.com" not in result.modified_content
        assert "[REDACTED:EMAIL]" in result.modified_content
        assert any(e.matched_pattern == "EMAIL" for e in result.events)

    def test_email_not_redacted_when_pii_disabled(self):
        # redact_email must not override the master redact_pii switch.
        f = OutputFilter(redact_pii=False, redact_secrets=True, redact_email=True)
        content = "Contact support at agent-oncall@example.com for help."
        result = f.inspect_and_redact(content)
        assert not any(e.matched_pattern == "EMAIL" for e in result.events)
        if result.modified_content is not None:
            assert "agent-oncall@example.com" in result.modified_content

    # --- Phone ---
    def test_phone_not_redacted_by_default(self):
        f = OutputFilter(redact_pii=True, redact_secrets=True)
        content = "Call us at +12025550143 during business hours."
        result = f.inspect_and_redact(content)
        assert result.verdict == Verdict.ALLOW
        assert result.modified_content is None
        assert not any(e.matched_pattern == "PHONE" for e in result.events)

    def test_phone_redacted_when_enabled(self):
        f = OutputFilter(redact_pii=True, redact_secrets=True, redact_phone=True)
        content = "Call us at +12025550143 during business hours."
        result = f.inspect_and_redact(content)
        assert result.verdict == Verdict.REDACT
        assert "+12025550143" not in result.modified_content
        assert "[REDACTED:PHONE]" in result.modified_content
        assert any(e.matched_pattern == "PHONE" for e in result.events)

    def test_flags_are_independent(self):
        # Enabling email must not enable phone and vice-versa.
        f = OutputFilter(redact_pii=True, redact_secrets=True, redact_email=True)
        content = "Mail agent-oncall@example.com or call +12025550143."
        result = f.inspect_and_redact(content)
        assert "[REDACTED:EMAIL]" in result.modified_content
        assert "+12025550143" in result.modified_content  # phone still present
