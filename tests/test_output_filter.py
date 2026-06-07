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
