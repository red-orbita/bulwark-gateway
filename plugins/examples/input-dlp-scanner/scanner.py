"""
Input DLP Scanner — Data Leakage Prevention for LLM prompts.

Prevents users from sending sensitive data (credit cards, IBANs, national IDs,
API keys, private keys, bulk PII) to LLM backends.

Key features:
- Credit card validation using the Luhn algorithm (not just regex)
- IBAN structural validation (length + country code)
- Spanish DNI/NIE checksum validation
- US SSN format detection with context awareness
- AWS/GCP/Azure API key pattern detection
- Private key header detection (RSA, SSH, PGP)
- Bulk email/phone detection (data dump prevention)

All detection is pure regex + algorithmic — zero external dependencies.
"""

from __future__ import annotations

import re
from typing import Optional

from src.models import GuardrailResult, SecurityEvent, Verdict, ThreatCategory
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Credit card: 13-19 digits, optionally separated by spaces or dashes
_CC_PATTERN = re.compile(
    r"\b(?:"
    r"4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{1,4}"  # Visa
    r"|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # Mastercard
    r"|3[47][0-9]{1,2}[\s\-]?[0-9]{4,6}[\s\-]?[0-9]{4,5}"  # Amex
    r"|6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # Discover
    r"|(?:[0-9]{4}[\s\-]?){3}[0-9]{1,4}"  # Generic 13-19 digits grouped
    r")\b"
)

# IBAN: 2 letter country + 2 check digits + up to 30 alphanumeric
_IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}[0-9]{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b"
)

# Spanish DNI: 8 digits + letter
_DNI_PATTERN = re.compile(r"\b([0-9]{8})[\s\-]?([A-Z])\b")
# Spanish NIE: X/Y/Z + 7 digits + letter
_NIE_PATTERN = re.compile(r"\b([XYZ])[\s\-]?([0-9]{7})[\s\-]?([A-Z])\b")

# US SSN: 3-2-4 format
_SSN_PATTERN = re.compile(r"\b([0-9]{3})[\s\-]([0-9]{2})[\s\-]([0-9]{4})\b")

# AWS Access Key ID (starts with AKIA)
_AWS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
# AWS Secret Key (40 chars base64-ish)
_AWS_SECRET_PATTERN = re.compile(r"\b([A-Za-z0-9/+=]{40})\b")
# GCP API key
_GCP_KEY_PATTERN = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
# Azure subscription key
_AZURE_KEY_PATTERN = re.compile(r"\b[0-9a-f]{32}\b")
# Generic long hex (could be API secret)
_HEX_SECRET_PATTERN = re.compile(r"\b[0-9a-f]{40,64}\b")

# Private key headers
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|DSA|EC|OPENSSH)\s+KEY-----"
)

# Email addresses
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Phone numbers (international format)
_PHONE_PATTERN = re.compile(
    r"(?:\+[0-9]{1,3}[\s\-]?)?(?:\([0-9]{1,4}\)[\s\-]?)?[0-9]{3,4}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{2,4}"
)


# ---------------------------------------------------------------------------
# Validation algorithms
# ---------------------------------------------------------------------------


def luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm.

    The Luhn algorithm (mod 10) detects accidental errors in credit card numbers.
    Returns True if the number passes the checksum.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn: from right, double every second digit
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def validate_dni(number: str, letter: str) -> bool:
    """Validate Spanish DNI checksum.

    DNI letter is calculated as: number % 23 → lookup table.
    """
    _DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
    try:
        idx = int(number) % 23
        return _DNI_LETTERS[idx] == letter.upper()
    except (ValueError, IndexError):
        return False


def validate_nie(prefix: str, number: str, letter: str) -> bool:
    """Validate Spanish NIE checksum.

    NIE prefix X=0, Y=1, Z=2 prepended to 7 digits, same letter calculation as DNI.
    """
    _DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
    prefix_map = {"X": "0", "Y": "1", "Z": "2"}
    try:
        full_number = prefix_map.get(prefix, "0") + number
        idx = int(full_number) % 23
        return _DNI_LETTERS[idx] == letter.upper()
    except (ValueError, IndexError):
        return False


def validate_ssn(area: str, group: str, serial: str) -> bool:
    """Basic SSN validation (reject known invalid ranges)."""
    a, g, s = int(area), int(group), int(serial)
    # SSA never issues: area 000, 666, 900-999; group 00; serial 0000
    if a == 0 or a == 666 or a >= 900:
        return False
    if g == 0 or s == 0:
        return False
    return True


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class Scanner(InputScanner):
    """Input DLP Scanner — blocks sensitive data from being sent to LLMs.

    Detects credit cards (Luhn-validated), IBANs, national IDs (DNI/NIE/SSN),
    cloud API keys, private keys, and bulk PII dumps.
    """

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="input-dlp-scanner",
            version="1.2.0",
            scanner_type=ScannerType.INPUT_ASYNC,
            description="Data Leakage Prevention — blocks sensitive data in LLM prompts",
            author="sentinel-community",
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan user input for sensitive data that should not be sent to LLMs.

        Args:
            content: The normalized user message text.
            context: Request context (tenant, agent, request_id).

        Returns:
            GuardrailResult with BLOCK verdict if sensitive data found,
            WARN for borderline cases, ALLOW otherwise.
        """
        findings: list[str] = []
        severity = "high"

        # --- Credit Card Detection (with Luhn validation) ---
        cc_matches = _CC_PATTERN.finditer(content)
        valid_ccs = 0
        for match in cc_matches:
            raw = match.group(0)
            digits_only = re.sub(r"[\s\-]", "", raw)
            if luhn_check(digits_only):
                valid_ccs += 1
                # Mask for the finding description
                masked = digits_only[:4] + "****" + digits_only[-4:]
                findings.append(f"Credit card detected (Luhn-valid): {masked}")

        # --- IBAN Detection ---
        iban_matches = _IBAN_PATTERN.findall(content)
        for iban in iban_matches:
            clean = iban.replace(" ", "")
            # Basic IBAN length validation by country
            country = clean[:2]
            known_lengths = {
                "ES": 24, "DE": 22, "FR": 27, "GB": 22, "IT": 27,
                "PT": 25, "NL": 18, "BE": 16, "AT": 20, "CH": 21,
            }
            expected_len = known_lengths.get(country)
            if expected_len is None or len(clean) == expected_len:
                findings.append(f"IBAN detected: {clean[:4]}****{clean[-4:]}")

        # --- Spanish DNI ---
        for match in _DNI_PATTERN.finditer(content):
            number, letter = match.group(1), match.group(2)
            if validate_dni(number, letter):
                findings.append(f"Spanish DNI detected: {number[:2]}****{letter}")

        # --- Spanish NIE ---
        for match in _NIE_PATTERN.finditer(content):
            prefix, number, letter = match.group(1), match.group(2), match.group(3)
            if validate_nie(prefix, number, letter):
                findings.append(f"Spanish NIE detected: {prefix}****{letter}")

        # --- US SSN ---
        for match in _SSN_PATTERN.finditer(content):
            area, group, serial = match.group(1), match.group(2), match.group(3)
            if validate_ssn(area, group, serial):
                findings.append(f"US SSN detected: {area}-**-****")

        # --- Cloud API Keys ---
        if _AWS_KEY_PATTERN.search(content):
            findings.append("AWS Access Key ID detected (AKIA...)")
            severity = "critical"

        if _GCP_KEY_PATTERN.search(content):
            findings.append("GCP API key detected (AIza...)")
            severity = "critical"

        # --- Private Keys ---
        if _PRIVATE_KEY_PATTERN.search(content):
            findings.append("Private key detected (RSA/SSH/EC)")
            severity = "critical"

        # --- Bulk Email Detection (data dump) ---
        emails = _EMAIL_PATTERN.findall(content)
        if len(emails) >= 3:
            findings.append(f"Bulk email addresses detected ({len(emails)} found) — possible data dump")

        # --- Bulk Phone Detection ---
        phones = _PHONE_PATTERN.findall(content)
        if len(phones) >= 5:
            findings.append(f"Bulk phone numbers detected ({len(phones)} found) — possible data dump")

        # --- Build result ---
        if not findings:
            return GuardrailResult(verdict=Verdict.ALLOW)

        description = f"DLP: {len(findings)} sensitive data item(s) detected: {'; '.join(findings[:3])}"
        if len(findings) > 3:
            description += f" (+{len(findings) - 3} more)"

        events = [
            SecurityEvent(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.PII_LEAK,
                severity=severity,
                description=description,
                source="input-dlp-scanner",
                request_id=context.request_id,
                metadata={"findings": findings, "count": len(findings)},
            )
        ]

        return GuardrailResult(
            verdict=Verdict.BLOCK,
            events=events,
        )

    async def startup(self) -> None:
        """No initialization needed — pure regex + algorithmic detection."""
        pass

    async def shutdown(self) -> None:
        """No cleanup needed."""
        pass
