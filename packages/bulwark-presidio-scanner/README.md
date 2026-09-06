# bulwark-presidio-scanner

Optional **Microsoft Presidio** (NER-backed) PII scanner plugin for
[Bulwark Gateway](../../README.md). It complements the builtin regex-only output
filter with **context-aware PII detection** — `PERSON`, `LOCATION`, medical /
finance identifiers, and more — for LLM-output redaction and inbound-PII
advisory.

It plugs into Bulwark through the standard `bulwark.scanners` entry-point group,
so once installed it is auto-discovered by the scanner pipeline (no core code
changes). This mirrors the pfSense model: a curated third-party engine you switch
on when you need it.

## What you get

| Scanner | Type | Behaviour |
|---------|------|-----------|
| `PresidioOutputScanner` | `OUTPUT_BLOCKING` | Detects PII in LLM responses, returns `REDACT` with spans masked as `[REDACTED:<ENTITY>]`. |
| `PresidioInputScanner`  | `INPUT_ASYNC`    | Advisory: emits a `WARN` security event when a user message contains PII (does not block or modify). |

Both are **BETA** maturity: real detection logic, but validate efficacy against
your own data before blocking in production.

## Fail-open by design

The heavy dependencies (`presidio-analyzer` + a spaCy model) are an **optional
extra**. If they are not installed the scanners are **inert**:

- `health()` returns `False`,
- `scan()` returns a clean `ALLOW` (no redaction, no crash),
- a single `critical` log line explains that Presidio is not provisioned.

This is deliberate: registering the plugin without provisioning the model must
never take down the pipeline. Install the extra to activate it.

## Install

From the Bulwark repo root (editable, in-repo):

```bash
pip install -e "packages/bulwark-presidio-scanner[presidio]"
python -m spacy download en_core_web_lg
```

The thin plugin alone (no detection, for testing the inert path):

```bash
pip install -e packages/bulwark-presidio-scanner
```

## Configuration (environment)

| Variable | Default | Description |
|----------|---------|-------------|
| `BULWARK_PRESIDIO_ENTITIES` | conservative PII set | Comma-separated Presidio entity names to detect. `*` ⇒ all recognizers. |
| `BULWARK_PRESIDIO_SCORE_THRESHOLD` | `0.5` | Minimum confidence (0–1) to report a span. |
| `BULWARK_PRESIDIO_LANGUAGE` | `en` | Analyzer language code. |
| `BULWARK_PRESIDIO_SPACY_MODEL` | `en_core_web_lg` | spaCy model backing the NER engine. |

Default entity set: `CREDIT_CARD, CRYPTO, EMAIL_ADDRESS, IBAN_CODE, IP_ADDRESS,
LOCATION, MEDICAL_LICENSE, PERSON, PHONE_NUMBER, US_BANK_NUMBER, US_PASSPORT,
US_SSN`.

## Relationship to the builtin filter

Bulwark's builtin `output_redaction` scanner (priority 10) already redacts
high-confidence secrets and regex-matchable PII. This Presidio scanner runs
after it (priority 20) to catch **contextual** PII that pure regex cannot — for
example a person's name in a sentence, or a location. Run both.
