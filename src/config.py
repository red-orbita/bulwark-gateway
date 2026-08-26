"""Application configuration via environment variables and Docker secrets."""

import os
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(env_name: str, prefix: str = "BULWARK_") -> str | None:
    """Read a secret from a Docker secrets file if *_FILE env var is set."""
    file_path = os.getenv(f"{prefix}{env_name}_FILE") or os.getenv(f"{env_name}_FILE")
    if file_path:
        p = Path(file_path)
        if p.is_file():
            return p.read_text().strip()
    return None


class Settings(BaseSettings):
    """Bulwark Gateway configuration.

    All settings can be overridden via environment variables
    prefixed with BULWARK_ (e.g., BULWARK_PORT=9000).

    Secrets can be provided via Docker secret files:
      BULWARK_JWT_SECRET_FILE=/run/secrets/jwt_secret
      BULWARK_REDIS_PASSWORD_FILE=/run/secrets/redis_password
    """

    # Server
    # nosec B104: binding all interfaces is required so the proxy is reachable
    # inside its container/pod network namespace. External exposure is controlled
    # by Kubernetes Services/NetworkPolicies and the ingress layer, not this bind.
    host: str = "0.0.0.0"  # nosec B104
    port: int = 8080
    workers: int = 4
    debug: bool = False
    mode: str = "proxy"  # "proxy" or "sidecar"

    # Auth
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    # Asymmetric JWT (RS256/ES256) — enterprise mode
    # When set, takes precedence over jwt_secret for verification
    jwt_public_key_path: str = ""    # Path to PEM public key file
    jwt_private_key_path: str = ""   # Path to PEM private key (for token generation)
    jwt_jwks_url: str = ""           # JWKS endpoint URL (for external IdP integration)
    jwt_key_id: str = ""             # Key ID (kid) for key rotation
    jwt_jwks_ttl: int = 3600         # JWKS cache TTL in seconds (default 1h)
    # H-03: JWT audience/issuer for cross-service isolation (set to prevent admin→proxy reuse)
    jwt_audience: str = "bulwark-proxy"
    jwt_issuer: str = "bulwark-gateway"
    api_keys_enabled: bool = True
    # Comma-separated list of valid API keys (e.g., "key1,key2,key3")
    # If empty and api_keys_enabled=True, only JWT auth works
    api_keys: str = ""

    # Backend (upstream agent/LLM)
    backend_url: str = "http://localhost:11434"  # Default: local Ollama
    backend_timeout: float = 120.0

    # Policies
    policies_dir: Path = Path("config/policies")

    # Agent Registry (multi-backend routing)
    agents_config: Path = Path("config/agents.yaml")

    # IOC
    ioc_path: Path = Path("config/iocs.json")

    # IOC Feed API Keys (all optional — feeds with missing keys are skipped)
    urlhaus_key: str = ""
    threatfox_key: str = ""
    otx_key: str = ""
    abuseipdb_key: str = ""

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_rpm: int = 60  # requests per minute per tenant
    rate_limit_rpm_burst: int = 10

    # Redis (for distributed rate limiting, pattern sync, SIEM stats)
    redis_url: str | None = None
    redis_password: str | None = None  # Separate password for K8s (injected into URL)
    redis_tls_insecure: bool = False  # Skip TLS cert verification (self-signed certs)

    # Logging
    log_format: str = "json"  # "json" or "console"
    log_level: str = "INFO"

    # Security
    fail_mode: str = "closed"  # "closed" (block on error) or "open" (allow on error)
    cors_origins: List[str] = []  # Empty = no CORS; set explicitly via BULWARK_CORS_ORIGINS

    # Output filter — opt-in PII redaction (high-false-positive types, off by default)
    # Emails and phone numbers are frequently *legitimate* agent output (e.g. a
    # support bot returning a contact address). Redacting them unconditionally
    # breaks those flows, so redaction is gated behind explicit config. A tenant
    # with stricter requirements (e.g. healthcare) can enable it globally here.
    redact_email: bool = False   # Redact email addresses in LLM output ([REDACTED:EMAIL])
    redact_phone: bool = False   # Redact phone numbers in LLM output ([REDACTED:PHONE])

    # Allowed-request visibility (opt-in). By default only BLOCK and WARN verdicts
    # are recorded as browsable events; legitimate ALLOW traffic is only counted.
    # Enabling this records each allowed request as a (redacted, capped) event so
    # analysts can drill into passing traffic in the Security Events viewer. This
    # trades Redis memory + write volume for auditability — keep the cap modest.
    log_allowed: bool = False        # Record ALLOW verdicts as browsable events
    # Redis is only the *live buffer* for the Security Events viewer; the durable,
    # queryable history lives in the admin database (synced from these lists). This
    # cap bounds Redis memory per tenant per feed (block/warn and allowed). It must
    # stay comfortably above the per-sync event volume so nothing is evicted before
    # the admin sync drains it into the durable store.
    events_max_per_tenant: int = 1000

    # Multi-tenancy (Tier 2: Pod-level isolation)
    # Comma-separated list of tenant IDs this pod is allowed to serve.
    # Empty = serve all tenants (shared pool mode).
    # When set, requests for other tenants are rejected with 403.
    allowed_tenants: str = ""
    # JSON list or comma-separated tenant names with dedicated pods.
    # Used by the shared pool to route requests to dedicated proxy services.
    dedicated_tenants: str = ""
    # Kubernetes namespace for internal service discovery (dedicated pod routing)
    namespace: str = "bulwark-gateway"
    # Redis key prefix for tenant isolation (dedicated pods use tenant-scoped keys)
    redis_key_prefix: str = "bulwark"

    # Webhook alerts (comma-separated: "type|name|url" or just "url")
    webhook_alert_urls: str = ""

    # Scanner Pipeline
    scanners_dir: Path = Path("config/scanners")  # Drop-in scanner plugins directory
    scanners_pipeline_enabled: bool = True  # Use new scanner pipeline (vs legacy direct calls)

    # ML Scanner Settings (Phase 2+)
    ml_enabled: bool = False  # Master switch for ML-based scanners
    # SECURITY FIX (H-07): Default ml_blocking=True when ML is enabled.
    # Previously ml_blocking=False meant ML detections fired AFTER the request
    # was already forwarded to the backend — completely useless for blocking.
    ml_blocking: bool = True  # If True, ML scanners can block requests (adds latency)
    ml_block_threshold: float = 0.85  # Confidence threshold for ML to auto-block (H-08: lowered from 0.9)
    ml_warn_threshold: float = 0.6  # Confidence threshold for ML to warn (H-08: lowered from 0.7)
    ml_timeout_ms: int = 10000  # Max ML inference time in milliseconds (CPU: ~1-5s)
    ml_model_dir: Path = Path("models")  # Directory for ML model files

    # Input Guardrail DoS controls (DOS-04)
    # Hard cap on how many bytes of a single message the input guardrail will scan.
    # Oversized messages are truncated to a bounded overlapping-window reconstruction
    # whose total size never exceeds guardrail_max_scan_bytes. Bounds the aggregate
    # cost of running 400+ regex patterns on adversarially large inputs.
    guardrail_max_input_size: int = 8_000        # Per-message "oversized" threshold
    guardrail_max_scan_bytes: int = 16_000       # Absolute cap on reconstructed scan text
    # Per-message CPU budget for the regex loop. Sized comfortably ABOVE the worst-case
    # cost of scanning a full max_scan_bytes payload of benign text (~0.7s observed), so
    # the fail-closed budget path only trips on genuinely anomalous backtracking rather
    # than on legitimately large prose (e.g. long documents to summarize). With the
    # catastrophic-backtracking patterns rewritten and input capped at max_scan_bytes,
    # this doubles as a hard latency ceiling per message.
    guardrail_regex_budget_seconds: float = 1.5
    guardrail_max_concat_bytes: int = 16_000     # Cap on concatenated cross-message scan
    # Aggregate wall-clock budget for the per-message scan phase of inspect_messages.
    # A single request carries the full conversation history; a padded history of many
    # large turns must not pin a worker for seconds. Messages are inspected most-recent
    # first (the live attack surface) until this budget is spent; older overflow content
    # is still covered by the capped concatenated split-attack scan.
    guardrail_messages_budget_seconds: float = 2.0

    # RAG Guard (Phase 5)
    rag_enabled: bool = False  # Master switch for RAG scanners (retrieval + memory guard)

    # Multilingual Detection (Phase 3)
    multilingual_enabled: bool = False  # Master switch for language detection + multilingual patterns

    # Structured-output schema validation (opt-in, default off).
    # When enabled, the model-free SchemaValidator (OUTPUT_BLOCKING) is registered
    # in the scanner pipeline. It is INERT (returns ALLOW) for any agent that does
    # not declare `output_validation` in its policy — enabling the flag alone has
    # no behavioural effect until a per-agent schema is configured. jsonschema is a
    # core runtime dependency, so no extra install is required.
    schema_validation_enabled: bool = False

    # Embedding-based output relevance scoring (opt-in, default off).
    # When enabled, the RelevanceScanner (OUTPUT_ASYNC, fire-and-forget) is
    # registered in the scanner pipeline. It computes cosine similarity between
    # the user's question and the LLM response using the provisioned
    # `sentence-embeddings` ONNX model (no LLM call, off the hot path). It is
    # INERT (returns ALLOW) unless BOTH the model is provisioned AND the agent
    # declares `output_validation.relevance_check: true` in its policy, so
    # enabling the flag alone has no behavioural effect. Requires the
    # `sentence-embeddings` model (scripts/download-models.py --embeddings).
    relevance_scanning_enabled: bool = False

    # NLI-based output validation (opt-in, default off). Both scanners share the
    # provisioned `nli-classifier` ONNX model and run as OUTPUT_ASYNC
    # (fire-and-forget, off the hot path, no LLM call). Each stays INERT (ALLOW)
    # until the model loads AND the agent opts in via its output_validation policy
    # (hallucination_check / a RAG context for grounding). Requires the
    # nli-classifier model (scripts/download-models.py --nli).
    hallucination_scanning_enabled: bool = False
    grounding_scanning_enabled: bool = False

    # Multimodal (image) input scanning (opt-in, default off). When enabled the
    # VisionScanner (INPUT_ASYNC, fire-and-forget) is registered. Its shipped,
    # tested capability is a set of ZERO-dependency deterministic guards over
    # inline `data:image/...;base64` URIs found in text content — the
    # `allow_images` policy gate, the DoS size limit, base64 validation, and
    # magic-byte format-signature validation (MIME-confusion detection). The
    # OCR-based image-content layer stays INERT unless pillow + an OCR backend
    # are installed (they do not ship in the distroless / no-torch image), so the
    # scanner remains MaturityTier.EXPERIMENTAL. No LLM call, off the hot path.
    vision_scanning_enabled: bool = False

    # mTLS (inter-service communication: proxy ↔ admin)
    # When enabled, internal endpoints require a valid client certificate
    # signed by the trusted CA. External endpoints continue using JWT/API key.
    mtls_enabled: bool = False
    mtls_ca_cert_path: str = ""       # Trusted CA certificate for client cert verification
    mtls_server_cert_path: str = ""   # This service's server certificate
    mtls_server_key_path: str = ""    # This service's server private key
    mtls_client_cert_path: str = ""   # Client cert for outbound inter-service calls
    mtls_client_key_path: str = ""    # Client key for outbound inter-service calls
    mtls_crl_path: str = ""           # CRL file for certificate revocation (M-13)
    # SECURITY: Only trust X-Client-Cert-* headers from these proxy CIDRs.
    # If empty, header-based cert extraction is DISABLED (only direct TLS works).
    # Typical values: "10.244.0.0/16,10.96.0.0/12" (K8s pod/service CIDRs)
    mtls_trusted_proxy_cidrs: str = ""

    # OpenTelemetry Distributed Tracing
    tracing_enabled: bool = False  # Master switch — zero overhead when disabled
    tracing_endpoint: str = "http://localhost:4317"  # OTLP gRPC endpoint
    tracing_exporter: str = "otlp"  # "otlp", "zipkin", "console", "none"
    tracing_sample_rate: float = 1.0  # 1.0 = trace all, 0.1 = 10% sampling
    tracing_service_name: str = "bulwark-gateway-proxy"

    # === Correlation Engine (Phase 0/1) ===
    # Inline input↔output correlation: raise the risk state of a request's origin
    # (tenant / session / input-hash) when a suspicious INPUT is followed by a
    # sensitive OUTPUT in the same request, and confirm exfiltration by BLOCKing
    # the leaking response. This is enforcement-oriented (not forensic): the SIEM
    # remains the system of record for multi-source / cross-tenant correlation.
    #
    # Master switch. Off by default — zero cost on the hot path when disabled.
    correlation_enabled: bool = False
    # When True, a confirmed input→output exfiltration correlation BLOCKs the
    # response (replaces leaking content). When False, it only WARNs + records the
    # incident and elevates risk state (observe-first rollout). WARN-before-BLOCK.
    correlation_blocking: bool = False
    # LATENT/reserved (F4): input↔output correlation is strictly same-request, so a
    # request's input and its own output are inherently paired and NO time window is
    # enforced today (the proxy does not feed the correlator a detection timestamp).
    # Wiring one to the backend round-trip would false-negative on slow LLM responses
    # (elapsed ≈ backend latency, up to the backend timeout). Retained — accepted and
    # bounded — for a future cross-request/async correlator. See src/correlation/runtime.py.
    correlation_window_seconds: float = 30.0
    # Risk-state decay half-life (seconds). Elevated origin risk decays over time
    # so a single bad request does not permanently penalise a tenant/session.
    correlation_risk_decay_seconds: float = 900.0  # 15 min
    # Origin risk score at/above which the next requests from that origin are
    # hardened (WARN→BLOCK escalation eligibility). Bounded 0..10 scale.
    correlation_risk_block_threshold: float = 7.0
    # Origin risk score at/above which the origin is flagged as elevated (WARN).
    correlation_risk_warn_threshold: float = 4.0
    # Content-corroboration confidence (0..1) required to escalate a confirmed
    # input↔output correlation from WARN to BLOCK when blocking is enabled. A pure
    # category co-occurrence (suspicious input + sensitive output, no corroborating
    # content) scores low and stays WARN; a high-entropy secret leak or a critical
    # credential/model-theft output with lexical linkage scores high and BLOCKs.
    # This guards against false "confirmed exfiltration" hard-blocks. Lower it to
    # block more aggressively; raise it to require stronger content evidence.
    correlation_confidence_block_threshold: float = 0.5

    model_config = SettingsConfigDict(
        env_prefix="BULWARK_",
        env_file=".env",
        extra="ignore",
        secrets_dir="/run/secrets",  # Docker secrets mount point
    )


def _build_settings() -> "Settings":
    """Build settings with Docker secret file overrides.

    Reads *_FILE env vars pointing to /run/secrets/* (Docker secrets pattern).
    Falls back to direct env vars for local dev.
    """
    s = Settings()

    # JWT secret
    jwt_from_file = _read_secret_file("JWT_SECRET")
    if jwt_from_file:
        s.jwt_secret = jwt_from_file

    # API keys
    api_keys_from_file = _read_secret_file("API_KEYS")
    if api_keys_from_file:
        s.api_keys = api_keys_from_file

    # IOC feed keys
    for key_name in ("URLHAUS_KEY", "THREATFOX_KEY", "OTX_KEY", "ABUSEIPDB_KEY"):
        val = _read_secret_file(key_name)
        if val:
            setattr(s, key_name.lower(), val)

    # Redis password → inject into URL (supports redis:// and rediss:// schemes)
    redis_pw = _read_secret_file("REDIS_PASSWORD")
    if not redis_pw and s.redis_password:
        redis_pw = s.redis_password  # From BULWARK_REDIS_PASSWORD env var (K8s)
    if redis_pw and s.redis_url:
        scheme_match = "://" in s.redis_url and (
            s.redis_url.startswith("redis://") or s.redis_url.startswith("rediss://")
        )
        if scheme_match:
            # SECURITY FIX (VULN 1.7): URL-encode the password to prevent injection.
            # A password containing '@' could redirect the connection to a malicious host.
            from urllib.parse import quote as url_quote
            safe_pw = url_quote(redis_pw, safe="")
            if "@" not in s.redis_url:
                s.redis_url = s.redis_url.replace("://", f"://:{safe_pw}@")
            elif ":@" in s.redis_url:
                s.redis_url = s.redis_url.replace(":@", f":{safe_pw}@")

    return s


settings = _build_settings()


def validate_settings():
    """Validate critical security settings at startup."""
    # --- Asymmetric JWT validation (RS256/ES256) ---
    # If using asymmetric algorithms, validate key configuration BEFORE
    # checking the symmetric secret (asymmetric mode doesn't need jwt_secret).
    if settings.jwt_algorithm in ("RS256", "ES256"):
        if not settings.jwt_public_key_path and not settings.jwt_jwks_url:
            raise SystemExit(
                f"FATAL: JWT algorithm '{settings.jwt_algorithm}' requires either "
                f"BULWARK_JWT_PUBLIC_KEY_PATH or BULWARK_JWT_JWKS_URL to be set. "
                f"Without a public key source, token verification is impossible."
            )

        # Initialize asymmetric key management (fail-closed on error)
        from src.middleware.jwt_keys import initialize, JWTKeyError

        try:
            initialize(
                algorithm=settings.jwt_algorithm,
                public_key_path=settings.jwt_public_key_path,
                private_key_path=settings.jwt_private_key_path,
                jwks_url=settings.jwt_jwks_url,
                jwks_ttl=settings.jwt_jwks_ttl,
            )
        except JWTKeyError as e:
            raise SystemExit(f"FATAL: JWT key initialization failed: {e}")

        import logging
        logging.getLogger(__name__).info(
            f"JWT asymmetric mode enabled: algorithm={settings.jwt_algorithm}, "
            f"public_key={'configured' if settings.jwt_public_key_path else 'none'}, "
            f"jwks={'configured' if settings.jwt_jwks_url else 'none'}"
        )
        # Skip symmetric secret validation when using asymmetric mode
        return

    # --- Symmetric JWT validation (HS256) ---
    # SECURITY FIX (VULN 1.5): Expanded blocklist of known-insecure secrets
    # These are publicly documented in README, .env.example, and now in the pentest report
    insecure_secrets = {
        "change-me-in-production",
        "bulwark-jwt-dev-secret-change-in-prod",
        "bulwark-admin-change-me-in-production",
        "",
        "secret",
        "test",
        "dev",
        "admin",
        "password",
        "changeme",
    }
    jwt = settings.jwt_secret.lower().strip()

    # H-02: Check both blocklist AND entropy (minimum 32 bytes of randomness)
    is_insecure = jwt in insecure_secrets or len(settings.jwt_secret) < 32

    if is_insecure:
        if settings.debug:
            # SECURITY FIX: In debug mode, auto-generate a random secret instead of
            # allowing the insecure default. This prevents the attack vector where
            # debug=true + known secret = forge arbitrary tokens.
            import secrets as _secrets
            import logging
            generated = _secrets.token_hex(32)
            settings.jwt_secret = generated  # type: ignore[misc]
            logging.getLogger(__name__).warning(
                "INSECURE JWT_SECRET detected in debug mode — auto-generated random secret. "
                "Set BULWARK_JWT_SECRET to a strong value for persistent tokens."
            )
        else:
            raise SystemExit(
                "FATAL: BULWARK_JWT_SECRET is insecure. "
                "Set a strong secret (32+ chars of random data) via environment variable or Docker secret."
            )


# Validation is called explicitly by src/main.py at startup, not at import time.
# This allows admin service to import settings without proxy-specific validation failing.
