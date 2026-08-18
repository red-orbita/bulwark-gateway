# ============================================================
# Bulwark Gateway — Proxy (Security Hot Path)
# Multi-stage build for minimal attack surface
# H-08 fix: Pin base image to SHA256 digest (prevents supply chain poisoning)
# ============================================================
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS builder

WORKDIR /build

COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps --prefix=/install -r requirements.lock && \
    pip install --no-cache-dir --prefix=/install .

# ML dependencies (optional, controlled by build args)
ARG INSTALL_ML=false
ARG INSTALL_EMBEDDINGS=false
RUN if [ "$INSTALL_ML" = "true" ]; then \
      pip install --no-cache-dir --prefix=/install \
        "onnxruntime>=1.17" "tokenizers>=0.15" "numpy>=1.26"; \
    fi
RUN if [ "$INSTALL_EMBEDDINGS" = "true" ] || [ "$INSTALL_ML" = "true" ]; then \
      pip install --no-cache-dir --prefix=/install \
        --index-url https://download.pytorch.org/whl/cpu \
        "torch>=2.2" && \
      pip install --no-cache-dir --prefix=/install \
        "sentence-transformers>=2.6" || \
      echo "WARNING: torch/sentence-transformers install failed (non-fatal)"; \
    fi

# ============================================================
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS runtime

LABEL org.opencontainers.image.title="bulwark-gateway"
LABEL org.opencontainers.image.description="Security guardrail proxy for AI agents"
LABEL org.opencontainers.image.version="0.4.3"

# SECURITY: patch fixable OS CVEs not yet baked into the pinned base digest.
# We upgrade ALL installed OS packages to the latest security-patched versions
# available in the pinned base's Debian (trixie) apt snapshot. This clears the
# fixable Trivy findings across perl(-base), openssl, ncurses, glibc (libc6),
# libsqlite3, tar, gzip, bzip2, zlib1g, libacl1, libattr1, libpam*, util-linux
# and systemd libraries in one deterministic layer. CVEs with no released
# Debian fix remain until upstream ships one (expected).
# Runtime stage only — the builder layer is discarded, and the final image is
# what SCA/Trivy scans. Non-root + read-only rootfs still hold at runtime
# (apt cannot write once the container starts).
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Security: non-root user
RUN groupadd -r bulwark && useradd -r -g bulwark -s /bin/false bulwark

WORKDIR /app

# Copy installed dependencies
COPY --from=builder /install /usr/local

# Copy application code
COPY src/ src/
COPY config/ config/
COPY docker/entrypoint-proxy.sh /app/docker/entrypoint-proxy.sh

# Create data directories (models dir for ML, writable for download)
RUN mkdir -p data reports models shared/enrichment shared/siem && \
    chmod 0555 /app/docker/entrypoint-proxy.sh && \
    chown -R bulwark:bulwark /app && \
    rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 && \
    rm -rf /usr/local/lib/python3.12/site-packages/pip \
           /usr/local/lib/python3.12/site-packages/pip-*.dist-info

USER bulwark

EXPOSE 8080

# Healthcheck using built-in Python (no curl dependency)
# SECURITY FIX (APT-19): Wrapped in try/except to suppress stack traces on failure
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
try: urllib.request.urlopen('http://127.0.0.1:8080/health'); \
except: sys.exit(1)"

# SECURITY FIX (APT-13): Use exec-form entrypoint for proper signal handling.
# Shell form invokes /bin/sh as PID 1 which doesn't forward SIGTERM properly,
# delaying graceful shutdown and leaving zombie processes.
# GAP-A: the entrypoint script derives uvicorn --workers from BULWARK_WORKERS so
# the real worker count matches the rate limiter's per-worker divisor. The
# script uses `exec`, preserving the APT-13 signal-handling guarantee (uvicorn
# becomes PID 1).
ENTRYPOINT ["/app/docker/entrypoint-proxy.sh"]
