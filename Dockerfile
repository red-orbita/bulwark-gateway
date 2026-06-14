# ============================================================
# Sentinel Gateway — Proxy (Security Hot Path)
# Multi-stage build for minimal attack surface
# H-08 fix: Pin base image to SHA256 digest (prevents supply chain poisoning)
# ============================================================
FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9 AS builder

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
FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9 AS runtime

LABEL org.opencontainers.image.title="sentinel-gateway"
LABEL org.opencontainers.image.description="Security guardrail proxy for AI agents"
LABEL org.opencontainers.image.version="0.2.0"

# Security: non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -s /bin/false sentinel

WORKDIR /app

# Copy installed dependencies
COPY --from=builder /install /usr/local

# Copy application code
COPY src/ src/
COPY config/ config/

# Create data directories (models dir for ML, writable for download)
RUN mkdir -p data reports models shared/enrichment shared/siem && \
    chown -R sentinel:sentinel /app && \
    rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

USER sentinel

EXPOSE 8080

# Healthcheck using built-in Python (no curl dependency)
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"

# Production: configurable workers (default 4), no access log
ENV SENTINEL_WORKERS=4
CMD ["sh", "-c", "python -m uvicorn src.main:app --host 0.0.0.0 --port 8080 --workers ${SENTINEL_WORKERS} --access-log --log-level warning --no-server-header"]
