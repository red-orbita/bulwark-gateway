# ============================================================
# Bulwark Gateway — Proxy (Security Hot Path)
# Distroless multi-stage build for MINIMAL attack surface.
#
# Runtime is Google Distroless (gcr.io/distroless/python3-debian13): no shell,
# no apt, no package manager, no coreutils — only Python + its runtime libs.
# This removes the post-exploitation toolkit (/bin/sh, curl, cat, ...) that
# reverse shells and recon rely on, and shrinks the image dramatically.
#
# Security properties preserved from the previous Debian-slim build:
#   - Non-root:      runs as the distroless `nonroot` user (UID 65532).
#   - Read-only FS:  compatible (all writable paths are mounted volumes/tmpfs).
#   - Pinned bases:  both stages pinned by SHA256 digest (supply-chain: H-08).
#   - Reproducible:  deps installed with --require-hashes from requirements.lock.
#   - Signal safety: proxy_launcher.py os.execv's into uvicorn (uvicorn = PID 1).
#
# Debian 13 (trixie) base is used instead of Debian 12 (bookworm): its package
# snapshot is fresh, so `trivy --ignore-unfixed` reports ~1 fixable OS CVE vs
# ~60 on the stale bookworm interpreter. Python is fixed at 3.13 to match the
# distroless python3-debian13 runtime ABI (pyproject requires-python >= 3.11).
# The builder MUST be the same 3.13/Debian 13 (trixie) toolchain so compiled
# wheels and the venv are ABI-compatible.
# ============================================================
FROM python:3.13-slim-trixie@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS builder

WORKDIR /build

# Build into an isolated virtual environment we can copy wholesale into the
# distroless runtime. The runtime uses distroless's own python3.13 with
# PYTHONPATH pointing at this venv's site-packages (same Python version = ABI
# compatible); the venv's bin/ scripts are never executed.
ENV VENV=/opt/venv
RUN python -m venv "$VENV"
ENV PATH="$VENV/bin:$PATH"

COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock && \
    pip install --no-cache-dir --no-deps .

# ML dependencies (optional, controlled by build args) — installed into the venv.
ARG INSTALL_ML=false
ARG INSTALL_EMBEDDINGS=false
RUN if [ "$INSTALL_ML" = "true" ]; then \
      pip install --no-cache-dir \
        "onnxruntime>=1.17" "tokenizers>=0.15" "numpy>=1.26"; \
    fi
RUN if [ "$INSTALL_EMBEDDINGS" = "true" ] || [ "$INSTALL_ML" = "true" ]; then \
      pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        "torch>=2.2" && \
      pip install --no-cache-dir \
        "sentence-transformers>=2.6" || \
      echo "WARNING: torch/sentence-transformers install failed (non-fatal)"; \
    fi

# Remove pip/setuptools/wheel from the venv so they are never shipped to runtime
# (reduces post-exploitation surface — there is no package manager in the image).
RUN pip uninstall -y pip setuptools wheel 2>/dev/null || true

# Assemble the final /app tree here (distroless has no shell to mkdir/chown at
# runtime). Ownership is set to the distroless nonroot UID (65532) via the COPY
# --chown in the runtime stage below.
WORKDIR /app
COPY src/ src/
COPY config/ config/
COPY docker/proxy_launcher.py docker/proxy_launcher.py
# Writable runtime directories (data, model downloads, enrichment/siem spool).
RUN mkdir -p data reports models shared/enrichment shared/siem

# ============================================================
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:f3d5ddc6c64a019fe520e7f005f2880be21e6afc461b10a3c15ef2e4edc71e33 AS runtime

LABEL org.opencontainers.image.title="bulwark-gateway"
LABEL org.opencontainers.image.description="Security guardrail proxy for AI agents"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.base.name="gcr.io/distroless/python3-debian13"

# Virtual environment (third-party deps) + application tree, owned by nonroot.
COPY --from=builder --chown=65532:65532 /opt/venv /opt/venv
COPY --from=builder --chown=65532:65532 /app /app

# Resolve imports from the venv's site-packages using distroless's python3.13.
# PYTHONDONTWRITEBYTECODE keeps the read-only rootfs clean; unbuffered logs.
ENV PYTHONPATH=/opt/venv/lib/python3.13/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Distroless already runs as nonroot (UID 65532); declared explicitly.
USER 65532:65532

EXPOSE 8080

# Exec-form healthcheck (distroless has no /bin/sh, so shell-form CMD is invalid).
# Uses stdlib urllib; a raised exception exits non-zero => container unhealthy.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]

# Exec-form entrypoint: distroless's python3 runs the launcher, which derives the
# worker count from BULWARK_WORKERS and os.execv's into uvicorn (uvicorn => PID 1
# for correct SIGTERM/graceful-shutdown handling).
ENTRYPOINT ["python3", "/app/docker/proxy_launcher.py"]
