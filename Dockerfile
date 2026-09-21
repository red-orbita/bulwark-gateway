# Bulwark proxy release-candidate profile: Linux amd64, CPython 3.14, non-root.
# Builder pip selects hash-approved cp314 wheels only; it never executes them.
# Runtime import/version gates below run in the actual target interpreter.
FROM python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS builder
WORKDIR /build
COPY requirements.lock requirements-postgres.lock ./
COPY docker/requirements-runtime-check.lock ./
RUN python -m pip install --no-cache-dir --target /verification --only-binary=:all: \
    --require-hashes -r requirements-runtime-check.lock
ARG INSTALL_POSTGRES=false
ARG INSTALL_ML=false
ARG INSTALL_EMBEDDINGS=false
RUN test "$INSTALL_ML" = false && test "$INSTALL_EMBEDDINGS" = false
RUN case "$INSTALL_POSTGRES" in \
      true) python -m pip install --no-cache-dir --target /packages --python-version 3.14 \
        --only-binary=:all: --require-hashes -r requirements.lock -r requirements-postgres.lock ;; \
      false) python -m pip install --no-cache-dir --target /packages --python-version 3.14 \
        --only-binary=:all: --require-hashes -r requirements.lock ;; \
      *) echo "INSTALL_POSTGRES must be true or false" >&2; exit 1 ;; \
    esac

RUN mkdir -p /app/data /app/reports /app/models /app/shared/enrichment /app/shared/siem /locks && \
    cp requirements.lock /locks/ && \
    if [ "$INSTALL_POSTGRES" = true ]; then cp requirements-postgres.lock /locks/; fi
COPY LICENSE LICENSING.md /app/
COPY src/ /app/src/
COPY config/ /app/config/
COPY docker/proxy_launcher.py docker/verify_runtime.py /app/docker/

FROM cgr.dev/chainguard/python@sha256:1206ffee8644e6338b3fc8b6e5dc384b03d91ad1df1d6b74fa4255544ac51ad2 AS runtime
COPY --from=builder --chown=65532:65532 /packages /opt/packages
COPY --from=builder --chown=65532:65532 /app /app
COPY --from=builder /locks /usr/share/bulwark/locks
ENV PYTHONPATH=/opt/packages PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
USER 65532:65532
LABEL org.opencontainers.image.title="bulwark-gateway" \
      org.opencontainers.image.base.name="cgr.dev/chainguard/python" \
      org.bulwark.release.profile="python314-amd64-rc"
RUN --mount=type=bind,from=builder,source=/verification,target=/verification ["python3", "/app/docker/verify_runtime.py", "proxy"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"]
ENTRYPOINT ["python3", "/app/docker/proxy_launcher.py"]
