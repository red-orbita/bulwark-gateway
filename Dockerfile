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

FROM builder AS runtime-download
COPY docker/fetch_runtime.py docker/wolfi-runtime.lock docker/wolfi-APKINDEX.tar.gz /runtime-build/
RUN python /runtime-build/fetch_runtime.py /runtime-build/wolfi-runtime.lock /apks

FROM cgr.dev/chainguard/wolfi-base@sha256:88a20e2d017bd20cdc0cb3910de603e7bea9512a6c351a8dd3c9df212ab03d73 AS runtime-root
COPY --from=runtime-download /apks /apks/x86_64
RUN --network=none mkdir -p /rootfs/etc/apk/keys && cp /etc/apk/keys/*.pub /rootfs/etc/apk/keys/ && \
    apk --root /rootfs --initdb --no-network --no-cache --no-scripts \
    --keys-dir /etc/apk/keys --repositories-file /dev/null --repository /apks add $(cat /apks/x86_64/packages.txt)

FROM scratch AS runtime
COPY --from=runtime-root /rootfs/ /
COPY docker/wolfi-runtime.lock /usr/share/bulwark/wolfi-runtime.lock
COPY --from=builder --chown=65532:65532 /packages /opt/packages
COPY --from=builder --chown=65532:65532 /app /app
COPY --from=builder /locks /usr/share/bulwark/locks
ENV PYTHONPATH=/opt/packages PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PATH=/usr/bin:/bin SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
USER 65532:65532
LABEL org.opencontainers.image.title="bulwark-gateway" \
      org.opencontainers.image.base.name="scratch" \
      org.bulwark.release.profile="python314-amd64-rc"
RUN --mount=type=bind,from=builder,source=/verification,target=/verification ["python3", "/app/docker/verify_runtime.py", "proxy"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"]
ENTRYPOINT ["python3", "/app/docker/proxy_launcher.py"]
