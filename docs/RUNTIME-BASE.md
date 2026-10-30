# Maintained Python 3.14 Runtime

The Linux amd64 release builds now assemble their runtime from a hash-locked
Wolfi package closure instead of tracking the public Chainguard Python image's
latest interpreter. This preserves CPython 3.14 and the SQLCipher cp314 wheel.
It is a Bulwark-maintained composition, not a Chainguard-maintained image product.

## Trust And Rebuilds

- `docker/wolfi-runtime.lock` fixes every APK filename/version and SHA-256, including
  transitive libraries. `docker/fetch_runtime.py` downloads only those files from
  the fixed HTTPS Wolfi repository, without redirects or ambient proxies.
- `docker/wolfi-APKINDEX.tar.gz` preserves the signed repository snapshot. Its
  SHA-256 is fixed in the fetcher, so tomorrow's mutable index cannot change the
  dependency solution. Keep this binary snapshot with the lock; do not regenerate
  it automatically during ordinary builds.
- A digest-pinned Wolfi builder supplies APK and trusted public signing keys.
  APK installs the local closure against the signed index with network and package
  scripts disabled. Signature/checksum failures are fatal; no untrusted-package
  bypass is used. Individual APKs rely on the authenticated repository index.
- The final stage is `scratch` plus the installed root, not the builder. Package
  metadata is preserved for Trivy/SBOM inventory. There is no shell or APK binary;
  UID/GID remains 65532. The standard runtime/native-import gates still apply.
- The build verifier compares the installed APK inventory with the full lock and
  rejects additional, missing or different-version packages. CI requires the
  build-supply-chain and dependency-floor regression suites to execute without skips.
- Python requires `py3-pip-wheel`; the patched wheel archive remains inventoried.
  Pip is not installed as an importable module. This is not a claim that the image
  contains no installer archive or could confine hostile Python code.

The closure currently uses Python `3.14.8_git20261021-r3`, glibc `2.44-r11`, CA
bundle `20261020-r0` and pip-wheel `26.2.2-r2`. It includes OpenSSL 4.0.3 libraries;
the Python ABI did not change. Only Linux amd64 is supported by this lock.

Rebuild with the normal `Dockerfile` / `docker/Dockerfile.admin` commands.
The test candidate uses the same closure. Network access is needed to retrieve
the exact APKs and Python wheels; upstream removal fails the build. For long-term
availability archive the reviewed artifacts in an approved immutable mirror.
Content/version reproducibility does not establish bit-for-bit OCI digest equality:
builder timestamps, metadata and build attestations may differ.

## Maintenance Gate

For each refresh, resolve the desired Python 3.14 package and CA bundle in an
isolated builder, review the complete dependency closure, record every package's
SHA-256 and preserve the matching signed index. Review key and builder-image
updates separately. Never silently migrate to a new Python minor version or
replace SQLCipher with plaintext SQLite to obtain a green build.

Required validation: offline lock/fetch tests, all runtime builds (including the
proxy PostgreSQL variant), native imports, real SQLCipher encrypted roundtrip,
application regressions and Trivy against each exact built artifact. Missing
artifacts, changed hashes, failed signatures, dependency drift, ABI errors or
fixable security findings block release. Re-run security scans regularly: a clean
scan is specific to its database/date, not a permanent guarantee or an audit.

The October 30 local candidate scans with Trivy 0.74.0 found no known OS or Python
package vulnerabilities in proxy/admin. This does not close GitHub alerts until
the change is reviewed, merged and the default-branch scan succeeds. No publishing,
deployment or risk acceptance is implied by these local tests.
