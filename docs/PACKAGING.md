# Release Packaging

Building or importing an image does not approve it for production. Each candidate
must pass the vulnerability and artifact gates in
[Release Verification](RELEASE-VERIFICATION.md), including unfixed vulnerabilities.

## Separate Runtime Locks

Do not install `requirements.lock` and `requirements-admin.lock` into the same
environment, either together or sequentially. They describe different service
runtimes and conflict on cachetools, FastAPI, Pydantic, pydantic-core,
pydantic-settings, Redis and Uvicorn. Sequential installs hide the conflict by
overwriting the first service's versions.

The release workflow's `test-runtime-locks` matrix installs proxy, proxy with
PostgreSQL, and admin dependencies in fresh Python 3.14 virtual environments.
Each uses hash verification, wheels only, `pip check`, exact installed-version
checks and import smoke checks. No test tooling is installed into these runtime
environments. All matrix rows must succeed before image publication.

Combined application tests cannot use both runtime locks. The deterministic
`tests/packaging_locks.py ci` composition keeps the **entire admin lock unchanged**
and adds only the proxy's existing JSON-schema dependency closure: attrs,
jsonschema, jsonschema-specifications, referencing and rpds-py. This is an explicit
CI runtime dependency set, not proxy runtime parity evidence. Every emitted
version and hash comes directly from the checked-in service locks. Unexpected
overlap fails rather than silently choosing a version. Separate runtime checks
avoid changing reviewed service dependencies merely to accommodate combined tests.

Python test tools and their dependencies are hash-locked in `requirements-test.lock`;
Ruff/mypy and their closure are in `requirements-lint.lock` (Linux amd64, CPython
3.13). `docker/requirements-test-cp314.lock` contains NumPy fixture wheels for both
CPython 3.13 and 3.14 on Linux amd64. CI installs these with the runtime composition
in one hash-enforced, wheels-only operation, followed by `pip check`. There is no
editable install or implicit build backend. Other platforms require reviewed wheel
hashes, not a source-build fallback. External Helm/Docker tools and runner images
have separate provisioning policies; this does not make the entire CI machine
reproducible. `scripts/validate-ci-tool-locks.py` verifies the Python composition in
a new isolated environment, without changing developer or service environments.

## Canonical Candidate Builds

`Dockerfile` (proxy) and `docker/Dockerfile.admin` (admin) are the canonical build
paths used by Compose and CI. Both use the reviewed CPython3.14/Wolfi base; there
is no second experimental application Dockerfile. The proxy excludes the admin
source tree. Both preserve UID/GID65532, exec-form entrypoints and healthchecks;
writable directories are mount points, not permission to disable read-only rootfs.
This prepares a release candidate, not an automatic production approval. The current
base is pinned to an amd64 digest and the public supplier offers a moving latest
track, not guaranteed free access to a fixed Python maintenance track. Review
future patch availability and support terms before adopting it. The inherited
base includes a pip wheel; do not describe it as containing no package-management
payload whatsoever. Final release approval still requires exact-artifact scans,
SBOMs, signature/provenance and deployment verification.

The pinned Python3.13 builder installs only hash-approved cp314 wheels into
`/opt/packages` using pip's target-version selection; no target extension runs in
the builder. `docker/verify_runtime.py` then executes in the actual 3.14 runtime:
checks exact locked versions, native imports, Requires-Python, active Requires-Dist
markers and transitive extras (including uvicorn[standard]). The metadata parser
is hash-locked and read-only-mounted only for this build step, not copied into the
final image. Missing/incompatible target dependencies fail the build. Lock copies
ship under `/usr/share/bulwark/locks` for inventory; the verifier script alone cannot
be rerun after build without provisioning its separate verification dependency.

Update the runtime digest in both Dockerfiles together. Dependabot groups the
root and `/docker` manifests into one container-base update. Offline tests enforce
full SHA-256 pinning, a shared runtime reference and the target-interpreter build
gate; they do not certify a particular digest. Each update still needs builds of
both roles, vulnerability scans and the release verification described above.

Compose and CI select `linux/amd64`; other architectures are not claimed supported
by this candidate. Setting INSTALL_ML or INSTALL_EMBEDDINGS to anything other than
false, or supplying a nonempty SKILLSPECTOR_COMMIT, fails explicitly. Optional
features require their own reviewed locks and runtime validation; no best-effort
source installation is allowed in the release profile.

The separate `docker/Dockerfile.candidate-tests` uses the existing CI dependency
composition, not the proxy service lock. Its test result establishes interpreter
compatibility for that composition, not independent parity of every service lock.
It takes explicit source-only build contexts for tests, scripts, Docker metadata,
Helm, workflows and examples. Never supply a context containing secrets or an
entire operational workspace. Host-only publication tests and live/native/model
fixtures require their own environments; report omissions rather than counting
them as passes.

## Operator Installation

Use the existing deterministic `packaging_locks.py ci` composition for the release
signer/verifier: the admin lock provides cryptography/Pydantic and the five-package
proxy supplement provides offline JSON Schema validation. No version or hash is
newly resolved, and neither shipped runtime lock changes. Example from the repository root,
with an independently provisioned wheelhouse (no network):

```sh
python3.13 -m venv .operator-venv
.operator-venv/bin/python -m pip install --no-index --find-links=/approved/wheelhouse \
  --only-binary=:all: --require-hashes -r /approved/operator.lock
.operator-venv/bin/python -m pip check
.operator-venv/bin/python tests/packaging_locks.py verify /approved/operator.lock
.operator-venv/bin/python scripts/verify-release.py --help
```

Prepare `/approved/operator.lock` from `python tests/packaging_locks.py ci` in the
approved provisioning process, and provision its wheels with hash verification.
This set is larger than a dedicated signing-only lock, but reuses the existing
tested composition without another dependency resolution. Execute operator scripts
with this Linux environment and the bundled schemas, never with the proxy runtime.

## PostgreSQL Proxy Variant

The default Dockerfile keeps `INSTALL_POSTGRES=false`: asyncpg, admin dependencies,
and signing libraries are not added. `requirements-postgres.lock` contains only
asyncpg 0.31.0 with **all the same hashes as the existing admin lock**. Install it
in the same pip invocation as the proxy lock, not as an overriding service lock.
Unknown build-argument values fail. Source builds are refused; absence of a
compatible hash-approved wheel is an error, not permission to fetch build tools.

For an approved build environment (these commands require provisioned images and
wheels or network access and were not executed during offline validation):

```sh
docker build --build-arg INSTALL_POSTGRES=true -t bulwark-gateway-proxy:postgres-candidate .
```

Release CI explicitly selects `INSTALL_POSTGRES=true`, with ML/embeddings disabled.
After publication, it pulls the **exact output digest** and runs the target Python
to import both asyncpg and its compiled protocol extension. The container has no
network, a read-only rootfs, no capabilities and no-new-privileges. Import/version
failure fails the build job and prevents downstream deployment/signing. The pushed
candidate itself is not deleted or considered an approved release on failure.

The proxy copies application source directly into `/app`, as before. It no longer
tries to build/install a project from only `pyproject.toml` without its source;
that step could fail discovery and fetched an unpinned isolated build backend.
The image entrypoint remains the existing Python launcher, not an installed CLI.

## Verification Limits

Offline tests check lock provenance/composition, overwrite detection, workflow
gates, shell/Python syntax, and both valid and invalid Docker argument branches
with the pip boundary replaced. They do not prove wheel availability, resolver
compatibility from artifact metadata, native ABI compatibility, a successful
container build, registry publication, or a live PostgreSQL connection. Those
require the clean CI installs and built-image import gate to run successfully.

AnyIO is pinned to the security-corrected 4.14.2 in both service locks. No current
CVE/maintenance claims are made from static inspection; rescan each exact image.
Both canonical builds prohibit source-build fallback and unreviewed optional
installs. Existing mutable PostgreSQL/smoke-test image tags
and the staging smoke test's unlocked httpx install also remain separate workflow
hardening gaps; no unverified replacement digest was invented.

Focused offline checks using a provisioned Python 3.13 project environment:

```sh
python -m pytest \
  tests/test_packaging_locks.py tests/test_delivery_workflow.py \
  tests/test_release_verification.py tests/test_release_signing.py -q --tb=short
python -m ruff check \
  tests/packaging_locks.py tests/test_packaging_locks.py tests/test_delivery_workflow.py
```

These checks alone do not prove installation from the CI locks, successful image
builds, passing vulnerability scans or live PostgreSQL behavior. Preserve separate
evidence for each release gate against the exact candidate artifacts.
