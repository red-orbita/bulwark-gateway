# Release Signing And Verification

`scripts/verify-release.py` verifies an Ed25519-signed manifest and local artifact
bytes. It neither signs a production release nor fetches, installs or executes
artifacts. It invokes a bounded local schema-validation worker. Use the locked
operator environment described below; do not add
signing keys to the proxy image or repository.

The authenticated payload is `b"bulwark-release-manifest-v1\x00"` followed by the
exact manifest bytes. Detached signature and public key files contain hex encoding
of 64 and 32 bytes respectively. Provision the public key independently from the
package under inspection. A public key bundled by an attacker proves nothing.

Manifest schema (illustration; hashes/revision must be actual release values):

```json
{
  "schema_version": 1,
  "revision": "<full-40-character-commit>",
  "artifacts": [
    {"name": "proxy.oci.tar", "sha256": "<actual-sha256>", "size": 123},
    {"name": "sbom.json", "sha256": "<actual-sha256>", "size": 456}
  ]
}
```

```sh
python scripts/verify-release.py --manifest release.json --signature release.sig \
  --public-key /trusted/release.pub --artifacts /releases/candidate \
  --expected-revision <approved-full-commit>
```

The expected revision prevents accepting another correctly signed revision in its
place; it must come from the operator's approval process. A revoked-key list,
transparency log and automatic anti-rollback version policy are not implemented.
The verifier does not assert that the SBOM is complete or a scanner report is true.

Inputs are bounded regular files, symlinks at the final component are rejected,
artifact paths are single filenames opened relative to a pinned directory FD,
and hashes are computed incrementally. Limits: manifest 128 KiB, 128 artifacts,
4 GiB per artifact, 16 GiB total signed sizes. Output contains status,
revision, count, manifest hash and image references when present. Extra files not
listed are not approved.

This is point-in-time verification. Deployment must consume the verified bytes
from immutable, access-controlled storage; replacing a pathname afterward is not
prevented by a standalone verifier. Production instead supplies verified immutable
OCI digests to Helm, so changing a mutable tag cannot change the selected image.
No production keys were generated here.

## Production CI Gate

The workflow preserves the `BULWARK_PUBLISH_IMAGES`, `BULWARK_DEPLOY_STAGING` and
`BULWARK_DEPLOY_PRODUCTION` repository-variable opt-ins. All publication/deployment
jobs require a push; PRs cannot deploy. Production also requires a `v` tag and the
protected `production` environment. Staging remains the pre-existing unsigned
development path, not a signed-release acceptance path.
Staging now pins both repositories and exact build-output digests and uses atomic
Helm rollout; this removes mutable-tag selection but does not add production's
signature/scan approval to the staging path.

1. Unit tests, coverage evidence and PostgreSQL parity gate the build.
2. Buildx pushes proxy/admin candidates with SBOM and max provenance requested.
   Each action's actual `digest` output is exported, not a tag lookup. No `latest`
   tag is published. Candidates are not yet approved releases.
3. Production scans both exact `repository@sha256:...` references with Trivy
   before exposing signing or cluster credentials. Unknown, HIGH and CRITICAL
   findings, including unfixed findings, block the release. Scanner, network and
   authentication failures also stop the job; there is no bypass flag.
4. Trivy converts each successful scan (with `--list-all-pkgs`) into CycloneDX 1.7.
   `scripts/sign-release.py` validates both scans and the SBOM release profile,
   including image/config identities and equality of package PURL sets, hashes all
   six artifacts (two scans, two SBOMs, two database metadata files), then signs
   the manifest with Ed25519. Missing, oversized, stale or
   rejected evidence fails before reading the key; conversion failures stop CI.
5. `scripts/verify-release.py` independently checks signature, revision, both
   expected build images, scan/SBOM hashes, scan policy and SBOM profile. Only success can create
   `verified-images.json`; existing outputs are never overwritten.
6. Only then are cluster credentials decoded and Helm invoked. Verified repository
   and digest values are applied **after** operator values, with `--atomic` and no
   production tag fallback. Credentials are cleaned up even on failure.

The manifest uses the existing domain and schema version, extended with an
`images` object containing exactly `proxy` and `admin`. Existing offline manifests
without images still verify as local artifacts, but cannot pass the deployment
gate requiring both expected images. Both `proxy-scan.json` and `admin-scan.json`,
plus `proxy.cdx.json` and `admin.cdx.json`, are required, with a 16 MiB limit each.
Both `proxy-database.json` and `admin-database.json` are also mandatory, at most
8 KiB each, and their exact hashes are included in the signed manifest.
Image-bearing manifests without SBOMs no longer pass the release gate. Only Trivy `os-pkgs`/`lang-pkgs` results
without unknown, HIGH or CRITICAL vulnerabilities are accepted. This authenticates
what trusted CI reported, not whether a compromised scanner told the truth.
Each image report must include both OS analysis and Python package analysis
(`python-pkg`/`pip`). An OS-only or another-language-only clean report is not enough
to authorize a Python gateway release. This checks the reported analysis categories,
not completeness of the scanner's package inventory or database freshness.

SBOM validation first checks the official CycloneDX 1.7 Draft-07 schema, then the
narrower Trivy 0.74 Debian-or-Wolfi/Python image profile. The reported OS family,
OS result type and all OS package PURL namespaces must agree (`pkg:deb/debian/`
or `pkg:apk/wolfi/`). Unknown families or mismatches fail closed. Python packages
must use `pkg:pypi/` and the complete reported library set must match the scan.
Supporting Wolfi evidence does not itself approve a runtime migration.
All four required schema resources
and the Apache-2.0 license are bundled under `scripts/schemas/cyclonedx/`, from
specification release 1.7.1, commit `b29bae660048e0ad2fbc5f2972927b442ce951c4`.
Their exact SHA-256 hashes are checked on every invocation. Missing, modified or
symlinked resources fail closed. No remote reference retrieval is permitted and
the document cannot choose the validator through its `$schema` field.

Validation runs in a separate Linux process with 512 MiB address-space, 10 CPU
seconds and 15 seconds wall-time limits, no inherited credentials, and suppressed
diagnostics. Input limits include 16 MiB, 200,000 JSON nodes and depth 64; duplicate
keys and non-finite numbers are rejected. A timeout, absent dependency or worker
failure rejects the release before reading the signing key or writing Helm values.

Draft-07 `format` keywords use annotation semantics, not optional format-plugin
assertions. Structural constraints, patterns, enumerations and schema references
are validated. Conformance does not establish package authenticity, dependency
completeness, license compatibility, cryptographic validity of embedded signatures
or source-to-image provenance. The detached Ed25519 release signature and separate
CVE gate remain authoritative for their respective checks.

Only the manifest, signature, two scans, two SBOMs and two database metadata files are uploaded as
`signed-release-<commit>` (90-day retention). They retain `signed-release/` and
`release-scans/` directories. No private key, public trust anchor, kubeconfig or
Helm environment values are uploaded. Consumers must use an independently trusted
public key, never one supplied by downloaded evidence.

## Operator Provisioning

Use the deterministic operator composition (admin lock plus the existing proxy
JSON-schema dependency closure), never the two entire service locks together.
See [Release Packaging](PACKAGING.md) for offline
installation, runtime-matrix gates and the PostgreSQL proxy image variant.
Before enabling production, provision:

- Environment secret `BULWARK_RELEASE_SIGNING_KEY`: hex of the 32-byte Ed25519
  private seed delivered by the organization's approved key-management process.
- Environment variable `BULWARK_RELEASE_PUBLIC_KEY`: hex of the 32-byte public key,
  independently reviewed and distributed to release consumers.
- Required reviewers and protected tag rules for `production`; restrict who can
  modify the workflow, trust anchor, release tags and secrets.
- Registry read credentials and the existing production cluster/Helm secrets.
  Configure the registry namespace in `REGISTRY_URL`.

CI writes the seed only into a mode-0600 file inside a temporary mode-0700 runner
directory outside the checkout. It removes the raw value from the child environment
and supplies `BULWARK_RELEASE_SIGNING_KEY_FILE`. The signer has no inline-key
fallback, refuses symlinks/nonregular files, requires owner-only permissions and
rejects key files inside the checkout, scans or output directory. The output
directory must not exist, preventing reuse of a stale signature after failure.
No key generator or KMS client is added. Python cannot guarantee memory zeroization;
this software-key path does not offer KMS/HSM isolation. Use isolated ephemeral
runners; a compromised same-user runner remains outside this defense.

Operator invocation with actual approved values already in the environment:

```sh
python scripts/sign-release.py --revision "$APPROVED_REVISION" \
  --proxy-image "$PROXY_IMAGE" --admin-image "$ADMIN_IMAGE" \
  --artifacts "$SCAN_DIRECTORY" --public-key "$TRUSTED_PUBLIC_KEY_FILE" \
  --output "$NEW_SIGNED_DIRECTORY"
python scripts/verify-release.py --manifest "$NEW_SIGNED_DIRECTORY/release.json" \
  --signature "$NEW_SIGNED_DIRECTORY/release.sig" \
  --public-key "$TRUSTED_PUBLIC_KEY_FILE" --artifacts "$SCAN_DIRECTORY" \
  --expected-revision "$APPROVED_REVISION" \
  --expected-proxy-image "$PROXY_IMAGE" --expected-admin-image "$ADMIN_IMAGE" \
  --helm-values "$NEW_VERIFIED_VALUES_FILE"
```

## Pins And Coverage

Action pins were checked through read-only GitHub API calls. The existing
`docker/build-push-action` SHA did not exist; it was replaced with the actual
`v5.3.0` commit `2cdde995de11925a030ce8070c3d77a52ffcf1c0`. Other actions reuse
existing verified pins. Trivy 0.74.0's Linux-64bit archive is verified **before
extraction** against its GitHub release asset digest:
`sha256:2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a`.
The vulnerability database is fetched at scan time, not a reproducible snapshot.
Production CI checks its metadata after each scan, before signing credentials are
exposed: version 2, timezone-aware dates, update age at most 24 hours, no future
update/download beyond five minutes clock tolerance, and an unexpired NextUpdate.
Missing or invalid metadata stops the job. Per-image `*-database.json` files are
retained alongside scan evidence and their hashes are signed. They are assertions
from the trusted scanner workflow, not cryptographic attestations from the database
publisher. The signer checks freshness before accessing its key; scan CreatedAt
must be valid and consistent with the database download. Verification with expected
image arguments (the deployment path) requires current evidence again. Historical
verification without expected images validates the dates as of scan time, not
current deployment eligibility. A fresh scan is required for later deployments
once the 24-hour/NextUpdate window expires; there is no stale-evidence bypass flag.
The Helm action is pinned; its upstream tool-download behavior has not been
replaced with a new checksum-provisioning mechanism in this change.

P1 publishes `coverage.json` with JUnit using **stdlib `trace`**, without installing
`coverage`/`pytest-cov` or editing locks. The denominator enumerates bytecode
executable lines in every Python file under `src`, `admin` and `scripts`, including
unexecuted files and nested code. Empty coverage fails the step, and test failures
retain their exit status. Release security suites must execute without skips.

This is current-process line evidence, not branch coverage, subprocess coverage,
PostgreSQL-job coverage or proof of complete security coverage. No global percentage
threshold is claimed. A locked coverage toolchain and reviewed per-component
thresholds remain explicit acceptance work; trace semantics differ from coverage.py.
The report generator has tests for unexecuted files, nested code and empty evidence.

## Acceptance Still Required

Historical pre-SBOM verification: 78 focused tests passed; stdlib trace reported 98% line
coverage for the signer and 96% for the verifier. Tests use ephemeral test keys
and synthetic inert reports only. No dependencies were installed, real release
signed, image built, service started or remote configuration changed in this work.

Remote CI has **not** been run. Before accepting production, retain:

- Green required unit/PostgreSQL checks with JUnit, skip checks and `coverage.json`;
  triage existing broader-suite failures instead of suppressing them.
- Successful builds and scans against the actual returned OCI digests. Inspect
  real Trivy report compatibility, SBOM and provenance. The strict vulnerability
  policy may intentionally block current base-OS findings.
- Protected-environment approval, trusted-key provisioning and a signed bundle
  independently verified. Test bad keys, tampered reports, wrong digests and scanner
  failures using test keys in a nonproduction validation environment; none may reach
  cluster credentials or Helm.
- Rendered and running proxy/admin/init-container image references matching the
  verified digests, including dedicated tenants. Optional third-party images are
  outside this two-image manifest and need separate review.

OCI-native signatures, KMS/HSM or OIDC signing, transparency/revocation, anti-rollback
policy, long-term release storage and evaluator onboarding remain outside this
software Ed25519 implementation.
