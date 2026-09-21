# CycloneDX Schema Bundle

Unmodified data from CycloneDX specification release 1.7.1, commit
`b29bae660048e0ad2fbc5f2972927b442ce951c4`:
https://github.com/CycloneDX/specification/tree/b29bae660048e0ad2fbc5f2972927b442ce951c4

Copyright OWASP Foundation. Redistributed under the bundled Apache-2.0 `LICENSE`.
The upstream root contains no separate NOTICE file at this revision.
The JSF schema retains its upstream attribution to Anders Rundgren and the
OpenKeyStore project in its `$comment`; SPDX attribution is retained in its schema.

`bom-1.7.schema.json` and all three external schema dependencies are preserved
byte-for-byte. SHA-256 pins live in `scripts/release_sbom_schema.py` and are checked
on every validation. `scripts/update-cyclonedx-schemas.py` is an explicit maintainer
retrieval tool; it uses the pinned commit and hashes, refuses overwrite and is never
called by validation or production CI. To update, review upstream changes, references,
license and hashes together, then provision into a fresh directory and test.

The validator uses Draft-07 with format keywords as annotations, not assertions.
It validates structural constraints, patterns, enumerations and all references.
Schema conformance does not verify publisher signatures, package authenticity,
license compatibility, dependency completeness or vulnerability safety. Bulwark's
image/inventory and vulnerability gates remain separate and mandatory.
