# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately using GitHub's
[Report a vulnerability](https://github.com/red-orbita/bulwark-gateway/security/advisories/new)
form. Private vulnerability reporting is enabled for this repository. A GitHub
account is required. Do not open a public issue or pull request containing an
undisclosed exploit, credentials, customer data or private infrastructure details.

Include the affected version or commit, image digest if applicable, deployment
mode, prerequisites, expected security boundary and a minimal reproduction using
synthetic data. Explain the observed impact and any known mitigation. Sanitized
logs are useful; never send live tokens, passwords, private keys or personal data.
If credentials have been exposed, revoke or rotate them rather than posting them.

If the private form is unavailable, open an issue titled "Security contact
request" with no vulnerability details and ask a maintainer for a private route.
Public issues are not confidential. Wait for that route before sharing details.

## Maintenance Scope

Security fixes are developed against the current `master` branch. Include reports
against older releases too, but fixes may require upgrading. There is currently
no guaranteed LTS or backport schedule. A version label, passing CI, or a clean
scan alone does not constitute production approval. See
[release verification](docs/RELEASE-VERIFICATION.md) and
[known limitations](docs/LIMITATIONS.md).

## Handling and Disclosure

Maintainers will assess reports, request additional information where necessary,
and coordinate remediation and disclosure through the private report. Responses
are best effort; no response-time SLA or bounty is promised. Agree on a disclosure
plan before publishing exploit details. Reporter credit is provided with consent.

Test only systems you own or are explicitly authorized to assess. This policy
does not authorize testing third-party deployments, accessing other tenants'
data, service disruption or social engineering.

Ordinary bugs, documentation requests and feature proposals belong in the public
[issue tracker](https://github.com/red-orbita/bulwark-gateway/issues).
