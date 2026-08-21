# Licensing

Bulwark Gateway is **open source**, released under the **GNU General Public
License, version 3.0 or (at your option) any later version
(GPL-3.0-or-later)**. The full text is in [`LICENSE`](./LICENSE).

Self-host it, study it, modify it, redistribute it — for free.

---

## What the GPL Gives You

- **Run** the software for any purpose.
- **Study and modify** the source code.
- **Redistribute** copies, original or modified.

In exchange, the GPL asks (in summary — the license text controls):

- If you **distribute** the software or a modified version, make the **complete
  corresponding source code** available to your recipients under the same
  GPL-3.0-or-later terms.
- **Preserve** copyright and license notices.
- License derivative works you distribute under GPL-3.0-or-later as well.

For the vast majority of users — self-hosting internally, evaluating,
researching, or building GPL-compatible open-source software — this is all you
need, at no cost.

> **Note on network use.** The GPL's copyleft is triggered by *distribution*, not
> by running the software as a hosted service. If you modify Bulwark Gateway and
> offer it only as a SaaS without distributing binaries, the GPL does not, by
> itself, require you to publish your changes. The project may adopt the
> **AGPL-3.0-or-later** in the future to close this gap.

---

## Contributions

Bulwark Gateway is currently maintained by a single copyright holder. To keep the
project sustainably and consistently licensed as it grows, contributions are
accepted under the [Contributor License Agreement](./CLA.md). The CLA lets you
**keep the copyright to your work** while granting the project the rights it needs
to distribute it. Signing takes one line in your first pull request.

---

## Third-Party Components

Bulwark Gateway depends on third-party open-source packages, each under its own
license. To the maintainer's knowledge, all runtime and admin dependencies are
under permissive licenses (MIT, BSD, Apache-2.0, PSF, HPND) or weak-copyleft
licenses (e.g., MPL-2.0 for `certifi`) that are compatible with distribution under
GPL-3.0-or-later. The optional `skill-scanner` extra pulls in `skillspector`
(NVIDIA); verify its terms before enabling that optional component in a
redistribution context. Each dependency remains governed by its own license.

---

<sub>The GPL doesn't fit your use case (e.g. embedding in a closed-source product
you distribute)? Reach out to the maintainer through the contact channel in the
repository and we can talk about alternative terms.</sub>

<sub>*This document is informational and is not legal advice. The
[`LICENSE`](./LICENSE) file is the controlling legal document.*</sub>
