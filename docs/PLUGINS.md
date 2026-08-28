# Creating and Publishing Plugins

A **plugin** packages a scanner as a self-contained, installable unit with its
own metadata (`bulwark-plugin.yaml`), lifecycle management, and — critically — a
**security sandbox**. This is the safe way to distribute and run third-party or
in-house detection logic in Bulwark Gateway.

Before reading this, make sure you understand the scanner interface — a plugin
*is* a scanner class plus a spec file. See [Writing a Custom Scanner](CUSTOM-SCANNERS.md).

> **Honesty note:** there is **no public plugin hub / marketplace / registry.**
> "Publishing" means distributing your plugin as a **local directory** or an
> **HTTPS Git repository** that operators install explicitly. The CLI accepts a
> `--source hub` argument, but it fails closed with a clear message — it is a
> reserved placeholder, not a working feature.

---

## 1. Anatomy of a Plugin

A plugin is a directory containing:

```
my-plugin/
├── bulwark-plugin.yaml     # spec (required, at the root)
├── scanner.py              # must define a class named `Scanner` (required)
├── tests/
│   └── test_scanner.py     # tests (recommended)
└── README.md               # docs (recommended)
```

Two hard requirements enforced by the manager:

1. `bulwark-plugin.yaml` at the plugin root (parsed into a `PluginSpec`).
2. `scanner.py` defining a class **named exactly `Scanner`** that subclasses
   `InputScanner` or `OutputScanner`, matching the `type` in the spec.

---

## 2. The Spec — `bulwark-plugin.yaml`

The spec is a Pydantic model (`src/plugins/spec.py`, `PluginSpec`). Fields:

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `name` | ✅ | str | kebab-case, 2–64 chars, starts with a letter (`^[a-z][a-z0-9\-]{1,63}$`) |
| `version` | ✅ | str | SemVer (e.g. `1.2.0`, `0.1.0-rc.1`) |
| `author` | ✅ | str | must be non-empty |
| `type` | ✅ | enum | `input_scanner`, `output_scanner`, or `enrichment` |
| `license` | | str | SPDX id, default `MIT` |
| `description` | | str | recommended (validator warns if empty) |
| `blocking` | | bool | default `false` — whether it runs in the blocking hot path |
| `requires` | | map | Python deps: `{ "package": "version-spec" }` |
| `models` | | list | ML models: `{ name, size, url }` each |
| `config` | | map | tunable params: `{ name, type, default, description }`, type ∈ `str/float/int/bool` |

Real example (`plugins/examples/input-dlp-scanner/bulwark-plugin.yaml`):

```yaml
name: input-dlp-scanner
version: 1.2.0
author: bulwark-community
license: GPL-3.0
description: >
  Data Leakage Prevention scanner for user INPUT. Blocks sensitive data
  (credit cards, IBANs, DNI/NIE, API keys, private keys, bulk PII).
type: input_scanner
blocking: false
requires: {}
models: []
config:
  block_credit_cards:
    name: block_credit_cards
    type: bool
    default: true
    description: Block messages containing valid credit card numbers (Luhn-validated)
  bulk_email_threshold:
    name: bulk_email_threshold
    type: int
    default: 3
    description: Number of email addresses that triggers a data dump alert
```

`validate_plugin_spec()` returns a list of human-readable errors for a bad spec
(invalid name/version, empty author, bad config param type, model missing
`url`/`size`, malformed `requires` keys). Installation refuses to proceed if
there are any.

---

## 3. Scaffold a New Plugin

The fastest start is the CLI scaffolder (invoked via the `bulwark-plugin`
console script declared in `pyproject.toml`, or `python -m src.plugins.cli`):

```bash
bulwark-plugin create my-plugin --output-dir ./plugins
```

This generates a ready-to-edit tree:

```
my-plugin/
├── bulwark-plugin.yaml   # input_scanner, v0.1.0, one float config param
├── scanner.py            # class Scanner(InputScanner) returning ALLOW (stub)
├── tests/test_scanner.py # two starter tests (benign ALLOW + info assertions)
└── README.md             # install/config/dev docs
```

Then implement your detection in `scanner.py`'s `Scanner.scan()`. The generated
scanner is a valid no-op (`Verdict.ALLOW`) — replace the `# TODO` with real
logic. See [Writing a Custom Scanner](CUSTOM-SCANNERS.md) §5–6 for the `scan()`
contract, event emission, and redaction.

> **Sandbox constraint (read §5 first):** plugin `scanner.py` runs inside a
> restricted sandbox. You **cannot** `import subprocess`, `socket`, `threading`,
> `pickle`, `ctypes`, `importlib`, use `eval`/`exec`/`__import__`, or touch frame
> internals. Stick to pure computation + the standard whitelisted modules
> (`re`, `json`, etc.). The DLP example is a good template — pure regex +
> algorithms, zero forbidden imports.

---

## 4. Validate and Security-Check Locally

Before installing, run the plugin `test` command — it loads the spec, validates
it, and runs the **same** static security analysis used at install time:

```bash
bulwark-plugin test ./my-plugin
```

It reports:

- spec fields + any spec validation errors,
- **security warnings** (regex pre-filter + AST analysis findings),
- whether `scanner.py` is present.

A non-empty security warning list means the plugin **will be rejected at
install** — fix the flagged code before proceeding.

You should also run the plugin's own unit tests (positive + negative cases are
required for any scanner):

```bash
cd my-plugin && pytest tests/ -v
```

---

## 5. The Security Model (why plugins are safe to run)

Plugins execute untrusted code, so the `PluginManager`
(`src/plugins/manager.py`) sandboxes them at **six** levels:

1. **AST static analysis at install time** — `analyze_plugin_source()` /
   `analyze_plugin_directory()` inspect every `.py` file; dangerous patterns
   block installation.
2. **Regex pre-filter** — a fast blocklist (`_DANGEROUS_PATTERNS`) catches
   blatant issues: `eval(`, `exec(`, `__import__(`, `os.system(`, `subprocess`,
   `pickle`, `ctypes`, `socket`, `threading`, `importlib`, `os.popen/fork`,
   frame-internals access (`f_globals`, `gi_frame`, `__subclasses__`, …).
3. **Restricted imports at runtime** — only whitelisted modules load while the
   plugin's code executes.
4. **Network blocked** during execution (no sockets).
5. **Filesystem restricted** — read-only, confined to the plugin's own directory.
6. **Execution timeout** (default ~5–10 s) + **decompression-bomb protection**
   on uploads.

Two enforcement points matter:

- **Install** (`_security_check`) — regex + AST on all `.py`; any finding ⇒
  install fails.
- **Load / run** (`get_scanner` → `SandboxedScanner`) — source is
  **re-validated by AST at load time** (defense-in-depth), the module is
  imported inside `sandbox.activate()`, and **every `scan()` call runs inside
  the sandbox**. If a plugin times out, attempts a sandbox escape
  (`PermissionError`/`ImportError`), or crashes, the wrapper returns
  **`Verdict.BLOCK`** — fail-closed. A malicious plugin cannot auto-crash to
  silently disable detection.

The full AST audit is also exposed programmatically:

```python
from pathlib import Path
from src.plugins.manager import PluginManager

mgr = PluginManager(plugin_dir=Path("plugins"))
audit = mgr.security_audit("my-plugin")   # StaticAnalysisResult
print(audit.safe, audit.risk_score, audit.findings)
```

---

## 6. Install, List, Enable/Disable, Uninstall

### Install from a local path

```bash
bulwark-plugin install ./my-plugin --source local
```

The manager validates the spec, runs the security check, and copies the plugin
into the plugin directory (default `plugins/`). It refuses if a plugin of the
same name is already installed.

### Install from a Git repository

```bash
bulwark-plugin install https://github.com/org/my-plugin.git --source git --branch main
```

Git installs are hardened and fail-closed at every step (`_install_from_git`):

- URL is validated **HTTPS-only**, with no shell/option injection, and DNS is
  resolved against private/loopback/link-local/reserved ranges to block SSRF and
  DNS-rebinding (`validate_git_url`).
- Branch name is injection-validated (`validate_git_branch`).
- Clone is shallow (`--depth 1`), non-interactive (`GIT_TERMINAL_PROMPT=0`), and
  time-boxed (30 s).
- The cloned tree runs through the **same** AST + regex security check as a local
  install before anything is copied in. The `.git` dir is dropped.

`bulwark-plugin.yaml` may be at the repo root or one directory deep.

### `--source hub`

Accepted but **not available** — there is no registry. The command fails closed
with an actionable message pointing you at `--source local` or `--source git`.

### Other commands

```bash
bulwark-plugin list                  # installed plugins (+ disabled marker)
bulwark-plugin disable my-plugin     # keep installed, stop loading it
bulwark-plugin enable  my-plugin     # re-enable
bulwark-plugin uninstall my-plugin   # remove from the plugin directory
```

Enabled/disabled state persists in `plugins/plugin-state.json`. A disabled
plugin is skipped by `get_scanner()` and never loaded.

---

## 7. Managing Plugins from the Admin API

The same lifecycle is available over the admin API (`admin/routes/plugins.py`,
session-authenticated), e.g. for a UI or automation:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/plugins/` | List installed plugins |
| GET | `/admin/plugins/{name}` | Get a plugin's spec |
| POST | `/admin/plugins/install` | Install from source |
| POST | `/admin/plugins/uninstall` | Uninstall |
| POST | `/admin/plugins/{name}/enable` | Enable |
| POST | `/admin/plugins/{name}/disable` | Disable |
| POST | `/admin/plugins/scaffold` | Create a template |
| POST | `/admin/plugins/{name}/security-check` | Run the AST security audit |

---

## 8. Publishing Checklist

Since distribution is Git/local (no registry), "publishing" is about making your
plugin trivially installable and auditable by an operator:

- [ ] `bulwark-plugin.yaml` valid — `bulwark-plugin test ./my-plugin` shows no
      spec errors.
- [ ] `bulwark-plugin test ./my-plugin` shows **no security warnings** (it will
      be rejected at install otherwise).
- [ ] `scanner.py` defines `class Scanner(...)` matching the spec `type`, using
      only sandbox-permitted operations (no forbidden imports / dynamic exec).
- [ ] Honest `MaturityTier` in `ScannerInfo` (default `EXPERIMENTAL`; earn `GA`).
- [ ] Positive **and** negative tests pass: `pytest tests/ -v`.
- [ ] `README.md` documents config params and install command.
- [ ] Pin any `requires`/`models` accurately (models need `url` + `size`).
- [ ] Push to an **HTTPS** Git repo (SSH/`git://` URLs are rejected).
- [ ] Tag a SemVer release so `--branch <tag>` installs are reproducible.

Consumers then install with:

```bash
bulwark-plugin install https://github.com/you/my-plugin.git --source git --branch v1.0.0
```

---

## 9. Related Docs

- [Writing a Custom Scanner](CUSTOM-SCANNERS.md) — the scanner interface a plugin implements.
- [Using Bulwark as a Library](SDK-LIBRARY-MODE.md) — run scanners in-process without a plugin.
- [Architecture](ARCHITECTURE.md) — where scanners sit in the request pipeline.
