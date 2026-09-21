# Contributing to Bulwark Gateway

Participation follows our [Code of Conduct](CODE_OF_CONDUCT.md). For suspected
vulnerabilities, use [private security reporting](SECURITY.md), not a public issue
or pull request. Bug reports and feature proposals use the issue templates.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/bulwark-gateway.git`
3. Create a branch: `git checkout -b feat/my-feature`
4. Install the hash-locked CI dependency composition described below
5. Make your changes
6. Run the tests, lint and type checks described below
7. Commit with conventional message: `feat: add new detection pattern`
8. Push and open a Pull Request

## Development Setup

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python tests/packaging_locks.py ci > .venv/ci-runtime.lock
python tests/packaging_locks.py constraints > .venv/ci-runtime.constraints
python -m pip install --only-binary=:all: --require-hashes \
  -r .venv/ci-runtime.lock -c .venv/ci-runtime.constraints \
  -r requirements-test.lock -r requirements-lint.lock \
  -r docker/requirements-test-cp314.lock
python -m pip check

# Run tests
python -m pytest tests/ -q --ignore=tests/test_admin_integration.py \
  --ignore=tests/test_postgres_parity.py --ignore=tests/test_postgres_release_contract.py

# Run linter
python -m ruff check src/ admin/ tests/

# Run type checker
python -m mypy src/ --ignore-missing-imports
python -m mypy admin/ --ignore-missing-imports
```

These tooling locks target Linux amd64 and Python 3.13; release containers use
Python 3.14. Do not install the complete proxy and admin locks together. See
[packaging](docs/PACKAGING.md) for the CI composition and separate runtime checks.
Container, PostgreSQL and optional model tests need separately provisioned
environments. Report skips explicitly; do not point destructive test fixtures at
an existing database. Use [deployment guidance](docs/DEPLOYMENT.md) for local services.

## Code Style

- Python 3.11+ with full type annotations
- Formatted and linted by [ruff](https://docs.astral.sh/ruff/)
- Pydantic models for all data structures
- Async/await throughout (no blocking I/O in handlers)

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new guardrail pattern for XSS detection
fix: resolve race condition in rate limiter
test: add coverage for GDPR export endpoint
docs: update deployment guide for external Redis
refactor: extract telemetry transports to separate modules
ci: add staging smoke test to pipeline
chore: update dependencies
```

## Security Rules

Before submitting code, review the public [security hardening guidance](docs/SECURITY-HARDENING.md)
and [known limitations](docs/LIMITATIONS.md). Key rules:

- Never use `eval()`, `exec()`, `pickle`, or dynamic code execution
- Never hardcode secrets — use env vars with `*_FILE` support
- All persistence through `get_database()` abstraction (no raw sqlite3)
- Fail-closed on error in security-critical paths
- All new patterns MUST have positive AND negative test cases

## Testing Requirements

- All new features must have tests
- Security-critical code requires positive (blocks attack) AND negative (allows legit) tests
- Target: 85%+ coverage on new code
- Run the applicable suites before submitting and list any unexecuted checks

## Pull Request Process

1. Ensure CI passes (tests, lint, type-check)
2. Update CHANGELOG.md if adding user-facing changes
3. Request review from a maintainer
4. Leave merging and release approval to maintainers

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0-or-later.
