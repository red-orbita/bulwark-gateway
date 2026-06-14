# Contributing to Sentinel Gateway

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/sentinel-gateway.git`
3. Create a branch: `git checkout -b feat/my-feature`
4. Install dependencies: `pip install -e ".[dev]"` and `pre-commit install`
5. Make your changes
6. Run checks: `make test && make lint && make type-check`
7. Commit with conventional message: `feat: add new detection pattern`
8. Push and open a Pull Request

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

# Run tests
pytest tests/ -q

# Run linter
ruff check src/ admin/ tests/

# Run type checker
mypy src/ --ignore-missing-imports

# Local stack (proxy + admin + redis)
docker-compose up -d
```

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

Before submitting code, review `.opencode/SECURE-CODING-STANDARDS.md`. Key rules:

- Never use `eval()`, `exec()`, `pickle`, or dynamic code execution
- Never hardcode secrets — use env vars with `*_FILE` support
- All persistence through `get_database()` abstraction (no raw sqlite3)
- Fail-closed on error in security-critical paths
- All new patterns MUST have positive AND negative test cases

## Testing Requirements

- All new features must have tests
- Security-critical code requires positive (blocks attack) AND negative (allows legit) tests
- Target: 85%+ coverage on new code
- Run the full suite before submitting: `pytest tests/ -q`

## Pull Request Process

1. Ensure CI passes (tests, lint, type-check)
2. Update CHANGELOG.md if adding user-facing changes
3. Request review from a maintainer
4. Squash commits on merge

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0-or-later.
