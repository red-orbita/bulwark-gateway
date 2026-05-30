# Skill: Run Tests

## Purpose
Run the test suite, identify failures, and fix them.

## Workflow

1. **Run full suite**:
   ```bash
   source .venv/bin/activate && pytest -v
   ```

2. **If tests fail**:
   - Read the failure output carefully
   - Determine if it's a pattern issue (regex not matching) or logic issue
   - Fix the source code, NOT the test (unless the test expectation is wrong)
   - Re-run only the failing test: `pytest tests/<file>::<class>::<test> -v`
   - Then run full suite to check for regressions

3. **Run linting**:
   ```bash
   ruff check src/ tests/
   ```

4. **Run type checking**:
   ```bash
   mypy src/
   ```

5. **Common failure patterns**:
   - Regex doesn't match: test the regex in isolation with `re.search()`
   - Import error: check `__init__.py` files
   - Async test issues: ensure `@pytest.mark.asyncio` and `async def`
   - Pydantic validation: check model field types match

## Test File Mapping

| Source | Test |
|--------|------|
| `src/guardrails/input_guardrail.py` | `tests/test_input_guardrail.py` |
| `src/guardrails/output_filter.py` | `tests/test_output_filter.py` |
| `src/guardrails/tool_policy.py` | `tests/test_tool_policy.py` |
| `src/ioc/manager.py` | `tests/test_ioc.py` |
