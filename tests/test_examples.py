"""
Tests for the runnable examples in ``examples/``.

These execute the zero-dependency examples end-to-end so the SDK snippets we
ship can never silently rot. The examples assert their own security behaviour
(input blocked, benign allowed, secrets redacted) — here we just drive their
``main()`` coroutines and require them to complete without error.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _load_example(name: str):
    """Import an example module by file path (examples/ is not a package)."""
    path = _EXAMPLES_DIR / name
    spec = importlib.util.spec_from_file_location(f"_example_{name.replace('.', '_')}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_examples_dir_has_readme():
    assert (_EXAMPLES_DIR / "README.md").is_file()


@pytest.mark.asyncio
async def test_quickstart_runs():
    """quickstart.py must block the injection, allow the benign input, and
    redact the leaked AWS key (its own asserts enforce this)."""
    module = _load_example("quickstart.py")
    await module.main()


@pytest.mark.asyncio
async def test_wrap_llm_runs():
    """wrap_llm.py must let benign calls through and raise SecurityError on
    malicious input (caught internally); completing means the contract held."""
    module = _load_example("wrap_llm.py")
    await module.main()


@pytest.mark.asyncio
async def test_langchain_example_is_ci_safe():
    """langchain_guard.py must exit cleanly (return 0) whether or not the
    optional langchain-core dependency is installed."""
    module = _load_example("langchain_guard.py")
    assert await module.main() == 0
