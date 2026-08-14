"""Regression test for /v2/scan IOC failure handling (H-3).

Previously an exception raised by the IOC manager during a V2 scan was
silently swallowed (`except Exception: pass`), which would make the scan
report "clean" without the IOC protection it promises. The fix logs a
warning so operators can detect the degradation.
"""

from unittest.mock import MagicMock

import src.main
import src.routes.v2.scan as scan_mod
from src.routes.v2.scan import ScanType, _run_scan


class _BoomIOC:
    """IOC manager stub whose check_content always fails."""

    def check_content(self, content):
        raise RuntimeError("ioc backend down")


def test_ioc_failure_is_logged(monkeypatch):
    # Force a benign input so the input guardrail returns a non-BLOCK verdict
    # and the IOC branch is actually exercised.
    monkeypatch.setattr(src.main.app.state, "ioc_manager", _BoomIOC(), raising=False)

    fake_logger = MagicMock()
    monkeypatch.setattr(scan_mod, "logger", fake_logger)

    result, _ = _run_scan("hello world", ScanType.INPUT, "tenant-x", "agent-y")

    # The IOC failure must be logged, not swallowed.
    fake_logger.warning.assert_called_once()
    assert fake_logger.warning.call_args.args[0] == "v2_scan_ioc_check_failed"
    # A benign input with a broken IOC check must not spuriously block.
    assert result.verdict.value in ("allow", "warn")


def test_ioc_disabled_does_not_log(monkeypatch):
    # When no IOC manager is registered, the branch is skipped entirely and
    # nothing is logged as an error.
    monkeypatch.setattr(src.main.app.state, "ioc_manager", None, raising=False)

    fake_logger = MagicMock()
    monkeypatch.setattr(scan_mod, "logger", fake_logger)

    _run_scan("hello world", ScanType.INPUT, "tenant-x", "agent-y")

    fake_logger.warning.assert_not_called()
