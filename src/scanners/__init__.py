"""
Sentinel Scanners — Pluggable security scanner framework.

This package provides the protocol, pipeline, and discovery mechanisms
for all security scanners (input, output, enrichment). Both built-in
and third-party scanners implement the same protocol.

Architecture:
  - Blocking scanners: run in the hot path (<5ms budget)
  - Async scanners: run as fire-and-forget enrichment (no latency impact)

Usage:
  from src.scanners import ScannerPipeline, InputScanner, OutputScanner

  pipeline = ScannerPipeline()
  pipeline.register(MyCustomScanner(), priority=50)
"""

from src.scanners.protocol import (
    InputScanner,
    OutputScanner,
    ScanContext,
    ScannerInfo,
    ScannerType,
)
from src.scanners.pipeline import ScannerPipeline

__all__ = [
    "InputScanner",
    "OutputScanner",
    "ScanContext",
    "ScannerInfo",
    "ScannerPipeline",
    "ScannerType",
]
