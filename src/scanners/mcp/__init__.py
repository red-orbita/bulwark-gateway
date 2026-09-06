"""
MCP (Model Context Protocol) threat-detection package.

Stdlib-only detection cores for MCP tool poisoning and least-privilege analysis,
plus the runtime ``McpToolScanner`` that enforces them on inbound tool
definitions in the proxy hot path. These cores are the single source of truth
shared by the admin SkillSpector pipeline (pre-deployment) and the proxy scanner
(runtime) — ``src`` never imports ``admin``.
"""

from src.scanners.mcp import mcp_poisoning, mcp_privilege
from src.scanners.mcp.scanner import McpToolScanner

__all__ = [
    "McpToolScanner",
    "mcp_poisoning",
    "mcp_privilege",
]
