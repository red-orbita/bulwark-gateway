"""
SkillSpector Enrichment Scanner — Async background skill analysis.

Invoked as part of the enrichment pipeline AFTER the hot path decision.
Provides additional security signal for agent tool calls by running
SkillSpector analysis on tool definitions seen in responses.

This is advisory only — never blocks requests in the hot path.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
from typing import Optional

from .base import BaseEnrichmentScanner, EnrichmentResult, EnrichmentStatus

logger = logging.getLogger(__name__)

# Only activate if explicitly enabled (heavy dependency)
SKILL_ENRICHMENT_ENABLED = os.getenv("SENTINEL_SKILL_ENRICHMENT_ENABLED", "false").lower() == "true"
SKILLSPECTOR_TIMEOUT = int(os.getenv("SENTINEL_SKILLSPECTOR_ENRICHMENT_TIMEOUT", "30"))


class SkillEnrichmentScanner(BaseEnrichmentScanner):
    """Background enrichment scanner using SkillSpector for tool call analysis.

    Examines tool definitions in LLM responses for potential security issues:
    - Tool poisoning patterns
    - Excessive permissions in tool schemas
    - Hidden instructions in tool descriptions
    - Data exfiltration via tool arguments

    This scanner runs asynchronously and NEVER impacts request latency.
    """

    name = "skill_enrichment"
    timeout_ms = 30_000.0  # 30s — SkillSpector can be slow

    def __init__(self) -> None:
        self._available: Optional[bool] = None
        self._mode: str = "unavailable"

    @property
    def available(self) -> bool:
        if self._available is None:
            self._detect()
        return self._available or False

    def _detect(self) -> None:
        """Check if SkillSpector is importable or CLI available."""
        if not SKILL_ENRICHMENT_ENABLED:
            self._available = False
            self._mode = "disabled"
            return

        try:
            from skillspector import graph as _  # noqa: F401
            self._available = True
            self._mode = "api"
            return
        except ImportError:
            pass

        if shutil.which("skillspector"):
            self._available = True
            self._mode = "cli"
            return

        self._available = False
        self._mode = "unavailable"
        logger.info("skill_enrichment_scanner unavailable (skillspector not installed)")

    async def score(self, text: str, request_id: str) -> EnrichmentResult:
        """Analyze text for tool-related security patterns.

        Extracts tool definitions/calls from the text and runs SkillSpector
        analysis if tool-related content is detected.
        """
        if not self.available:
            return EnrichmentResult(
                scanner=self.name,
                status=EnrichmentStatus.ERROR,
                detail="skillspector not available",
            )

        # Only scan if text contains tool-like structures
        if not self._has_tool_content(text):
            return EnrichmentResult(
                scanner=self.name,
                status=EnrichmentStatus.CLEAN,
                confidence=0.0,
                detail="no tool content detected",
            )

        # Write content to temp file and scan
        try:
            result = await self._run_scan(text, request_id)
            return result
        except Exception as e:
            logger.warning(
                "skill_enrichment_error",
                extra={"request_id": request_id, "error": str(e)},
            )
            return EnrichmentResult(
                scanner=self.name,
                status=EnrichmentStatus.ERROR,
                detail=str(e),
            )

    def _has_tool_content(self, text: str) -> bool:
        """Quick heuristic: does text contain tool definitions or calls?"""
        indicators = [
            '"function"', '"tool_call"', '"type": "function"',
            "tool_calls", "function_call", "parameters",
            "inputSchema", "tool_choice",
        ]
        text_lower = text.lower()
        return any(ind.lower() in text_lower for ind in indicators)

    async def _run_scan(self, text: str, request_id: str) -> EnrichmentResult:
        """Execute SkillSpector scan on extracted content."""
        # Create temp file with content
        content_hash = hashlib.sha256(text.encode()).hexdigest()[:12]
        suffix = f"_skill_{content_hash}.json"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, dir="/tmp"
        ) as f:
            # Wrap content as a skill-like structure for SkillSpector
            skill_doc = {
                "name": f"runtime-tool-{content_hash}",
                "description": "Tool definition extracted from LLM response",
                "content": text[:10000],  # Cap at 10KB
                "request_id": request_id,
            }
            json.dump(skill_doc, f)
            tmp_path = f.name

        try:
            if self._mode == "api":
                return await self._scan_api(tmp_path)
            else:
                return await self._scan_cli(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    async def _scan_api(self, path: str) -> EnrichmentResult:
        """Run scan via Python API in thread pool."""
        from skillspector import graph

        loop = asyncio.get_event_loop()
        raw = await loop.run_in_executor(
            None,
            lambda: graph.invoke({"input_path": path, "output_format": "json"}),
        )
        return self._parse_output(raw)

    async def _scan_cli(self, path: str) -> EnrichmentResult:
        """Run scan via CLI subprocess."""
        cli_path = shutil.which("skillspector")
        if not cli_path:
            return EnrichmentResult(
                scanner=self.name,
                status=EnrichmentStatus.ERROR,
                detail="skillspector CLI not found",
            )

        proc = await asyncio.create_subprocess_exec(
            cli_path, "scan", path, "--format", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=SKILLSPECTOR_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            return EnrichmentResult(
                scanner=self.name,
                status=EnrichmentStatus.ERROR,
                detail="scan timeout",
            )

        if proc.returncode != 0:
            return EnrichmentResult(
                scanner=self.name,
                status=EnrichmentStatus.ERROR,
                detail=f"exit code {proc.returncode}",
            )

        raw = json.loads(stdout.decode())
        return self._parse_output(raw)

    def _parse_output(self, raw: dict) -> EnrichmentResult:
        """Convert SkillSpector output to EnrichmentResult."""
        risk_score = float(raw.get("risk_score", 0.0))
        findings = raw.get("filtered_findings", raw.get("findings", []))

        if risk_score >= 7.0:
            status = EnrichmentStatus.THREAT
        elif risk_score >= 4.0:
            status = EnrichmentStatus.SUSPICIOUS
        else:
            status = EnrichmentStatus.CLEAN

        # Summarize findings
        finding_summary = ""
        if findings:
            top = findings[0]
            finding_summary = f"{top.get('rule_id', '?')}: {top.get('message', '')[:80]}"

        return EnrichmentResult(
            scanner=self.name,
            status=status,
            confidence=min(risk_score / 10.0, 1.0),
            category="tool_abuse" if risk_score >= 4.0 else None,
            detail=f"risk={risk_score:.1f}/10 findings={len(findings)} | {finding_summary}" if findings else None,
        )
