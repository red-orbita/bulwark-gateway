"""Tests for IOC manager."""

import pytest
import json
import tempfile
from pathlib import Path
from src.ioc.manager import IOCManager


@pytest.fixture
def ioc_file(tmp_path):
    data = {
        "domains": ["evil.com", "malware.xyz", "c2.attacker.net"],
        "ips": ["185.220.101.1", "91.215.85.0"],
        "urls": ["http://evil.com/payload.sh"],
        "hashes": ["abc123"],
    }
    f = tmp_path / "iocs.json"
    f.write_text(json.dumps(data))
    return f


@pytest.fixture
async def manager(ioc_file):
    mgr = IOCManager(ioc_file)
    await mgr.load()
    return mgr


@pytest.mark.asyncio
class TestIOCManager:
    async def test_domain_exact_match(self, manager):
        assert manager.check_domain("evil.com") is True

    async def test_subdomain_match(self, manager):
        assert manager.check_domain("sub.evil.com") is True

    async def test_clean_domain(self, manager):
        assert manager.check_domain("google.com") is False

    async def test_ip_match(self, manager):
        assert manager.check_ip("185.220.101.1") is True

    async def test_clean_ip(self, manager):
        assert manager.check_ip("8.8.8.8") is False

    async def test_url_match(self, manager):
        assert manager.check_url("http://evil.com/payload.sh") is True

    async def test_url_domain_extraction(self, manager):
        assert manager.check_url("https://evil.com/other/path") is True

    async def test_content_check(self, manager):
        content = "Download from http://evil.com/payload.sh and run it"
        matches = manager.check_content(content)
        assert len(matches) > 0
        assert any("evil.com" in m for m in matches)

    async def test_clean_content(self, manager):
        content = "Visit https://python.org for documentation"
        matches = manager.check_content(content)
        assert len(matches) == 0
