"""Tests for the binary model-artifact opcode scanner (BWK-ART-*).

Covers the standalone `model_artifact_scanner` engine (never deserializes,
`pickletools`-only) and its integration as a stage in the SkillSpector
`skill_scanner` pipeline.

All malicious fixtures are built here at test time; none are ever unpickled.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import pickle
import struct
import zipfile

import numpy as np
import pytest

from src.scanners.artifacts import model_artifact_scanner as mas

# ═══════════════════════════════════════════════════════════════════
# Malicious fixture builders (constructed statically — never executed)
# ═══════════════════════════════════════════════════════════════════

class _OsSystemRCE:
    """Pickle whose __reduce__ wires os.system to a REDUCE gadget."""

    def __reduce__(self):
        return (os.system, ("id",))


class _EvalRCE:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))


def _malicious_pickle_bytes() -> bytes:
    return pickle.dumps(_OsSystemRCE())


def _benign_pickle_bytes() -> bytes:
    return pickle.dumps({"weights": [1, 2, 3], "name": "model", "layers": 12})


def _rule_ids(findings) -> set[str]:
    return {f["rule_id"] for f in findings}


# ═══════════════════════════════════════════════════════════════════
# Raw pickle detection
# ═══════════════════════════════════════════════════════════════════

class TestRawPickle:
    def test_os_system_reduce_is_rce(self):
        findings = mas.analyze_bytes(_malicious_pickle_bytes(), "evil.pkl")
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings)
        rce = next(f for f in findings if f["rule_id"] == "BWK-ART-PICKLE-RCE")
        assert rce["severity"] == "critical"
        assert rce["confidence"] >= 80

    def test_eval_reduce_is_rce(self):
        findings = mas.analyze_bytes(pickle.dumps(_EvalRCE()), "eval.pkl")
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings)

    def test_benign_pickle_has_no_findings(self):
        findings = mas.analyze_bytes(_benign_pickle_bytes(), "clean.pkl")
        assert findings == []

    def test_scanner_never_executes_payload(self, tmp_path):
        """Regression: scanning an os.system gadget must NOT run the command."""
        marker = tmp_path / "pwned"
        # __reduce__ would create the file if the pickle were ever loaded.
        klass = type("Marker", (), {
            "__reduce__": lambda self: (os.system, (f"touch {marker}",))
        })
        data = pickle.dumps(klass())
        findings = mas.analyze_bytes(data, "marker.pkl")
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings)
        assert not marker.exists(), "scanner executed the pickle payload!"

    def test_empty_input_is_clean(self):
        assert mas.analyze_bytes(b"", "empty.pkl") == []


# ═══════════════════════════════════════════════════════════════════
# Container formats
# ═══════════════════════════════════════════════════════════════════

class TestContainers:
    def test_torch_style_zip_with_malicious_data_pkl(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", _malicious_pickle_bytes())
            zf.writestr("archive/version", "3")
        findings = mas.analyze_bytes(buf.getvalue(), "model.pt")
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings)

    def test_torch_style_zip_benign(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", _benign_pickle_bytes())
        findings = mas.analyze_bytes(buf.getvalue(), "clean.pt")
        assert "BWK-ART-PICKLE-RCE" not in _rule_ids(findings)

    @pytest.mark.parametrize("compress,kind", [
        (gzip.compress, "gzip"),
        (bz2.compress, "bz2"),
        (lzma.compress, "xz"),
    ])
    def test_compressed_joblib_style_pickle(self, compress, kind):
        findings = mas.analyze_bytes(compress(_malicious_pickle_bytes()), f"m.{kind}")
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings), f"{kind} not scanned"

    def test_numpy_object_array_embeds_pickle(self, tmp_path):
        p = tmp_path / "obj.npy"
        arr = np.array([_OsSystemRCE()], dtype=object)
        np.save(p, arr, allow_pickle=True)
        findings = mas.analyze_file(p, str(p))
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings)

    def test_numpy_numeric_array_is_clean(self, tmp_path):
        p = tmp_path / "num.npy"
        np.save(p, np.arange(100, dtype=np.float32))
        findings = mas.analyze_file(p, str(p))
        assert "BWK-ART-PICKLE-RCE" not in _rule_ids(findings)

    def test_safetensors_is_informational_ok(self, tmp_path):
        p = tmp_path / "model.safetensors"
        header = b'{"__metadata__":{"format":"pt"}}'
        p.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 32)
        findings = mas.analyze_file(p, str(p))
        ids = _rule_ids(findings)
        assert "BWK-ART-SAFETENSORS-OK" in ids
        assert "BWK-ART-PICKLE-RCE" not in ids


# ═══════════════════════════════════════════════════════════════════
# is_model_artifact / directory / catalog
# ═══════════════════════════════════════════════════════════════════

class TestDetectionHelpers:
    def test_is_model_artifact_by_extension(self, tmp_path):
        p = tmp_path / "x.pkl"
        p.write_bytes(_benign_pickle_bytes())
        assert mas.is_model_artifact(p) is True

    def test_is_model_artifact_by_magic(self, tmp_path):
        p = tmp_path / "noext"
        p.write_bytes(_malicious_pickle_bytes())
        assert mas.is_model_artifact(p) is True

    def test_plain_text_is_not_artifact(self, tmp_path):
        p = tmp_path / "skill.yaml"
        p.write_text("name: demo\ntools: []\n")
        assert mas.is_model_artifact(p) is False

    def test_analyze_directory_finds_nested_malicious(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "weights.pkl").write_bytes(_malicious_pickle_bytes())
        (tmp_path / "clean.pkl").write_bytes(_benign_pickle_bytes())
        findings = mas.analyze_directory(tmp_path)
        assert "BWK-ART-PICKLE-RCE" in _rule_ids(findings)

    def test_analyze_content_is_noop(self):
        assert mas.analyze_content("os.system('id')", "x.txt") == []

    def test_pattern_count_positive(self):
        assert mas.PATTERN_COUNT > 0


# ═══════════════════════════════════════════════════════════════════
# Integration through the SkillSpector skill_scanner pipeline
# ═══════════════════════════════════════════════════════════════════

class TestSkillScannerIntegration:
    @pytest.fixture(autouse=True)
    def _reset_scanner(self):
        import admin.services.skill_scanner as ss
        ss._instance = None
        yield
        ss._instance = None

    @pytest.mark.asyncio
    async def test_malicious_pickle_file_is_blocked(self, tmp_path):
        from admin.services.skill_scanner import ScanVerdict, get_skill_scanner

        p = tmp_path / "model.pkl"
        p.write_bytes(_malicious_pickle_bytes())

        result = await get_skill_scanner().scan(str(p))
        assert result.verdict == ScanVerdict.BLOCK
        assert any(f.rule_id == "BWK-ART-PICKLE-RCE" for f in result.findings)
        assert any(f.source == "model_artifact" for f in result.findings)

    @pytest.mark.asyncio
    async def test_benign_pickle_file_passes(self, tmp_path):
        from admin.services.skill_scanner import ScanVerdict, get_skill_scanner

        p = tmp_path / "clean.pkl"
        p.write_bytes(_benign_pickle_bytes())

        result = await get_skill_scanner().scan(str(p))
        assert result.verdict == ScanVerdict.PASS

    @pytest.mark.asyncio
    async def test_artifact_file_skips_text_stages(self, tmp_path):
        """A binary artifact must not produce text-engine (bulwark/mcp) findings."""
        from admin.services.skill_scanner import get_skill_scanner

        p = tmp_path / "model.pkl"
        p.write_bytes(_malicious_pickle_bytes())

        result = await get_skill_scanner().scan(str(p))
        sources = {f.source for f in result.findings}
        assert sources == {"model_artifact"}

    @pytest.mark.asyncio
    async def test_directory_with_malicious_artifact_and_yaml(self, tmp_path):
        from admin.services.skill_scanner import ScanVerdict, get_skill_scanner

        (tmp_path / "skill.yaml").write_text(
            "name: demo\ndescription: a benign skill\ntools: []\n"
        )
        (tmp_path / "weights.pkl").write_bytes(_malicious_pickle_bytes())

        result = await get_skill_scanner().scan(str(tmp_path))
        assert result.verdict == ScanVerdict.BLOCK
        assert any(f.rule_id == "BWK-ART-PICKLE-RCE" for f in result.findings)

    def test_status_reports_artifact_patterns(self):
        from admin.services.skill_scanner import get_skill_scanner

        st = get_skill_scanner().status()
        assert st["model_artifact_patterns"] == mas.PATTERN_COUNT
        assert st["total_patterns"] >= mas.PATTERN_COUNT
