"""ML Scanner management routes — Toggle, configure thresholds, view status."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import TokenPayload
from ..services.auth_service import require_permission
from ..services.audit_logger import get_audit_logger

router = APIRouter()

# Persistent config file (writable /app/data in K8s)
_CONFIG_FILE = Path("data/ml_scanners_config.json")

# Default scanner definitions (matches src/scanners/ml/ + rag/ + multilingual/)
_DEFAULT_SCANNERS = {
    "ml_injection_classifier": {
        "name": "ml_injection_classifier",
        "display_name": "Injection Classifier",
        "description": "DeBERTa-v3 prompt injection detection (protectai/deberta-v3-base-prompt-injection-v2)",
        "model_path": "models/injection-classifier/",
        "category": "ml",
        "enabled": False,
        "blocking": False,
        "block_threshold": 0.9,
        "warn_threshold": 0.7,
        "timeout_ms": 500,
        "priority": 20,
    },
    "ml_toxicity_scanner": {
        "name": "ml_toxicity_scanner",
        "display_name": "Toxicity Scanner",
        "description": "Multi-label toxicity detection (toxic, severe_toxic, threat, insult, obscene)",
        "model_path": "models/toxicity/",
        "category": "ml",
        "enabled": False,
        "blocking": False,
        "block_threshold": 0.5,
        "warn_threshold": 0.7,
        "timeout_ms": 500,
        "priority": 25,
    },
    "ml_intent_scanner": {
        "name": "ml_intent_scanner",
        "display_name": "Intent Scanner",
        "description": "Adversarial intent classification (exploitation, social_engineering, evasion, exfiltration)",
        "model_path": "models/intent-classifier/",
        "category": "ml",
        "enabled": False,
        "blocking": False,
        "block_threshold": 0.85,
        "warn_threshold": 0.6,
        "timeout_ms": 500,
        "priority": 25,
    },
    "ml_topic_scanner": {
        "name": "ml_topic_scanner",
        "display_name": "Topic Scanner",
        "description": "Off-topic detection with per-agent allowed topic lists",
        "model_path": "models/topic-classifier/",
        "category": "ml",
        "enabled": False,
        "blocking": False,
        "block_threshold": 0.7,
        "warn_threshold": 0.7,
        "timeout_ms": 500,
        "priority": 30,
    },
    "memory_guard": {
        "name": "memory_guard",
        "display_name": "Memory Guard",
        "description": "Multi-turn manipulation detection: context stuffing, role confusion, prompt extraction",
        "model_path": "",
        "category": "rag",
        "enabled": False,
        "blocking": True,
        "block_threshold": 0.0,
        "warn_threshold": 0.0,
        "timeout_ms": 100,
        "priority": 4,
    },
    "retrieval_scanner": {
        "name": "retrieval_scanner",
        "display_name": "RAG Retrieval Scanner",
        "description": "Scans retrieved document chunks for indirect prompt injection (poisoned RAG)",
        "model_path": "",
        "category": "rag",
        "enabled": False,
        "blocking": True,
        "block_threshold": 0.0,
        "warn_threshold": 0.0,
        "timeout_ms": 100,
        "priority": 6,
    },
    "language_detector": {
        "name": "language_detector",
        "display_name": "Language Detector",
        "description": "Identifies input language (lingua/fasttext/heuristic). Enforces allowed_languages policy.",
        "model_path": "",
        "category": "multilingual",
        "enabled": False,
        "blocking": True,
        "block_threshold": 0.0,
        "warn_threshold": 0.0,
        "timeout_ms": 50,
        "priority": 5,
    },
    "multilingual_patterns": {
        "name": "multilingual_patterns",
        "display_name": "Multilingual Patterns",
        "description": "Attack detection in 10 languages (ES, FR, DE, PT, RU, ZH, JA, KO, AR, HI). 52 patterns.",
        "model_path": "",
        "category": "multilingual",
        "enabled": False,
        "blocking": True,
        "block_threshold": 0.0,
        "warn_threshold": 0.0,
        "timeout_ms": 50,
        "priority": 8,
    },
}

# In-memory state
_scanner_config: dict[str, dict] = {}


def _load_config() -> None:
    """Load ML scanner config from disk."""
    global _scanner_config
    _scanner_config = {k: dict(v) for k, v in _DEFAULT_SCANNERS.items()}
    if _CONFIG_FILE.exists():
        try:
            saved = json.loads(_CONFIG_FILE.read_text())
            for name, overrides in saved.items():
                if name in _scanner_config:
                    _scanner_config[name].update(overrides)
        except Exception:
            pass


def _save_config() -> None:
    """Persist ML scanner config to disk."""
    try:
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_FILE.write_text(json.dumps(_scanner_config, indent=2))
    except Exception:
        pass


def _sync_to_redis() -> None:
    """Push ML config to Redis so proxy can pick up changes without restart."""
    try:
        from ..services.redis_sync import get_redis_client
        r = get_redis_client()
        if not r:
            return
        r.set("sentinel:ml_scanners:config", json.dumps(_scanner_config))
        r.incr("sentinel:ml_scanners:version")
    except Exception:
        pass


def _check_model_exists(model_path: str) -> bool:
    """Check if ONNX model files exist at the given path."""
    p = Path(model_path)
    if not p.exists():
        return False
    # Look for .onnx files
    return any(p.glob("*.onnx"))


async def _query_proxy_scanner_status() -> dict | None:
    """Query the proxy service for actual scanner pipeline status.

    Uses the internal /internal/scanners/status endpoint (no auth required,
    network-level isolation via K8s NetworkPolicies).

    The proxy has the ML models loaded and knows the real state.
    Returns None if proxy is unreachable.
    """
    import httpx

    proxy_url = os.environ.get("SENTINEL_PROXY_URL", "http://proxy:8080")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{proxy_url}/internal/scanners/status")
            if resp.status_code == 200:
                return resp.json()
            return None
    except Exception:
        return None


# Load on import
_load_config()


@router.get("/status")
async def ml_scanner_status(
    _user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get ML scanner status — models, enabled state, thresholds.

    Queries the proxy pod for real scanner pipeline status (deps, models, health).
    Falls back to local checks if proxy is unreachable.
    """
    # Query proxy for actual runtime status
    proxy_data = await _query_proxy_scanner_status()
    proxy_reachable = proxy_data is not None

    # Extract proxy scanner info if available
    proxy_scanners: dict[str, dict] = {}
    proxy_ml_active = False
    proxy_lanes = {}
    if proxy_data:
        proxy_ml_active = proxy_data.get("ml_enabled", False)
        proxy_lanes = proxy_data.get("lanes", {})
        # Index proxy scanners by name for quick lookup
        for s in proxy_data.get("scanners", []):
            proxy_scanners[s["name"]] = s

    # Determine dependencies status:
    # - If proxy is reachable and ML is enabled, deps ARE available (on proxy pod)
    # - Only fall back to local check if proxy is unreachable
    if proxy_reachable:
        deps_available = True  # Proxy loaded successfully = deps present on proxy
        missing_deps = []
    else:
        # Fallback: check locally (admin pod doesn't have ML deps — warn user)
        deps_available = True
        missing_deps = []
        for dep_name in ("numpy", "onnxruntime", "tokenizers"):
            try:
                __import__(dep_name)
            except ImportError:
                deps_available = False
                missing_deps.append(dep_name)

    # Global ML settings from env (admin-side config, used for display)
    ml_enabled_env = os.environ.get("SENTINEL_ML_ENABLED", "false").lower() in ("true", "1")
    ml_blocking_env = os.environ.get("SENTINEL_ML_BLOCKING", "false").lower() in ("true", "1")
    model_dir = os.environ.get("SENTINEL_ML_MODEL_DIR", "models/")
    rag_enabled_env = os.environ.get("SENTINEL_RAG_ENABLED", "false").lower() in ("true", "1")
    multilingual_enabled_env = os.environ.get("SENTINEL_MULTILINGUAL_ENABLED", "false").lower() in ("true", "1")

    # Override with proxy's actual state if available
    if proxy_data:
        ml_enabled_env = proxy_data.get("ml_enabled", ml_enabled_env)
        ml_blocking_env = proxy_data.get("ml_blocking", ml_blocking_env)
        rag_enabled_env = proxy_data.get("rag_enabled", rag_enabled_env)
        multilingual_enabled_env = proxy_data.get("multilingual_enabled", multilingual_enabled_env)

    scanners = []
    for name, cfg in _scanner_config.items():
        model_path = cfg.get("model_path", "")

        # Check if scanner is registered + healthy on proxy
        proxy_scanner = proxy_scanners.get(name)
        if proxy_scanner:
            # Scanner is actually loaded on proxy — get real status
            model_installed = proxy_scanner.get("healthy", True)
            scanner_enabled = proxy_scanner.get("enabled", cfg.get("enabled", False))
            metrics = proxy_scanner.get("metrics", {})
        elif proxy_reachable and model_path:
            # Proxy is up but this scanner isn't registered (model not deployed)
            model_installed = False
            scanner_enabled = cfg.get("enabled", False)
            metrics = {}
        else:
            # Proxy unreachable — fall back to local check
            model_installed = _check_model_exists(model_path) if model_path else True
            scanner_enabled = cfg.get("enabled", False)
            metrics = {}

        # Pattern-based scanners (no model_path) don't need ML dependencies
        needs_ml_deps = bool(model_path)
        ready = model_installed and scanner_enabled
        if needs_ml_deps:
            ready = ready and deps_available

        scanners.append({
            **cfg,
            "enabled": scanner_enabled,
            "model_installed": model_installed,
            "ready": ready,
            "metrics": metrics,
        })

    return {
        "global": {
            "ml_enabled_env": ml_enabled_env,
            "ml_blocking_env": ml_blocking_env,
            "model_dir": model_dir,
            "rag_enabled_env": rag_enabled_env,
            "multilingual_enabled_env": multilingual_enabled_env,
            "dependencies_available": deps_available,
            "missing_dependencies": missing_deps,
            "proxy_reachable": proxy_reachable,
            "proxy_ml_active": proxy_ml_active,
            "proxy_lanes": proxy_lanes,
        },
        "scanners": scanners,
    }


@router.post("/toggle")
async def toggle_scanner(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Enable or disable a specific ML scanner."""
    name = data.get("name")
    enabled = data.get("enabled")

    if not name or name not in _scanner_config:
        raise HTTPException(status_code=404, detail=f"Scanner '{name}' not found")
    if enabled is None:
        raise HTTPException(status_code=400, detail="'enabled' field required")

    _scanner_config[name]["enabled"] = bool(enabled)
    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="ml_scanner.toggle",
        resource_type="ml_scanner",
        resource_id=name,
        details=json.dumps({"enabled": bool(enabled)}),
    )

    return {"message": f"Scanner '{name}' {'enabled' if enabled else 'disabled'}", "scanner": _scanner_config[name]}


@router.post("/configure")
async def configure_scanner(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Update thresholds and settings for an ML scanner."""
    name = data.get("name")
    if not name or name not in _scanner_config:
        raise HTTPException(status_code=404, detail=f"Scanner '{name}' not found")

    allowed_fields = {"block_threshold", "warn_threshold", "timeout_ms", "blocking", "priority"}
    updates = {}
    for field in allowed_fields:
        if field in data:
            val = data[field]
            # Validate thresholds
            if field in ("block_threshold", "warn_threshold"):
                val = float(val)
                if not (0.0 <= val <= 1.0):
                    raise HTTPException(status_code=400, detail=f"{field} must be between 0.0 and 1.0")
            elif field == "timeout_ms":
                val = int(val)
                if val < 50 or val > 10000:
                    raise HTTPException(status_code=400, detail="timeout_ms must be between 50 and 10000")
            elif field == "priority":
                val = int(val)
                if val < 0 or val > 100:
                    raise HTTPException(status_code=400, detail="priority must be between 0 and 100")
            elif field == "blocking":
                val = bool(val)
            updates[field] = val

    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    _scanner_config[name].update(updates)
    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="ml_scanner.configure",
        resource_type="ml_scanner",
        resource_id=name,
        details=json.dumps(updates),
    )

    return {"message": f"Scanner '{name}' updated", "scanner": _scanner_config[name]}


@router.post("/toggle-all")
async def toggle_all_scanners(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Enable or disable all ML scanners at once."""
    enabled = data.get("enabled")
    if enabled is None:
        raise HTTPException(status_code=400, detail="'enabled' field required")

    for name in _scanner_config:
        _scanner_config[name]["enabled"] = bool(enabled)

    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="ml_scanner.toggle_all",
        resource_type="ml_scanner",
        resource_id="*",
        details=json.dumps({"enabled": bool(enabled)}),
    )

    return {"message": f"All scanners {'enabled' if enabled else 'disabled'}", "scanners": _scanner_config}


@router.post("/reset")
async def reset_scanner_config(
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Reset all ML scanner settings to defaults."""
    global _scanner_config
    _scanner_config = {k: dict(v) for k, v in _DEFAULT_SCANNERS.items()}
    _save_config()
    _sync_to_redis()

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="ml_scanner.reset",
        resource_type="ml_scanner",
        resource_id="*",
        details="reset to defaults",
    )

    return {"message": "All scanners reset to defaults", "scanners": _scanner_config}
