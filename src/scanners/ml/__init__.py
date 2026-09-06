"""
ML-Based Scanners — Machine learning powered security detection.

These scanners use ONNX Runtime for inference and are designed to:
  - Run asynchronously (fire-and-forget) by default
  - Optionally run in blocking mode (with latency cost)
  - Gracefully degrade if models are unavailable
  - Work without GPU (CPU inference via ONNX)

Scanners:
  - InjectionClassifier: ML-based prompt injection detection
  - PromptGuard2Classifier: Meta Prompt Guard 2 injection/jailbreak detection
  - ToxicityScanner: Toxic/harmful content detection
  - GaGuardScanner: Remote classifier-sidecar input scanner (GA Guard Lite)
"""

from src.scanners.ml.ga_guard import GaGuardScanner
from src.scanners.ml.injection_classifier import InjectionClassifier
from src.scanners.ml.model_manager import ModelManager, get_model_manager
from src.scanners.ml.prompt_guard import PromptGuard2Classifier
from src.scanners.ml.toxicity_scanner import ToxicityScanner

__all__ = [
    "ModelManager",
    "get_model_manager",
    "InjectionClassifier",
    "PromptGuard2Classifier",
    "ToxicityScanner",
    "GaGuardScanner",
]
