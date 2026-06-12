"""
ML-Based Scanners — Machine learning powered security detection.

These scanners use ONNX Runtime for inference and are designed to:
  - Run asynchronously (fire-and-forget) by default
  - Optionally run in blocking mode (with latency cost)
  - Gracefully degrade if models are unavailable
  - Work without GPU (CPU inference via ONNX)

Scanners:
  - InjectionClassifier: ML-based prompt injection detection
  - ToxicityScanner: Toxic/harmful content detection
  - TopicScanner: Topic boundary enforcement
  - IntentScanner: Adversarial intent detection
"""

from src.scanners.ml.model_manager import ModelManager, get_model_manager
from src.scanners.ml.injection_classifier import InjectionClassifier
from src.scanners.ml.intent_scanner import IntentScanner
from src.scanners.ml.toxicity_scanner import ToxicityScanner
from src.scanners.ml.topic_scanner import TopicScanner

__all__ = [
    "ModelManager",
    "get_model_manager",
    "InjectionClassifier",
    "IntentScanner",
    "ToxicityScanner",
    "TopicScanner",
]
