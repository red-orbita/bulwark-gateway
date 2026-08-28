# Bulwark Gateway — Implementation Roadmap

Competitive feature parity plan. Organized by phases with dependencies, effort estimates, and architectural decisions.

**Status: Core capabilities shipped across all 9 phases (2,000+ tests passing).** The
scanner/guardrail *engines* for every phase are implemented and tested. However a
subset of the deliverables listed below are aspirational, opt-in-and-inert without a
provisioned model, shipped in a different shape than originally sketched, or
deliberately retired. The per-deliverable checkboxes reflect the honest state — this
roadmap is a plan-vs-reality ledger, not a "done" banner.

**Deliverable legend**: `[x]` shipped & tested · `[~]` partial — shipped in a
different shape, opt-in/inert, or not fully wired · `[ ]` not shipped (aspirational
or retired). Rationale is noted inline next to every non-`[x]` item.

**Principle**: Never sacrifice the zero-latency hot path. ML features are additive layers, not replacements for regex.

**Architecture Rule**: 
```
Hot Path (regex, <5ms) → Decision → Response to client
         ↓ (fire-and-forget)
    ML Enrichment Layer (async, 50-500ms) → Feedback loop → Auto-regex generation
```

---

## Timeline Overview

| Phase | Name | Duration | Priority | Status |
|-------|------|----------|----------|--------|
| 1 | Scanner Framework + Plugin Architecture | 3-4 weeks | Critical | Shipped (docs gap) |
| 2 | ML-Based Detection Engine | 4-6 weeks | Critical | Shipped (opt-in; 2 ML scanners) |
| 3 | Multilingual + Multimodal Support | 3-4 weeks | High | Partial |
| 4 | Hallucination + Output Validation | 3-4 weeks | High | Beta (opt-in) |
| 5 | RAG Guardrails + Dialog Control | 4-5 weeks | Medium | Shipped |
| 6 | SDK / Library Mode | 4-5 weeks | Medium | Shipped (core; no docs/examples) |
| 7 | Plugin Hub / Marketplace | 3-4 weeks | Medium | Partial (engine only; no hub) |
| 8 | Red Teaming + Evaluation Framework | 3-4 weeks | Medium | Shipped (core; no CI/leaderboard) |
| 9 | Agent Discovery + Workforce AI | 4-5 weeks | Low | Shipped (detection only) |

**Total estimated**: 31-41 weeks (parallelizable — see dependency graph below)

```
Phase 1 (Foundation)
   ├── Phase 2 (ML Engine)
   │      ├── Phase 3 (Multilingual/Multimodal)
   │      ├── Phase 5 (RAG + Dialog)
   │      ├── Phase 8 (Red Teaming)
   │      └── Phase 9 (Agent Discovery)
   ├── Phase 4 (Hallucination)
   ├── Phase 6 (SDK Mode)
   │      └── Phase 7 (Plugin Hub)
   └────────────────────────────────────────
```

**With 2 parallel tracks**: ~20-24 weeks total
**With 3 parallel tracks**: ~14-18 weeks total

---

## Phase 1: Scanner Framework + Plugin Architecture [SHIPPED — docs gap]

**Goal**: Create a formal, pluggable scanner infrastructure that all future phases build upon.

**Problem**: Currently, guardrails are ad-hoc implementations with no shared protocol. Adding new scanner types requires modifying `proxy.py` directly.

### 1.1 Scanner Protocol (ABC)

Create `src/scanners/protocol.py`:

```python
from typing import Protocol, runtime_checkable
from src.models import GuardrailResult

@runtime_checkable
class InputScanner(Protocol):
    """Protocol for all input scanning stages."""
    name: str
    version: str
    blocking: bool  # True = in hot path, False = async enrichment

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan input content and return a verdict."""
        ...

    async def health(self) -> bool:
        """Return True if scanner is operational."""
        ...

@runtime_checkable
class OutputScanner(Protocol):
    """Protocol for all output scanning stages."""
    name: str
    version: str

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        ...

@dataclass
class ScanContext:
    """Context passed to all scanners."""
    tenant_id: str
    agent_id: str
    request_id: str
    messages: list[dict]  # conversation history
    metadata: dict[str, Any] = field(default_factory=dict)
    language: str | None = None  # detected language (Phase 3)
    content_type: str = "text"   # "text", "image", "audio" (Phase 3)
```

### 1.2 Scanner Pipeline Manager

Create `src/scanners/pipeline.py`:

```python
class ScannerPipeline:
    """Orchestrates scanner execution with priority ordering."""

    def __init__(self):
        self._blocking_input: list[InputScanner] = []   # Hot path
        self._async_input: list[InputScanner] = []      # Enrichment
        self._output: list[OutputScanner] = []

    def register(self, scanner: InputScanner | OutputScanner, priority: int = 50):
        """Register a scanner. Lower priority = runs first."""
        ...

    async def run_blocking_input(self, content: str, ctx: ScanContext) -> GuardrailResult:
        """Run blocking scanners sequentially. First BLOCK wins."""
        ...

    async def run_async_input(self, content: str, ctx: ScanContext) -> list[GuardrailResult]:
        """Run async scanners concurrently (fire-and-forget)."""
        ...

    async def run_output(self, content: str, ctx: ScanContext) -> GuardrailResult:
        """Run output scanners sequentially."""
        ...
```

### 1.3 Plugin Discovery

Create `src/scanners/discovery.py`:

```python
# Support two discovery mechanisms:
# 1. Entry points (pip-installable plugins)
# 2. Drop-in directory (config/scanners/*.py)

def discover_plugins() -> list[type]:
    """Discover scanner plugins via entry_points and scanner dir."""
    scanners = []

    # Method 1: Entry points
    for ep in importlib.metadata.entry_points(group="bulwark.scanners"):
        scanners.append(ep.load())

    # Method 2: Drop-in directory
    scanner_dir = Path(settings.scanners_dir)
    if scanner_dir.exists():
        for py_file in scanner_dir.glob("*.py"):
            module = importlib.import_module_from_path(py_file)
            for cls in inspect.getmembers(module, is_scanner):
                scanners.append(cls)

    return scanners
```

### 1.4 Configuration Extension

Add to `src/config.py`:

```python
# Scanner pipeline settings
BULWARK_SCANNERS_DIR: Path = Path("config/scanners")
BULWARK_ML_ENABLED: bool = False           # Master switch for ML scanners
BULWARK_ML_BLOCKING: bool = False          # If True, ML can block (adds latency)
BULWARK_ML_BLOCK_THRESHOLD: float = 0.9    # Confidence to auto-block
BULWARK_ML_WARN_THRESHOLD: float = 0.7     # Confidence to warn
BULWARK_ML_TIMEOUT_MS: int = 500           # Max ML inference time
BULWARK_ML_MODEL_BACKEND: str = "local"    # "local", "remote", "onnx"
```

### 1.5 Refactor Existing Guardrails as Scanners

Wrap existing code into the new protocol:

| Current | New Wrapper |
|---------|-------------|
| `input_guardrail.py` | `src/scanners/builtin/regex_scanner.py` (blocking) |
| `output_filter.py` | `src/scanners/builtin/output_redaction_scanner.py` (blocking) |
| `tool_policy.py` | `src/scanners/builtin/tool_policy_scanner.py` (blocking) |
| `embedding_scanner.py` | `src/scanners/builtin/embedding_scanner.py` (async) |

**Backwards-compatible**: Old code paths remain, wrappers delegate to them.

### 1.6 Deliverables

- [x] `src/scanners/` package with protocol, pipeline, discovery
- [x] `src/scanners/builtin/` wrapping existing guardrails (regex, output-redaction, tool-policy)
- [x] Config settings for scanner pipeline (`src/config.py`)
- [x] Unit tests for pipeline orchestration (`tests/test_scanner_framework.py`)
- [ ] Documentation: "Writing a Custom Scanner" guide — not written (no `docs/` guide yet)

### 1.7 New Dependencies

None (pure Python abstractions).

---

## Phase 2: ML-Based Detection Engine [SHIPPED — opt-in]

**Goal**: Add ML-powered detection that catches semantic attacks regex cannot detect.

**Competitive gap addressed**: Lakera (ML-trained on 1M+ attackers), LLM Guard (transformer classifiers), NeMo (self-check).

### 2.1 Architecture Decision: Inference Backend

| Option | Latency | Deployment | GPU Required |
|--------|---------|------------|--------------|
| ONNX Runtime (local) | 5-50ms | In-container | No (CPU OK) |
| sentence-transformers (local) | 20-200ms | In-container | Optional |
| Remote model server (Triton/vLLM) | 10-100ms | Separate pod | Yes |
| LLM-as-judge (API call) | 200-2000ms | External | N/A |

**Recommendation**: ONNX Runtime as default (fast, no GPU, portable). Remote server as option for enterprise.

### 2.2 Prompt Injection Classifier

Create `src/scanners/ml/injection_classifier.py`:

```python
class InjectionClassifier(InputScanner):
    """ML-based prompt injection detection using fine-tuned classifier."""
    name = "ml_injection_classifier"
    version = "1.0.0"
    blocking = False  # Async by default, configurable

    def __init__(self):
        # Lazy-load ONNX model
        self._model: ort.InferenceSession | None = None
        self._tokenizer: AutoTokenizer | None = None

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        # Run in thread pool (CPU-bound inference)
        score = await asyncio.get_event_loop().run_in_executor(
            self._pool, self._predict, content
        )
        if score >= settings.ml_block_threshold:
            return GuardrailResult(verdict=Verdict.BLOCK, ...)
        elif score >= settings.ml_warn_threshold:
            return GuardrailResult(verdict=Verdict.WARN, ...)
        return GuardrailResult(verdict=Verdict.ALLOW)
```

**Models to fine-tune / use**:
- Base: `deepset/deberta-v3-base-injection` (HuggingFace)
- Alternative: `protectai/deberta-v3-base-prompt-injection-v2`
- Export to ONNX for production inference

### 2.3 Toxicity/Safety Classifier

Create `src/scanners/ml/toxicity_scanner.py`:

```python
class ToxicityScanner(InputScanner):
    """Detects toxic, harmful, or unsafe content using ML classifier."""
    name = "ml_toxicity"
    version = "1.0.0"
    blocking = False

    # Categories: hate, harassment, self-harm, sexual, violence
    # Model: unitary/toxic-bert or similar fine-tuned model
```

### 2.4 Semantic Similarity Scanner (Enhanced Embedding)

Enhance existing `embedding_scanner.py`:

```python
class SemanticSimilarityScanner(InputScanner):
    """Detects prompt injection via semantic similarity to known attacks."""
    name = "ml_semantic_similarity"
    version = "2.0.0"
    blocking = False

    # Improvements over current embedding_scanner:
    # 1. ONNX-exported model (faster than sentence-transformers)
    # 2. Larger attack corpus (auto-updated from AttackReplayDB)
    # 3. Contrastive learning on Bulwark's own blocked/allowed data
    # 4. Adaptive threshold based on tenant-specific false positive rate
```

### 2.5 Topic Classification Scanner — DEPRECATED (withdrawn from roadmap)

> **Status: DEPRECATED — will not be shipped as a planned roadmap item.**
> Earlier dead stubs were already removed (no provisioned model, no download
> path, no manifest entry, mock-only tests). This entry is now formally withdrawn
> to keep the roadmap honest: the only ML scanners Bulwark actually ships are
> `injection-classifier` and `toxicity` (real ONNX models, real forward-pass
> tests in `tests/test_ml_inference.py`, `download-models.py` + manifest pins).
>
> Topic-boundary enforcement is **not on the committed roadmap**. If a future
> need is proven, the *only* acceptable path is the same bar the shipped
> scanners meet — source/train a model → export to ONNX → add to
> `scripts/download-models.py` + `config/model_manifest.json` → add real
> forward-pass tests gated on `ml_dependencies_available()` + `model_files_present`.
> It would be a normal ONNX classifier (no LLM call in the hot path). Until that
> work is actually done, there is no `TopicScanner` and none is planned.

### 2.6 Sentiment/Intent Detector — DEPRECATED (withdrawn from roadmap)

> **Status: DEPRECATED — will not be shipped as a planned roadmap item.**
> Same disposition and rationale as §2.5. There is no `IntentScanner`, no model,
> and none is planned. Adversarial-intent signal is instead covered today by the
> regex hot path plus the shipped `injection-classifier`. Any future revival must
> clear the identical "real ONNX model + real-inference tests, no LLM in the hot
> path" bar before it re-enters the roadmap.


### 2.7 ML Model Management

Create `src/scanners/ml/model_manager.py`:

```python
class ModelManager:
    """Manages ML model lifecycle: loading, versioning, hot-swap."""

    def __init__(self, model_dir: Path):
        self._models: dict[str, LoadedModel] = {}
        self._model_dir = model_dir

    async def load_model(self, name: str, version: str) -> LoadedModel:
        """Load ONNX model with optional GPU acceleration."""
        ...

    async def hot_swap(self, name: str, new_version: str):
        """Replace running model without downtime."""
        ...

    def get_model(self, name: str) -> LoadedModel | None:
        """Get loaded model (thread-safe)."""
        ...
```

### 2.8 Feedback Loop (Auto-Improvement)

Extend `src/enrichment/attack_replay_db.py`:

```python
# Current: records evasions and generates regex candidates
# Enhancement: Feed ML model with new attack patterns

class FeedbackLoop:
    """Feeds confirmed attacks back into ML training pipeline."""

    async def record_decision(self, content, regex_verdict, ml_verdict, final_verdict):
        """Record for model retraining."""
        ...

    async def export_training_data(self, since: datetime) -> TrainingDataset:
        """Export labeled data for periodic model fine-tuning."""
        ...

    async def detect_model_drift(self) -> DriftReport:
        """Compare ML accuracy against regex ground truth."""
        ...
```

### 2.9 Deliverables

- [~] `src/scanners/ml/` package — **2** real scanners ship (`injection_classifier`, `toxicity_scanner`), not "4+". Topic/intent were withdrawn (§2.5/2.6); multilingual/semantic classifiers not shipped as distinct models
- [x] `src/scanners/ml/model_manager.py` for lifecycle management (ONNX loader, SHA-256 fail-closed)
- [x] ONNX model export scripts (`scripts/export_models.py` + `scripts/download-models.py`)
- [~] Pre-trained models downloadable — via `scripts/download-models.py` + `config/model_manifest.json` (hash-pinned), not a `bulwark-models` package
- [ ] Docker image variant with ML models included (`bulwark-gateway-proxy:*-ml`) — not built; ML ships only as pip extras (`ml`, `ml-gpu`)
- [ ] Feedback loop integration with AttackReplayDB — no ML feedback loop; AttackReplayDB only does regex-candidate generation/review (no `FeedbackLoop` class)
- [~] Benchmarks: latency + accuracy vs pure regex — `scripts/run-benchmarks.py` + `docs/BENCHMARKS.md` exist but benchmark **regex only**; ML-vs-regex comparison not done
- [x] Admin UI: ML scanner status (`admin/routes/ml_scanners.py` + template)

### 2.10 New Dependencies

```toml
[project.optional-dependencies]
ml = [
    "onnxruntime>=1.17",
    "tokenizers>=0.15",
    "numpy>=1.26",
    "scikit-learn>=1.4",   # for metrics
]
ml-gpu = [
    "onnxruntime-gpu>=1.17",
]
```

---

## Phase 3: Multilingual + Multimodal Support [PARTIALLY SHIPPED]

**Goal**: Detect attacks in any language and modality.

**Competitive gap**: Lakera supports 100+ languages and image-based attacks.

> **Status (honesty — corrected).** The **language detector** (heuristic; degrades
> without the optional `lingua` backend) and the **multilingual regex patterns**
> ship and are wired.
>
> The `lingua` backend is **intentionally kept as an opt-in extra**
> (`pip install bulwark-gateway[multilingual]`), not a core dependency: its wheel
> is ~170 MB (it bundles n-gram models for every supported language) and the
> detector is gated behind `BULWARK_MULTILINGUAL_ENABLED` (off by default).
> Shipping it in core would add 170 MB to every image for a default-off feature,
> so it stays out of the minimal distroless runtime. Default distribution runs
> only the script heuristic: CJK/Arabic/Cyrillic/Devanagari are detected, and all
> Latin-script input resolves to `"en"` at reduced confidence.
>
> The **vision scanner** (§3.4) is split into two honest capability tiers:
> - Its **zero-dependency deterministic guards** — inline `data:image/...;base64`
>   extraction, base64 decode validation, the DoS size limit, the `allow_images`
>   policy gate, and magic-byte format-signature validation (MIME-confusion
>   detection) — are **real, tested, and registered opt-in** via
>   `BULWARK_VISION_SCANNING_ENABLED` (default off). No OCR backend required.
> - Its eponymous **OCR-to-injection** capability remains **inert**: the `[vision]`
>   extra (pillow) is not installed in the default distribution and no OCR backend
>   ships (nor fits the distroless / no-torch runtime), so `startup()` leaves it
>   disabled. That logic is real but unproven.
>
> Because the headline OCR capability is unprovisioned, the whole scanner stays
> `MaturityTier.EXPERIMENTAL` — it never claims BETA/GA on the strength of the
> hygiene guards alone. To run OCR, install pillow + an OCR backend deliberately
> (understanding it will not load in a stock distroless image).
>
> These accepted gaps (vision OCR, multilingual heuristic-only default) are
> consolidated in [Accepted Limitations & Known Gaps](LIMITATIONS.md). The
> fasttext backend is now provisioned + hash-pinned via
> `download-models.py --fasttext` (the `[fasttext]` extra), so it is no longer a
> gap — just a lighter opt-in alternative to lingua.


### 3.1 Language Detection

Create `src/scanners/multilingual/language_detector.py`:

```python
class LanguageDetector(InputScanner):
    """Detects input language and routes to appropriate scanner config."""
    name = "language_detector"
    version = "1.0.0"
    blocking = True  # Must run first to inform other scanners

    # Uses lingua-py (opt-in [multilingual] extra, ~170 MB, no GPU) or a
    # fasttext lid.176.ftz model (opt-in [fasttext] extra + download-models.py
    # --fasttext, ~3 MB total); falls back to a script heuristic when neither
    # is installed.
    # Sets context.language for downstream scanners
    # Policy enforcement: agent allowed_languages in YAML
```

### 3.2 Multilingual Regex Patterns

Extend `src/guardrails/input_guardrail.py`:

```python
# Add pattern sets for top 10 languages:
# - Spanish, French, German, Portuguese, Chinese, Japanese, Korean, Arabic, Russian, Hindi

# Strategy:
# 1. Common attack keywords translated + localized (not just Google Translate)
# 2. Script-specific evasion detection (CJK encoding tricks, Arabic RTL injection)
# 3. Cross-language code-switching detection (mixing languages to bypass monolingual filters)
```

### 3.3 Multilingual ML Models

```python
class MultilingualInjectionClassifier(InputScanner):
    """Multilingual prompt injection using XLM-RoBERTa or mDeBERTa."""
    name = "ml_multilingual_injection"
    version = "1.0.0"
    blocking = False

    # Model: microsoft/mdeberta-v3-base fine-tuned on multilingual injection dataset
    # Covers: 100+ languages in a single model
    # Falls back to English model if multilingual model unavailable
```

### 3.4 Multimodal Scanner (Images)

Create `src/scanners/ml/vision_scanner.py`:

```python
class VisionScanner(InputScanner):
    """Detects prompt injection in images (OCR + analysis)."""
    name = "ml_vision_scanner"
    version = "1.0.0"
    blocking = False

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        if context.content_type != "image":
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Pipeline:
        # 1. OCR extraction (Tesseract or EasyOCR via ONNX)
        # 2. Run extracted text through injection classifier
        # 3. Image content safety check (NSFW, harmful content)
        # 4. Steganography detection (hidden text in image data)
        ...
```

### 3.5 Proxy Route Extension for Multimodal

Extend `src/routes/proxy.py` to handle multimodal messages:

```python
# OpenAI vision format:
# {"role": "user", "content": [
#     {"type": "text", "text": "..."},
#     {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
# ]}

# Extract images from messages → scan with VisionScanner
# Extract text from messages → scan with existing text scanners
```

### 3.6 Policy Extension

```yaml
# config/policies/multilingual-tenant.yaml
tenant: global-corp
agents:
  - id: support-bot
    allowed_languages: [en, es, fr, de, pt]
    block_unknown_language: true
    multimodal:
      allow_images: true
      max_image_size_mb: 5
      ocr_scan: true
      nsfw_detection: true
```

### 3.7 Deliverables

- [~] Language detection scanner — ships heuristic-by-default (`src/scanners/multilingual/language_detector.py`); fasttext/lingua backends are opt-in extras, off by default
- [x] Multilingual regex patterns (top 10 languages) (`src/scanners/multilingual/patterns.py`)
- [ ] Multilingual ML classifier (XLM-R / mDeBERTa) — not shipped; only the generic DeBERTa `injection_classifier` exists (no provisioned multilingual model)
- [~] Vision scanner with OCR + content safety — file ships but OCR is inert/EXPERIMENTAL (no OCR backend in distroless); only the model-free image-hygiene guards are functional (BETA)
- [x] Multimodal message parsing in proxy route (`_extract_image_contents`, OpenAI vision format)
- [~] Policy schema extension for language/multimodal settings — scanners read `allowed_languages`/`multimodal` from metadata, but the policy loader does **not** parse them yet, so the enforcement path is not wired end-to-end
- [x] Tests: multilingual attack corpus (`tests/test_multilingual_multimodal.py`)

### 3.8 New Dependencies

```toml
[project.optional-dependencies]
multilingual = [
    "lingua-language-detector>=2.0",  # ~170 MB wheel; opt-in only (see 3.1 status note)
]
vision = [
    "pillow>=10.0",
    "easyocr>=1.7",   # or pytesseract
]
```

---

## Phase 4: Hallucination Detection + Structured Output Validation [SHIPPED — BETA, opt-in]

**Goal**: Detect when LLM outputs are factually incorrect or don't match expected schema.

**Competitive gap**: NeMo (self-check facts/hallucination), Guardrails AI (Pydantic validation), LLM Guard (FactualConsistency).

> **Status (honesty — shipped BETA, opt-in).** All four output-validation
> scanners are now functional, wired into the proxy pipeline behind per-capability
> master flags (default off), and declared `MaturityTier.BETA`. None runs on the
> hot path or issues an LLM call — they are OUTPUT_ASYNC (fire-and-forget) except
> the schema validator, and each stays inert (ALLOW) until the owning agent opts
> in via its `output_validation` policy.
>
> - **Schema validator** — model-free, `jsonschema` is a core runtime dependency,
>   deterministic + unit-tested. Enable with `BULWARK_SCHEMA_VALIDATION_ENABLED`.
> - **Relevance** (`sentence-embeddings`, cosine similarity) — enable with
>   `BULWARK_RELEVANCE_SCANNING_ENABLED`.
> - **Hallucination** and **grounding** (share the `nli-classifier` model, NLI
>   entailment / claim extraction) — enable with
>   `BULWARK_HALLUCINATION_SCANNING_ENABLED` / `BULWARK_GROUNDING_SCANNING_ENABLED`.
>
> The three model-backed scanners are **provisioned**: each has a
> `config/model_manifest.json` entry, a download path in
> `scripts/download-models.py` (`--embeddings` / `--nli`), and **real
> forward-pass tests** gated on `ml_dependencies_available()` +
> `model_files_present`. If the model is not downloaded they no-op (ALLOW) rather
> than fail, so enabling a flag without provisioning the model carries no hot-path
> cost — but also delivers no protection (see `docs/DEPLOYMENT.md` → model
> provisioning). This meets the honesty bar of §2.5/2.6: **no capability ships
> without a real model + real-inference tests.**


### 4.1 Hallucination Detector

Create `src/scanners/output/hallucination_scanner.py`:

```python
class HallucinationScanner(OutputScanner):
    """Detects factual inconsistencies between input context and output."""
    name = "hallucination_detector"
    version = "1.0.0"

    # Strategy (multiple methods, configurable):
    # Method 1: NLI-based (entailment check) — fast, ONNX
    #   - If output contradicts input context → WARN/BLOCK
    # Method 2: Self-consistency (multiple samples) — requires extra LLM call
    #   - Generate N responses, check consistency
    # Method 3: Source attribution
    #   - Check if claims in output can be traced to input documents

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        # Extract claims from output
        claims = self._extract_claims(content)
        # Check each claim against input context
        for claim in claims:
            entailment = await self._check_entailment(claim, context.messages)
            if entailment == "contradiction":
                return GuardrailResult(verdict=Verdict.WARN, ...)
        return GuardrailResult(verdict=Verdict.ALLOW)
```

### 4.2 Structured Output Validator

Create `src/scanners/output/schema_validator.py`:

```python
class SchemaValidator(OutputScanner):
    """Validates LLM output matches expected JSON/Pydantic schema."""
    name = "schema_validator"
    version = "1.0.0"

    # Config per-agent in policy YAML:
    # output_schema: path/to/schema.json (JSON Schema)
    # output_model: module.ClassName (Pydantic model)
    # on_fail: block | warn | repair (attempt JSON repair)

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        schema = self._get_schema_for_agent(context.agent_id)
        if not schema:
            return GuardrailResult(verdict=Verdict.ALLOW)

        try:
            parsed = json.loads(content)
            jsonschema.validate(parsed, schema)
            return GuardrailResult(verdict=Verdict.ALLOW)
        except (json.JSONDecodeError, ValidationError) as e:
            if self._repair_mode:
                repaired = self._attempt_repair(content, schema)
                return GuardrailResult(
                    verdict=Verdict.REDACT,
                    modified_content=repaired
                )
            return GuardrailResult(verdict=Verdict.WARN, ...)
```

### 4.3 Factual Grounding Scanner (for RAG)

Create `src/scanners/output/grounding_scanner.py`:

```python
class GroundingScanner(OutputScanner):
    """Checks if output is grounded in provided context (RAG faithfulness)."""
    name = "grounding_checker"
    version = "1.0.0"

    # Uses NLI model (DeBERTa fine-tuned for NLI) to check:
    # - Does the output follow from the retrieved documents?
    # - Are there unsupported claims?
    # Scoring: grounding_score (0-1), threshold configurable per agent
```

### 4.4 Relevance Scanner

Create `src/scanners/output/relevance_scanner.py`:

```python
class RelevanceScanner(OutputScanner):
    """Checks if output is relevant to the user's question."""
    name = "relevance_checker"
    version = "1.0.0"

    # Uses sentence embeddings to compute cosine similarity
    # between user question and LLM response
    # Low relevance → WARN (possible hallucination or off-topic)
```

### 4.5 Policy Extension

```yaml
# config/policies/validated-output.yaml
agents:
  - id: data-extractor
    output_validation:
      schema: schemas/extraction_output.json
      on_schema_fail: repair     # block | warn | repair
      hallucination_check: true
      grounding_threshold: 0.7   # min NLI entailment score
      relevance_threshold: 0.5   # min cosine similarity
```

### 4.6 Deliverables

- [x] Hallucination detector (NLI-based, ONNX model) (`src/scanners/output/hallucination_scanner.py`, BETA)
- [x] JSON Schema validator with repair capability (`src/scanners/output/schema_validator.py`)
- [ ] Pydantic model validation support — not implemented; validation is JSON-Schema-based only
- [x] Grounding scanner for RAG faithfulness (`src/scanners/output/grounding_scanner.py`)
- [x] Relevance scorer (`src/scanners/output/relevance_scanner.py`)
- [x] Policy schema extension for output validation (`output_validation` block — parsed by loader, wired end-to-end)
- [ ] `config/schemas/` directory for user-defined schemas — not created; schemas are supplied inline via `output_validation.output_schema`
- [x] Tests: hallucination + schema validation (`tests/test_output_validation.py`, `tests/test_schema_validation_wiring.py`)

### 4.7 New Dependencies

```toml
[project.optional-dependencies]
output-validation = [
    "jsonschema>=4.20",
    "json-repair>=0.25",  # for JSON repair attempts
]
# NLI model uses same onnxruntime from Phase 2
```

---

## Phase 5: RAG Guardrails + Dialog Control [SHIPPED]

**Goal**: Intercept RAG pipelines and control conversational flows.

**Competitive gap**: NeMo (retrieval rails + Colang dialog), Lakera (MCP-connected system protection).

### 5.1 Retrieval Rails (RAG Interception)

Create `src/scanners/rag/` package:

```python
# Two integration modes:
# Mode A: Proxy intercepts RAG-augmented prompts (detects context injection in system messages)
# Mode B: Sidecar API for RAG pipeline integration

class RetrievalScanner(InputScanner):
    """Scans retrieved documents/chunks before they reach the LLM."""
    name = "retrieval_scanner"
    version = "1.0.0"
    blocking = True

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        # Detect injected instructions in retrieved documents
        # (indirect prompt injection via poisoned knowledge base)
        chunks = self._extract_rag_chunks(context.messages)
        for chunk in chunks:
            result = await self._scan_chunk(chunk)
            if result.verdict == Verdict.BLOCK:
                # Remove poisoned chunk, don't block entire request
                return GuardrailResult(
                    verdict=Verdict.REDACT,
                    modified_content=self._remove_chunk(content, chunk)
                )
        return GuardrailResult(verdict=Verdict.ALLOW)
```

### 5.2 RAG Sidecar API

> **Note**: This standalone endpoint remained a design sketch. The shipped
> implementation validates RAG chunks inline via the scanner pipeline
> (`src/scanners/rag/retrieval_scanner.py`), not a dedicated `/v1/rag/validate`
> route.

New endpoint at `/v1/rag/validate`:

```python
@router.post("/v1/rag/validate")
async def validate_rag_chunks(request: RAGValidationRequest):
    """Pre-validate retrieved chunks before injecting into prompt.

    Called by RAG pipeline (LangChain, LlamaIndex) before LLM call.
    Returns: which chunks are safe, which should be filtered.
    """
    results = []
    for chunk in request.chunks:
        verdict = await retrieval_scanner.scan(chunk.content, ctx)
        results.append(ChunkVerdict(chunk_id=chunk.id, verdict=verdict))
    return RAGValidationResponse(chunks=results)
```

### 5.3 Dialog Control Engine (Simplified Colang Alternative)

Create `src/dialog/` package:

```python
# NOT a full Colang implementation (too complex, NeMo-specific)
# Instead: YAML-based flow definitions that are simpler but sufficient

# config/dialogs/support-bot.yaml
# flows:
#   greeting:
#     trigger: "user.intent == 'greeting'"
#     response: "Hello! How can I help you today?"
#     next: [ask_topic]
#
#   ask_topic:
#     trigger: "always"
#     response: "What would you like help with?"
#     allowed_intents: [billing, technical, account]
#     denied_intents: [politics, religion, competitors]
#     on_denied: "I can only help with billing, technical, or account questions."

class DialogEngine:
    """Simple state-machine dialog controller."""

    def __init__(self, flows: dict[str, DialogFlow]):
        self._flows = flows
        self._state: dict[str, str] = {}  # session_id → current_flow_node

    async def process(self, message: str, session_id: str, context: ScanContext) -> DialogDecision:
        """Returns: allow (proceed normally), redirect (use canned response), block."""
        current_node = self._state.get(session_id, "start")
        intent = await self._classify_intent(message)

        node = self._flows[current_node]
        if intent in node.denied_intents:
            return DialogDecision(action="redirect", response=node.on_denied)
        if intent in node.allowed_intents or not node.allowed_intents:
            self._state[session_id] = node.next_node(intent)
            return DialogDecision(action="allow")
        ...
```

### 5.4 Conversation Memory Guard

Create `src/scanners/rag/memory_guard.py`:

```python
class MemoryGuard(InputScanner):
    """Detects conversation manipulation across turns."""
    name = "memory_guard"
    version = "1.0.0"
    blocking = True

    # Detects:
    # 1. Context window stuffing (extremely long messages to push instructions out)
    # 2. Role confusion injection ("pretend the previous messages didn't happen")
    # 3. Multi-turn escalation (gradually building up to harmful request)
    # 4. System prompt extraction attempts across turns
```

### 5.5 Deliverables

- [x] Retrieval scanner for indirect prompt injection in RAG chunks (`src/scanners/rag/retrieval_scanner.py`)
- [~] RAG chunk validation — shipped as an in-pipeline scanner, not the standalone `/v1/rag/validate` route originally sketched below
- [x] YAML-based dialog flow engine (simplified Colang alternative) (`src/dialog/engine.py`)
- [x] Memory guard for multi-turn manipulation (`src/scanners/rag/memory_guard.py`)
- [x] Session state management (Redis-backed, cross-replica, TTL-bounded — `src/dialog/engine.py`)
- [x] LangChain/LlamaIndex integration example (`src/sdk/integrations/`)
- [x] Tests: RAG poisoning scenarios, dialog flow compliance (`tests/test_phase5_phase6.py`)

---

## Phase 6: SDK / Library Mode [SHIPPED — core; no docs/examples]

**Goal**: Allow Bulwark to be used as an embeddable Python library, not just as a proxy.

**Competitive gap**: All OSS competitors (NeMo, Guardrails AI, LLM Guard) support library mode.

### 6.1 Package Restructure

```python
# New top-level package: bulwark-guardrails (pip-installable)
# bulwark_guardrails/
#   __init__.py         → Guard, ScanResult, Verdict
#   guard.py            → Main Guard class
#   scanners/           → All scanner implementations (shared with proxy)
#   config.py           → Lightweight config (no FastAPI dependency)
#   models.py           → Shared models
```

### 6.2 Guard API (Python)

```python
from bulwark_guardrails import Guard, Verdict

# Create a guard with default security scanners
guard = Guard(
    scanners=["regex_injection", "ml_toxicity", "output_redaction"],
    config={"ml_enabled": True, "block_threshold": 0.9}
)

# Scan input before sending to LLM
input_result = guard.scan_input("Please ignore previous instructions...")
if input_result.verdict == Verdict.BLOCK:
    raise SecurityError(input_result.reason)

# Wrap LLM call
response = guard.wrap(
    llm_call=openai.chat.completions.create,
    messages=[{"role": "user", "content": user_input}],
    model="gpt-4"
)
# response is automatically scanned (input + output)

# Or use as decorator
@guard.protect(scanners=["regex_injection", "output_redaction"])
def my_agent_function(user_input: str) -> str:
    return call_llm(user_input)
```

### 6.3 Framework Integrations

```python
# LangChain integration
from bulwark_guardrails.integrations import LangChainGuard

guard = LangChainGuard(config=...)
chain = guard.wrap(my_langchain_chain)
result = chain.invoke({"input": "..."})

# LlamaIndex integration
from bulwark_guardrails.integrations import LlamaIndexGuard

guard = LlamaIndexGuard(config=...)
query_engine = guard.wrap(my_query_engine)
```

### 6.4 JavaScript/TypeScript SDK

```typescript
// npm package: @bulwark-gateway/guardrails
import { Guard, Verdict } from '@bulwark-gateway/guardrails';

const guard = new Guard({
  // Can connect to Bulwark proxy for scanning
  proxyUrl: 'http://localhost:8080',
  // Or use local WASM-compiled regex scanners
  mode: 'local', // 'local' | 'remote'
});

const result = await guard.scanInput(userMessage);
if (result.verdict === Verdict.BLOCK) {
  throw new Error(result.reason);
}
```

### 6.5 Deliverables

- [~] Separate installable SDK package — ships as `bulwark-gateway-sdk` (`sdk/`, import `bulwark_sdk`), **not** the advertised `bulwark-guardrails` name; an in-tree `src/sdk/` variant also exists
- [x] Guard API: `scan_input()`, `scan_output()`, `wrap()`, `@protect` decorator (`src/sdk/guard.py`, sync + async)
- [x] LangChain integration module (`src/sdk/integrations/langchain.py`)
- [x] LlamaIndex integration module (`src/sdk/integrations/llamaindex.py`; also autogen/crewai)
- [~] TypeScript SDK — ships as `@bulwark-gateway/sdk` (`sdk/typescript/`), a thin HTTP client to the gateway, **not** the advertised `@bulwark-gateway/guardrails` local-WASM-regex engine
- [x] Shared scanner code between library and proxy — `src/sdk` reuses `src/scanners/` (standalone `sdk/` reimplements a small regex set)
- [ ] Documentation: "Using as Library" guide — not written
- [ ] Examples: OpenAI, LangChain, LlamaIndex, custom agent — no `examples/` directory (only module docstrings)

---

## Phase 7: Plugin Hub / Marketplace [PARTIAL — engine only, no hub]

**Goal**: Create an ecosystem where community/third-party can contribute scanner plugins.

**Competitive gap**: Guardrails AI Hub (200+ validators), LLM Guard (modular scanners).

### 7.1 Plugin Specification

```yaml
# bulwark-plugin.yaml (required in every plugin package)
name: bulwark-scanner-toxicity
version: 1.0.0
author: community
license: MIT
description: "ML-based toxicity detection using fine-tuned DeBERTa"
type: input_scanner  # input_scanner | output_scanner | enrichment
blocking: false
requires:
  bulwark-guardrails: ">=0.5.0"
  onnxruntime: ">=1.17"
models:
  - name: toxicity-deberta-v3
    size: 180MB
    url: https://hub.bulwark-gateway.dev/models/toxicity-deberta-v3.onnx
config:
  threshold:
    type: float
    default: 0.7
    description: "Confidence threshold to trigger"
```

### 7.2 CLI for Plugin Management

```bash
# Install a scanner from the hub
bulwark plugin install toxicity-scanner
bulwark plugin install community/custom-pii-detector

# List installed plugins
bulwark plugin list

# Create a new plugin scaffold
bulwark plugin create my-custom-scanner

# Test a plugin locally
bulwark plugin test my-custom-scanner --input "test payload"

# Publish to hub
bulwark plugin publish
```

### 7.3 Hub Registry (Web Service)

```
hub.bulwark-gateway.dev/
├── /scanners              # Browse all scanners
├── /scanners/{name}       # Scanner detail page
├── /api/v1/search         # Search scanners
├── /api/v1/install/{name} # Download scanner package
└── /api/v1/publish        # Publish new scanner
```

### 7.4 Quality/Security Gates for Plugins

- Automated security scan of plugin code (no eval, no network in blocking mode)
- Performance benchmark (must pass latency budget test)
- Test suite required (min coverage)
- Signed packages (GPG or Sigstore)
- Community rating system

### 7.5 Deliverables

- [x] Plugin specification format (`bulwark-plugin.yaml` / `PluginSpec`, `src/plugins/spec.py`)
- [x] `bulwark` CLI extension for plugin management (`src/plugins/cli.py`: install/uninstall/list/create/test/enable/disable)
- [x] Plugin scaffold generator (`bulwark plugin create` → `manager.scaffold()`)
- [ ] Hub web service (API + simple frontend) — never built; retired as fictional. `--source hub` is a stub that hard-fails; only `local` + `git` installs work
- [ ] 10+ initial plugins (migrated from built-in scanners) — only 1 example plugin ships (`plugins/examples/input-dlp-scanner/`)
- [x] Plugin security scanner (regex + AST audit at install time + admin `security-check` endpoint, `src/plugins/manager.py`)
- [ ] Documentation: "Creating and Publishing Plugins" — not written

---

## Phase 8: Red Teaming + Evaluation Framework [SHIPPED — core; no CI/leaderboard]

**Goal**: Automated adversarial testing to validate guardrail effectiveness.

**Competitive gap**: Lakera (Gandalf red teaming), NeMo (vulnerability scanning), Guardrails AI (Guardrails Index benchmark).

### 8.1 Attack Generator

Create `src/evaluation/attack_generator.py`:

```python
class AttackGenerator:
    """Generates adversarial prompts to test guardrail effectiveness."""

    def generate_attacks(self, categories: list[ThreatCategory], count: int) -> list[Attack]:
        """Generate diverse attack payloads per category."""
        attacks = []
        for category in categories:
            attacks.extend(self._template_attacks(category, count))
            attacks.extend(self._mutation_attacks(category, count))
            attacks.extend(self._llm_generated_attacks(category, count))
        return attacks

    def _template_attacks(self, category, count) -> list[Attack]:
        """Pattern-based attacks with variable substitution."""
        ...

    def _mutation_attacks(self, category, count) -> list[Attack]:
        """Mutate known-blocked payloads to find bypasses."""
        # Character substitution, encoding, word reordering, paraphrasing
        ...

    def _llm_generated_attacks(self, category, count) -> list[Attack]:
        """Use LLM to generate novel attack payloads (optional)."""
        ...
```

### 8.2 Evaluation Runner

Create `src/evaluation/runner.py`:

```python
class EvaluationRunner:
    """Runs red team evaluation against guardrail configuration."""

    async def run_evaluation(self, config: EvalConfig) -> EvaluationReport:
        """
        Metrics produced:
        - Detection rate (true positive rate) per category
        - False positive rate (legitimate prompts incorrectly blocked)
        - Bypass rate (attacks that evade detection)
        - Latency distribution (P50, P95, P99)
        - Coverage map (which attack types are covered)
        """
        ...

    async def compare_configs(self, config_a, config_b) -> ComparisonReport:
        """A/B comparison of guardrail configurations."""
        ...
```

### 8.3 Benchmark Suite

```bash
# CLI command
bulwark evaluate --config config/policies/ --attacks standard
bulwark evaluate --config config/policies/ --attacks exhaustive --categories prompt_injection,jailbreak
bulwark evaluate --report html --output reports/eval-2024-01.html

# Benchmark datasets:
# - Standard: 1000 attacks + 1000 benign (quick, ~5 min)
# - Exhaustive: 10000 attacks + 5000 benign (thorough, ~30 min)
# - Custom: user-provided attack corpus
```

### 8.4 Continuous Evaluation (CI Integration)

```yaml
# .github/workflows/security-eval.yml
- name: Run guardrail evaluation
  run: bulwark evaluate --config config/policies/ --min-detection-rate 0.95 --max-fp-rate 0.01
  # Fails CI if detection rate drops below 95% or FP rate exceeds 1%
```

### 8.5 Guardrail Leaderboard

A scoring system comparing Bulwark against competitors on standard datasets:

| Metric | Bulwark (regex) | Bulwark (regex+ML) | Lakera | LLM Guard | NeMo |
|--------|-----------------|---------------------|--------|-----------|------|
| Injection Detection Rate | — | — | — | — | — |
| False Positive Rate | — | — | — | — | — |
| Latency P95 | — | — | — | — | — |
| Language Coverage | — | — | — | — | — |

### 8.6 Deliverables

- [~] Attack generator — template + mutation + encoding + rule-based semantic paraphrase ship (`src/evaluation/attacks.py`); the "LLM-generated" strategy is **not** implemented (no LLM call, by hot-path design)
- [x] Evaluation runner with metrics (`src/evaluation/runner.py`: confusion matrix, detection/FP rates, latency percentiles)
- [x] Standard benchmark dataset (curated) (`src/evaluation/datasets.py`: benign + standard/exhaustive attacks)
- [x] `bulwark evaluate` CLI command (`src/evaluation/cli.py`: `run` + `compare`)
- [ ] CI integration template — no guardrail-evaluation workflow ships (`security.yml` is SAST/SCA only)
- [x] HTML/JSON report generation (`runner.generate_report`: text/json/html)
- [~] Comparison tool (A/B testing of configs) — CLI `compare` does A/B of two saved **report JSON files**, not a live config-vs-config runner (`compare_configs` not implemented)
- [ ] Public leaderboard data format — not defined (leaderboard table is a placeholder)

---

## Phase 9: Agent Discovery + Workforce AI Monitoring [SHIPPED — detection only]

**Goal**: Discover unknown AI agents and monitor AI usage beyond the gateway.

**Competitive gap**: Lakera (agent discovery, workforce AI security).

### 9.1 Agent Discovery

Create `src/discovery/` package:

```python
class AgentDiscovery:
    """Discovers AI agents and LLM API calls in the network."""

    # Discovery methods:
    # 1. Network traffic analysis (detect patterns of LLM API calls)
    # 2. DNS monitoring (detect calls to known LLM endpoints)
    # 3. Kubernetes pod scanning (detect containers with LLM SDKs)
    # 4. MCP server enumeration (scan for MCP-compatible services)

    async def scan_network(self, cidr: str) -> list[DiscoveredAgent]:
        ...

    async def scan_kubernetes(self, namespace: str) -> list[DiscoveredAgent]:
        ...

    async def scan_mcp_servers(self, registry_url: str) -> list[DiscoveredMCPServer]:
        ...
```

### 9.2 Shadow AI Detection

```python
class ShadowAIMonitor:
    """Detects unauthorized AI usage by employees."""

    # Integration points:
    # 1. DNS sinkhole for known AI endpoints (openai.com, anthropic.com, etc.)
    # 2. Proxy logs analysis (HTTP CONNECT to AI APIs)
    # 3. Browser extension (optional) for visibility
    # 4. DLP integration for data sent to external AI

    known_ai_endpoints = [
        "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
        "api.cohere.ai", "api.mistral.ai", "api.together.ai", ...
    ]
```

### 9.3 MCP Server Inventory

```python
class MCPInventory:
    """Maintains inventory of all MCP servers and their capabilities."""

    async def enumerate_tools(self, server_url: str) -> list[MCPTool]:
        """List all tools exposed by an MCP server."""
        ...

    async def assess_risk(self, tool: MCPTool) -> RiskAssessment:
        """Risk-assess an MCP tool based on capabilities."""
        ...

    async def monitor_usage(self, server_url: str) -> UsageReport:
        """Track which agents are calling which MCP tools."""
        ...
```

### 9.4 Deliverables

- [x] Network-based agent discovery (HTTP probe + fingerprinting, `src/discovery/agent_discovery.py`)
- [x] Kubernetes scanner for AI workloads (`scan_kubernetes` — enumerates Services via K8s API)
- [x] MCP server inventory and risk assessment (`src/discovery/mcp_inventory.py`)
- [x] Shadow AI detection (DNS-based) (`src/discovery/shadow_ai.py`)
- [x] Admin UI: agent map, discovered services, risk scores (`admin/routes/discovery.py` + template)
- [ ] Automated onboarding: discovered agent → suggested policy — not implemented; discovery results are display-only
- [x] Alerting: new unregistered AI agents detected — `ShadowAIMonitor.dispatch_alerts()` fans out detected alerts to the shared `NotificationEngine` (advisory `warn` verdict, `shadow_ai` category); opt-in via the `notify` flag on `POST /admin/discovery/shadow-ai/analyze`

---

## Implementation Principles

### Architecture Invariants (NEVER violate)

1. **Hot path remains regex-only** unless `BULWARK_ML_BLOCKING=true` is explicitly set
2. **Fail-closed** behavior preserved in all new features
3. **No external calls during request processing** unless explicitly configured
4. **Graceful degradation**: if ML model unavailable, fall back to regex-only
5. **Tenant isolation**: ML models and configs are per-tenant where applicable

### Quality Gates for Each Phase

- [ ] All existing tests pass (regression)
- [ ] New feature has >80% test coverage
- [ ] Performance benchmark: no regression in P95 latency for existing paths
- [ ] Security review for new attack surfaces
- [ ] Documentation updated (API reference, user guide)
- [ ] Docker image builds successfully
- [ ] Helm chart updated if new services/configs added

### Versioning Strategy

| Phase Complete | Version | Breaking Changes |
|---------------|---------|------------------|
| Phase 1 | 0.5.0 | No (additive) |
| Phase 2 | 0.6.0 | No (opt-in ML) |
| Phase 3 | 0.7.0 | No (additive) |
| Phase 4 | 0.8.0 | No (additive) |
| Phase 5 | 0.9.0 | Minor (new API endpoints) |
| Phase 6 | 1.0.0 | Yes (new package structure) |
| Phase 7 | 1.1.0 | No (additive) |
| Phase 8 | 1.2.0 | No (additive) |
| Phase 9 | 1.3.0 | No (additive) |

---

## Resource Requirements

### Team Composition (Ideal)

| Role | Phases | FTE |
|------|--------|-----|
| Backend Engineer (Python/async) | 1, 5, 6 | 1.0 |
| ML Engineer | 2, 3, 4 | 1.0 |
| Security Engineer | 2, 8 | 0.5 |
| Frontend Engineer (Admin UI) | All (UI updates) | 0.5 |
| DevOps Engineer | All (infra/CI) | 0.5 |

### Infrastructure

| Resource | Purpose | Phase |
|----------|---------|-------|
| GPU instance (training) | Fine-tune models | 2, 3 |
| ONNX model storage (S3/GCS) | Host exported models | 2+ |
| CI GPU runner | Test ML inference | 2+ |
| Hub hosting | Plugin marketplace | 7 |
| Benchmark infra | Evaluation runs | 8 |

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| ML adds latency to hot path | Default async-only; blocking requires explicit opt-in |
| Model size bloats container | Separate image tag (`-ml`); models downloaded at startup |
| False positives from ML | Conservative thresholds; human review via admin UI |
| Plugin security | Sandboxed execution; code signing; security gates |
| Scope creep per phase | Each phase is independently shippable; MVP first |
| Breaking existing deployments | Semver; feature flags; graceful degradation |

---

## Success Metrics

| Metric | Current | Target (Phase 2) | Target (Phase 6) |
|--------|---------|-------------------|-------------------|
| Attack detection rate | ~85% (regex) | >95% (regex+ML) | >97% |
| False positive rate | <0.5% | <1% (with ML) | <0.5% |
| Supported languages | 1 (English) | 10+ | 100+ |
| Multimodal support | None | Images | Images + Audio |
| Integration modes | Proxy only | Proxy + Sidecar | Proxy + SDK + Library |
| Plugin ecosystem | 0 | 5 built-in | 20+ (community) |
| P95 latency (hot path) | <5ms | <5ms (unchanged) | <5ms (unchanged) |
| P95 latency (with ML blocking) | N/A | <50ms | <30ms |
