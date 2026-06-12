# Sentinel Gateway — Implementation Roadmap

Competitive feature parity plan. Organized by phases with dependencies, effort estimates, and architectural decisions.

**Status: ALL 9 PHASES COMPLETE** (370 tests passing)

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
| 1 | Scanner Framework + Plugin Architecture | 3-4 weeks | Critical | COMPLETE |
| 2 | ML-Based Detection Engine | 4-6 weeks | Critical | COMPLETE |
| 3 | Multilingual + Multimodal Support | 3-4 weeks | High | COMPLETE |
| 4 | Hallucination + Output Validation | 3-4 weeks | High | COMPLETE |
| 5 | RAG Guardrails + Dialog Control | 4-5 weeks | Medium | COMPLETE |
| 6 | SDK / Library Mode | 4-5 weeks | Medium | COMPLETE |
| 7 | Plugin Hub / Marketplace | 3-4 weeks | Medium | COMPLETE |
| 8 | Red Teaming + Evaluation Framework | 3-4 weeks | Medium | COMPLETE |
| 9 | Agent Discovery + Workforce AI | 4-5 weeks | Low | COMPLETE |

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

## Phase 1: Scanner Framework + Plugin Architecture [COMPLETE]

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
    for ep in importlib.metadata.entry_points(group="sentinel.scanners"):
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
SENTINEL_SCANNERS_DIR: Path = Path("config/scanners")
SENTINEL_ML_ENABLED: bool = False           # Master switch for ML scanners
SENTINEL_ML_BLOCKING: bool = False          # If True, ML can block (adds latency)
SENTINEL_ML_BLOCK_THRESHOLD: float = 0.9    # Confidence to auto-block
SENTINEL_ML_WARN_THRESHOLD: float = 0.7     # Confidence to warn
SENTINEL_ML_TIMEOUT_MS: int = 500           # Max ML inference time
SENTINEL_ML_MODEL_BACKEND: str = "local"    # "local", "remote", "onnx"
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

- [ ] `src/scanners/` package with protocol, pipeline, discovery
- [ ] `src/scanners/builtin/` wrapping existing guardrails
- [ ] Config settings for scanner pipeline
- [ ] Unit tests for pipeline orchestration
- [ ] Documentation: "Writing a Custom Scanner" guide

### 1.7 New Dependencies

None (pure Python abstractions).

---

## Phase 2: ML-Based Detection Engine [COMPLETE]

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
    # 3. Contrastive learning on Sentinel's own blocked/allowed data
    # 4. Adaptive threshold based on tenant-specific false positive rate
```

### 2.5 Topic Classification Scanner

Create `src/scanners/ml/topic_scanner.py`:

```python
class TopicScanner(InputScanner):
    """Enforces topic boundaries using zero-shot classification."""
    name = "ml_topic_classifier"
    version = "1.0.0"
    blocking = False

    # Uses zero-shot NLI model (ONNX-exported bart-large-mnli or similar)
    # Config per-agent: allowed_topics, denied_topics in policy YAML
    # Example: agent "support-bot" can only discuss [billing, technical_support, account]
```

### 2.6 Sentiment/Intent Detector

Create `src/scanners/ml/intent_scanner.py`:

```python
class IntentScanner(InputScanner):
    """Detects adversarial intent via multi-label classification."""
    name = "ml_intent_detector"
    version = "1.0.0"
    blocking = False

    # Labels: benign, social_engineering, manipulation, escalation_attempt
    # Useful for detecting subtle attacks regex cannot catch
```

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

- [ ] `src/scanners/ml/` package with 4+ scanner implementations
- [ ] `src/scanners/ml/model_manager.py` for lifecycle management
- [ ] ONNX model export scripts in `scripts/export_models.py`
- [ ] Pre-trained models downloadable via `sentinel-models` package or URL
- [ ] Docker image variant with ML models included (`sentinel-gateway-proxy:0.5.0-ml`)
- [ ] Feedback loop integration with AttackReplayDB
- [ ] Benchmarks: latency + accuracy vs pure regex
- [ ] Admin UI: ML scanner status, confidence distributions, drift alerts

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

## Phase 3: Multilingual + Multimodal Support [COMPLETE]

**Goal**: Detect attacks in any language and modality.

**Competitive gap**: Lakera supports 100+ languages and image-based attacks.

### 3.1 Language Detection

Create `src/scanners/ml/language_detector.py`:

```python
class LanguageDetector(InputScanner):
    """Detects input language and routes to appropriate scanner config."""
    name = "language_detector"
    version = "1.0.0"
    blocking = True  # Must run first to inform other scanners

    # Uses fasttext-langdetect or lingua-py (lightweight, no GPU)
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

- [ ] Language detection scanner (fasttext-based, <5ms)
- [ ] Multilingual regex patterns (top 10 languages)
- [ ] Multilingual ML classifier (XLM-R / mDeBERTa)
- [ ] Vision scanner with OCR + content safety
- [ ] Multimodal message parsing in proxy route
- [ ] Policy schema extension for language/multimodal settings
- [ ] Tests: multilingual attack corpus (50+ test cases per language)

### 3.8 New Dependencies

```toml
[project.optional-dependencies]
multilingual = [
    "lingua-language-detector>=2.0",  # or fasttext
]
vision = [
    "pillow>=10.0",
    "easyocr>=1.7",   # or pytesseract
]
```

---

## Phase 4: Hallucination Detection + Structured Output Validation [COMPLETE]

**Goal**: Detect when LLM outputs are factually incorrect or don't match expected schema.

**Competitive gap**: NeMo (self-check facts/hallucination), Guardrails AI (Pydantic validation), LLM Guard (FactualConsistency).

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

- [ ] Hallucination detector (NLI-based, ONNX model)
- [ ] JSON Schema validator with repair capability
- [ ] Pydantic model validation support
- [ ] Grounding scanner for RAG faithfulness
- [ ] Relevance scorer
- [ ] Policy schema extension for output validation
- [ ] `config/schemas/` directory for user-defined schemas
- [ ] Tests: hallucination test cases + schema validation edge cases

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

## Phase 5: RAG Guardrails + Dialog Control [COMPLETE]

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

Create `src/scanners/dialog/memory_guard.py`:

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

- [ ] Retrieval scanner for indirect prompt injection in RAG chunks
- [ ] `/v1/rag/validate` sidecar endpoint
- [ ] YAML-based dialog flow engine (simplified Colang alternative)
- [ ] Memory guard for multi-turn manipulation
- [ ] Session state management (Redis-backed)
- [ ] LangChain/LlamaIndex integration example
- [ ] Tests: RAG poisoning scenarios, dialog flow compliance

---

## Phase 6: SDK / Library Mode [COMPLETE]

**Goal**: Allow Sentinel to be used as an embeddable Python library, not just as a proxy.

**Competitive gap**: All OSS competitors (NeMo, Guardrails AI, LLM Guard) support library mode.

### 6.1 Package Restructure

```python
# New top-level package: sentinel-guardrails (pip-installable)
# sentinel_guardrails/
#   __init__.py         → Guard, ScanResult, Verdict
#   guard.py            → Main Guard class
#   scanners/           → All scanner implementations (shared with proxy)
#   config.py           → Lightweight config (no FastAPI dependency)
#   models.py           → Shared models
```

### 6.2 Guard API (Python)

```python
from sentinel_guardrails import Guard, Verdict

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
from sentinel_guardrails.integrations import LangChainGuard

guard = LangChainGuard(config=...)
chain = guard.wrap(my_langchain_chain)
result = chain.invoke({"input": "..."})

# LlamaIndex integration
from sentinel_guardrails.integrations import LlamaIndexGuard

guard = LlamaIndexGuard(config=...)
query_engine = guard.wrap(my_query_engine)
```

### 6.4 JavaScript/TypeScript SDK

```typescript
// npm package: @sentinel-gateway/guardrails
import { Guard, Verdict } from '@sentinel-gateway/guardrails';

const guard = new Guard({
  // Can connect to Sentinel proxy for scanning
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

- [ ] `sentinel-guardrails` PyPI package (separate from proxy server)
- [ ] Guard API: `scan_input()`, `scan_output()`, `wrap()`, `@protect` decorator
- [ ] LangChain integration module
- [ ] LlamaIndex integration module
- [ ] TypeScript SDK (connects to proxy or local WASM regex)
- [ ] Shared scanner code between library and proxy (mono-repo structure)
- [ ] Documentation: "Using as Library" guide
- [ ] Examples: OpenAI, LangChain, LlamaIndex, custom agent

---

## Phase 7: Plugin Hub / Marketplace [COMPLETE]

**Goal**: Create an ecosystem where community/third-party can contribute scanner plugins.

**Competitive gap**: Guardrails AI Hub (200+ validators), LLM Guard (modular scanners).

### 7.1 Plugin Specification

```yaml
# sentinel-plugin.yaml (required in every plugin package)
name: sentinel-scanner-toxicity
version: 1.0.0
author: community
license: MIT
description: "ML-based toxicity detection using fine-tuned DeBERTa"
type: input_scanner  # input_scanner | output_scanner | enrichment
blocking: false
requires:
  sentinel-guardrails: ">=0.5.0"
  onnxruntime: ">=1.17"
models:
  - name: toxicity-deberta-v3
    size: 180MB
    url: https://hub.sentinel-gateway.dev/models/toxicity-deberta-v3.onnx
config:
  threshold:
    type: float
    default: 0.7
    description: "Confidence threshold to trigger"
```

### 7.2 CLI for Plugin Management

```bash
# Install a scanner from the hub
sentinel plugin install toxicity-scanner
sentinel plugin install community/custom-pii-detector

# List installed plugins
sentinel plugin list

# Create a new plugin scaffold
sentinel plugin create my-custom-scanner

# Test a plugin locally
sentinel plugin test my-custom-scanner --input "test payload"

# Publish to hub
sentinel plugin publish
```

### 7.3 Hub Registry (Web Service)

```
hub.sentinel-gateway.dev/
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

- [ ] Plugin specification format (`sentinel-plugin.yaml`)
- [ ] `sentinel` CLI extension for plugin management
- [ ] Plugin scaffold generator (`sentinel plugin create`)
- [ ] Hub web service (API + simple frontend)
- [ ] 10+ initial plugins (migrated from built-in scanners)
- [ ] Plugin security scanner (no malicious code in plugins)
- [ ] Documentation: "Creating and Publishing Plugins"

---

## Phase 8: Red Teaming + Evaluation Framework [COMPLETE]

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
sentinel evaluate --config config/policies/ --attacks standard
sentinel evaluate --config config/policies/ --attacks exhaustive --categories prompt_injection,jailbreak
sentinel evaluate --report html --output reports/eval-2024-01.html

# Benchmark datasets:
# - Standard: 1000 attacks + 1000 benign (quick, ~5 min)
# - Exhaustive: 10000 attacks + 5000 benign (thorough, ~30 min)
# - Custom: user-provided attack corpus
```

### 8.4 Continuous Evaluation (CI Integration)

```yaml
# .github/workflows/security-eval.yml
- name: Run guardrail evaluation
  run: sentinel evaluate --config config/policies/ --min-detection-rate 0.95 --max-fp-rate 0.01
  # Fails CI if detection rate drops below 95% or FP rate exceeds 1%
```

### 8.5 Guardrail Leaderboard

A scoring system comparing Sentinel against competitors on standard datasets:

| Metric | Sentinel (regex) | Sentinel (regex+ML) | Lakera | LLM Guard | NeMo |
|--------|-----------------|---------------------|--------|-----------|------|
| Injection Detection Rate | — | — | — | — | — |
| False Positive Rate | — | — | — | — | — |
| Latency P95 | — | — | — | — | — |
| Language Coverage | — | — | — | — | — |

### 8.6 Deliverables

- [ ] Attack generator (template + mutation + LLM-generated)
- [ ] Evaluation runner with metrics
- [ ] Standard benchmark dataset (curated)
- [ ] `sentinel evaluate` CLI command
- [ ] CI integration template
- [ ] HTML/JSON report generation
- [ ] Comparison tool (A/B testing of configs)
- [ ] Public leaderboard data format

---

## Phase 9: Agent Discovery + Workforce AI Monitoring [COMPLETE]

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

- [ ] Network-based agent discovery (DNS + traffic patterns)
- [ ] Kubernetes pod scanner for AI workloads
- [ ] MCP server inventory and risk assessment
- [ ] Shadow AI detection (DNS-based)
- [ ] Admin UI: agent map, discovered services, risk scores
- [ ] Automated onboarding: discovered agent → suggested policy
- [ ] Alerting: new unregistered AI agents detected

---

## Implementation Principles

### Architecture Invariants (NEVER violate)

1. **Hot path remains regex-only** unless `SENTINEL_ML_BLOCKING=true` is explicitly set
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
