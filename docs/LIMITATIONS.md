# Bulwark Gateway — Accepted Limitations & Known Gaps

Single source of truth for the project's **intentional, accepted limitations**.

Bulwark's design bar is _"nothing ships claiming a capability it does not really
have."_ Where a capability cannot be delivered cleanly in the default runtime
(or is deliberately left opt-in for cost reasons), we do not fake it — we degrade
honestly and record the gap here. Each entry states **what** the limitation is,
**why** it is accepted, its **impact**, and how to **opt in / work around** it.

Status legend:

| Status | Meaning |
|--------|---------|
| **By design** | Deliberate tradeoff; will not change without a strong reason |
| **Hard constraint** | Blocked by the runtime/packaging model; not fixable in place |
| **Future work** | Removable later via the normal "real model + real tests" path |

---

## L1 — Vision OCR is inert in the default (distroless) runtime

**Status: Hard constraint.** Scanner: `ml_vision_scanner`
(`MaturityTier.EXPERIMENTAL`).

The **deterministic image-hygiene guards** ship active and tested (opt-in via
`BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED`): inline `data:image/...;base64`
extraction, base64 decode validation, the DoS size limit, the `allow_images`
policy gate, and magic-byte format-signature validation (MIME-confusion
detection). These require **no** OCR backend.

The eponymous **OCR-to-injection** capability, however, stays inert: the
`[vision]` extra (pillow) is not installed by default and **no OCR backend fits
the distroless / no-torch runtime image**. `startup()` therefore leaves the OCR
path disabled, and because the headline capability is unprovisioned the whole
scanner remains `EXPERIMENTAL` (it never claims BETA/GA on the hygiene guards
alone).

- **Impact:** text rendered *inside* an image is not read/scanned by default.
- **Opt in:** install pillow + an OCR backend deliberately, understanding it will
  **not** load in a stock distroless image (you must build a fatter image).
- **Refs:** [ROADMAP §3 status note](ROADMAP.md), [ARCHITECTURE maturity
  tiers](ARCHITECTURE.md#maturity-tiers-honesty-signal),
  `src/scanners/multimodal/vision_scanner.py`.

---

## L2 — Multilingual detection is script-heuristic-only by default

**Status: By design.** Scanner: `language_detector` (`MaturityTier.BETA`).

Accurate language identification requires either the `lingua` backend — shipped
as the **opt-in `[multilingual]` extra**, a **~170 MB** wheel that bundles n-gram
models for every language — or a `fasttext` model (see L3). Because the scanner
is gated behind `BULWARK_MULTILINGUAL_ENABLED` (off by default), lingua is kept
out of core so the default image stays minimal (zero cost when disabled).

Without an accurate backend the detector runs a **script heuristic**: it detects
script-distinguishable languages (CJK, Arabic, Cyrillic, Devanagari) reliably,
but resolves **all Latin-script input to `"en"`** at reduced confidence.

- **Impact:** Latin-script languages (es/fr/de/pt/…) are not distinguished by
  default. Latin-script multilingual pattern sets stay dormant, and an
  `allowed_languages` policy that excludes English may under-block Latin-script
  text labelled `"en"`.
- **Opt in:** `pip install bulwark-gateway[multilingual]`.
- **Refs:** `src/scanners/multilingual/language_detector.py` (SHIPPED STATE
  docstring), [DEPLOYMENT multilingual footprint note](DEPLOYMENT.md),
  [ROADMAP §3.1](ROADMAP.md).

---

## L3 — fasttext language backend has no automated download path

**Status: By design.** Backend of `language_detector` (secondary to lingua).

The detector will use a `fasttext` model (`lid.176.ftz`) if `fasttext` is
installed **and** the model file is present in `BULWARK_ML_MODEL_DIR`. This path
is real and gracefully degrades (it logs `fasttext_model_missing` and falls
through to the heuristic), but unlike the ONNX classifiers it is **not** wired
into `scripts/download-models.py` / `config/model_manifest.json`, so there is no
hash-verified provisioning step for it.

- **Impact:** the fasttext backend is effectively operator-provisioned only; the
  supported "accurate detection" path is lingua (L2).
- **Opt in:** install `fasttext` and place `lid.176.ftz` in the model dir
  manually.
- **Refs:** `src/scanners/multilingual/language_detector.py` (`startup()`).

---

## L4 — Topic / intent ML classifiers are not shipped

**Status: Future work.**

Earlier `ml_topic_classifier` / intent stubs were **removed**: they had no
provisioned model, no download path, no manifest entry, and only mock-based
tests, so they violated the "no capability ships without a real model +
real-inference tests" bar. They are intentionally absent rather than shipped as
non-functional stubs.

- **Impact:** no topic-boundary / intent enforcement scanner today.
- **Add later:** identical to `injection-classifier` / `toxicity` — source/train
  a model → export to ONNX → add to `scripts/download-models.py` +
  `config/model_manifest.json` → add real forward-pass tests. No LLM call in the
  hot path.
- **Refs:** [ROADMAP §2.5/§2.6](ROADMAP.md).

---

## L5 — The input guardrail is not a SQLi / XSS WAF

**Status: By design.**

Free-form chat input is **not** reliably matched for classic SQL injection
(`'; DROP TABLE …`, `admin' OR 1=1 --`), XSS, or bare path traversal
(`../../../etc/passwd`). This is intentional: those threats are enforced where
the payload actually reaches a database / filesystem — the **tool-argument
layer** (`tool_policy.py`: path-traversal detection, `denied_arguments`,
argument allow/deny) and the **output filter**. Some `UNION SELECT`-style SQLi is
caught incidentally by exfiltration / tool-abuse patterns.

- **Impact:** do not rely on the input guardrail as a network WAF for app-layer
  injection; enforce those at the tool/output boundary.
- **Refs:** `src/guardrails/input_guardrail.py` scope note, `AGENTS.md` §4.

---

## L6 — Model-backed BETA scanners are inert until the model is provisioned

**Status: By design.**

Every capability scanner (ML injection/toxicity, relevance, hallucination,
grounding, RAG, vision OCR) stays **inert (returns ALLOW)** unless (a) its master
flag is on, (b) its backing model is downloaded via `scripts/download-models.py`,
**and** (c) the owning agent opts in via policy. Enabling a flag alone carries no
hot-path cost — but also delivers no protection until the model bytes are
present. A scanner whose flag is **on** while its model is **absent** now reports
`healthy: false` (rendered as a **Degraded** amber card) so the gap is visible
rather than silent.

- **Impact:** a flag flip without a provisioned model is a no-op for protection.
- **Verify:** `GET /internal/scanners/status` / admin "Advanced Scanners" page —
  confirm the scanner reads **Active**, not **Degraded**.
- **Refs:** [ARCHITECTURE master flags vs runtime
  toggles](ARCHITECTURE.md#master-flags-vs-runtime-toggles),
  [DEPLOYMENT scanner enablement](DEPLOYMENT.md).

---

_When a limitation here is genuinely removed (e.g. a topic classifier ships with
a real model + tests), delete its entry — this file must only ever list gaps that
are still real._
