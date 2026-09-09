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

Accurate language identification requires a real backend. Two are available,
both **opt-in** because the scanner is gated behind `BULWARK_MULTILINGUAL_ENABLED`
(off by default), so neither is shipped in core (zero cost when disabled):

- **`lingua`** — the `[multilingual]` extra, a **~170 MB** wheel that bundles
  n-gram models for every language. Most accurate.
- **`fasttext`** — the `[fasttext]` extra (~2 MB wheel) plus the 917 KB
  `lid.176.ftz` model, now provisioned + hash-pinned via
  `python scripts/download-models.py --fasttext`. Much smaller than lingua and a
  far better default than the heuristic.

Without either backend the detector runs a **script heuristic**: it detects
script-distinguishable languages (CJK, Arabic, Cyrillic, Devanagari) reliably,
but resolves **all Latin-script input to `"en"`** at reduced confidence.

- **Impact:** Latin-script languages (es/fr/de/pt/…) are not distinguished by
  the built-in heuristic. Latin-script multilingual pattern sets stay dormant,
  and an `allowed_languages` policy that excludes English may under-block
  Latin-script text labelled `"en"`.
- **Opt in:** `pip install bulwark-gateway[multilingual]` (lingua) **or**
  `pip install bulwark-gateway[fasttext] && python scripts/download-models.py --fasttext`.
- **Refs:** `src/scanners/multilingual/language_detector.py` (SHIPPED STATE
  docstring), [DEPLOYMENT multilingual footprint note](DEPLOYMENT.md),
  [ROADMAP §3.1](ROADMAP.md).

---

## L3 — Topic / intent ML classifiers are not shipped

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

## L4 — The input guardrail is not a SQLi / XSS WAF

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

## L5 — Model-backed BETA scanners are inert until the model is provisioned

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

## L6 — The input guardrail only scans the first 16 KB of a prompt by default

**Status: By design (bounded DoS trade-off), with an opt-in mitigation.**

The synchronous input guardrail caps its regex work at `guardrail_max_scan_bytes`
(16 KB) with a head→tail sliding window, and flags any single message longer than
`guardrail_max_input_size` (8 KB) as *oversized*. These two knobs are independent
and both intentional: they bound the worst-case cost of scanning an attacker-sized
prompt on the hot path (a full 16 KB scan of benign text is ~0.7 s observed). The
consequence is a **long-context blind spot** — an injection buried *past* the
16 KB boundary in a very long prompt is not seen by the synchronous scan, so a
detection that would otherwise BLOCK can degrade to WARN/ALLOW.

- **Impact:** do not assume the whole of a very long prompt is regex-scanned
  inline; the tail beyond `max_scan_bytes` is not covered by the sync guardrail.
- **Mitigation (opt-in):** set `BULWARK_LONG_CONTEXT_SCANNING_ENABLED=true` to
  register the `LongContextScanner` (INPUT_ASYNC). It re-runs the **shared**
  `InputGuardrail` (same pattern SSOT, zero new deps) over the content *beyond*
  the boundary, chunked so each window is scanned in full, plus a many-shot
  jailbreak density heuristic. Its total work is itself hard-capped by
  `BULWARK_LONG_CONTEXT_MAX_SCAN_BYTES` (256 KB) so the feature can never amplify
  a large prompt into unbounded regex work. Set
  `BULWARK_LONG_CONTEXT_SCANNING_BLOCKING=true` to let deep BLOCK-worthy findings
  block rather than warn.
- **Refs:** `src/guardrails/input_guardrail.py` (`max_scan_bytes`,
  `max_input_size`), `src/scanners/longcontext/long_context_scanner.py`,
  `AGENTS.md` §6 (long-context settings).

---

## L7 — Admin login per-IP throttle is coarse behind a shared-IP reverse proxy

**Status: By design.**

The admin login limiter (`admin/routes/auth.py`) keys its per-IP window on the
**real socket peer** (`request.client.host`) and deliberately does **not** consume
`X-Forwarded-For`. A forwarded header is trivially spoofable unless a trusted edge
strips and re-sets it, and trusting it would let an attacker rotate `XFF` to evade
the throttle (or pin a victim's IP to lock them out). Refusing to trust it is the
safe default.

The tradeoff is that when the admin service runs **behind a reverse proxy /
ingress** (the recommended topology), the socket peer is the proxy, so every
client collapses into a **single per-IP bucket** — the per-IP limit becomes a
coarse global cap rather than a true per-client control. The real backstop against
credential attacks is therefore the **per-username limiter** (`_USERNAME_ATTEMPTS`
/ Redis `login_attempts:user:*`), which is independent of source IP and blunts
distributed brute-force, plus MFA and bcrypt cost.

- **Impact:** the per-IP login cap is not a precise per-client control behind a
  shared-IP proxy; it does not defend against a distributed (many-source) login
  flood on its own.
- **Mitigation / opt in:** enforce IP-based login rate limiting **at the edge**
  (nginx/ingress/WAF), which sees real client IPs and is the correct layer for it;
  the app-layer per-username limiter + MFA remain the credential-attack backstop.
  The app will not be changed to trust `X-Forwarded-For` for a security decision.
- **Refs:** `admin/routes/auth.py` (`_check_login_rate_limit`,
  `_record_login_attempt`).

---

## L8 — Backend egress SSRF validation is not IP-pinned (DNS-rebind TOCTOU)

**Status: By design.**

The proxy validates a backend URL's resolved addresses against the SSRF blocklist
(`_url_resolves_to_blocked_ip` in `src/routes/proxy.py`) **before** forwarding, but
the subsequent `httpx` request performs its **own** DNS resolution at connect time
and is **not pinned** to the exact IP that was validated. A hostile authoritative
DNS server could therefore answer with a public IP during validation and a private
IP at connect (a time-of-check/time-of-use **DNS-rebinding** window). A short-lived
resolution cache (`_DNS_CACHE`) narrows but does not close the gap.

This is accepted because **backend targets are operator-configured, not
user-supplied**: agents/backends come from `config/agents.yaml` (env-expanded,
admin-controlled), so the destination host is trusted infrastructure, not an
attacker-chosen value. The genuinely user-influenced egress path — HTTP
**redirects** on outbound integration fetches — is hardened separately: every hop
is re-validated against the SSRF blocklist and sensitive headers are dropped
cross-host (see `admin/services/ioc_store.py::_safe_httpx_request`).

- **Impact:** an operator who points a backend at a hostname served by a hostile,
  attacker-controlled resolver could, in principle, be rebound to an internal
  address after validation. Not reachable by an unauthenticated/tenant caller.
- **Mitigation / opt in:** point backends at IP literals or names served by a
  trusted resolver; restrict egress at the network layer (NetworkPolicy / firewall)
  so a rebind cannot reach sensitive internal ranges regardless of DNS answers.
- **Refs:** `src/routes/proxy.py` (`_url_resolves_to_blocked_ip`, `_DNS_CACHE`),
  `admin/services/ioc_store.py` (redirect re-validation).

---

_When a limitation here is genuinely removed (e.g. a topic classifier ships with
a real model + tests), delete its entry — this file must only ever list gaps that
are still real._
