# Correlation Engine — Maturity Remediation & Audit Loop

> **Status:** ACTIVE
> **Scope:** `src/correlation/` + its proxy integration (`src/routes/proxy.py` PHASE 1r / 5c)
> and admin surface (`admin/routes/correlation.py`, `admin/routes/health.py`).
> **Why this doc exists:** the inline input↔output correlation + adaptive origin-risk
> feedback loop is the product's key differentiator. This file is the living tracker
> that drives it from "works" to "excellent" via an **evidence-closed loop**: a finding
> is only closed when a committed test demonstrates it is fixed.

---

## 1. Definition of "excellent" (acceptance criteria)

The engine is considered production-mature for `blocking:true` on a **shared, multi-user
agent** only when ALL of the following hold:

| # | Criterion | How it is proven |
|---|-----------|------------------|
| A1 | **Correctness under concurrency** — no lost updates when the same origin bumps risk concurrently | Real-Redis concurrency test: N concurrent bumps ⇒ final score == sequential expectation (±float epsilon) |
| A2 | **Bounded hot-path cost** — risk read/write adds ≤1 Redis round-trip each; no unbounded fan-out | Round-trip accounting test + code review; latency histogram P95 within budget |
| A3 | **Resilient to Redis faults** — a slow/down Redis never stalls or fails a user request | Circuit-breaker test: injected timeouts degrade to in-memory, request still served |
| A4 | **Bounded blast radius** — a single noisy user / false positive cannot BLOCK an entire shared agent | Scope-isolation test: per-subject risk does not escalate the shared session verdict |
| A5 | **No inert/ misleading controls** — every admin-tunable, documented knob actually affects the path | Wiring test proving each knob changes behaviour, OR the knob is removed/relabelled |
| A6 | **Quantified detection quality** — correlator FP/FN measured against a labelled dataset, with a target | Red-team dataset + report; FP rate below agreed threshold on benign corpus |
| A7 | **Fail-safe OFF** — zero hot-path cost and zero side effects when `correlation_enabled=false` | Existing inertness tests remain green |
| A8 | **Secure-coding compliant** — every change meets `.opencode/SECURE-CODING-STANDARDS.md` §8 (≥3 pos / ≥2 neg + fail-closed + adversarial) | Test count + ruff + mypy clean on touched modules |

---

## 2. Audit loop protocol

Each remediation phase R(n) runs the same closed loop:

```
1. AUDIT      — locate the defect, cite file:line, write the failing/│missing test first
2. REMEDIATE  — minimal, secure-coding-compliant change; no new deps; fail-closed
3. VERIFY     — pytest (pos/neg/adversarial/fail-closed) + ruff + mypy on touched files
4. RE-AUDIT   — re-read the changed path; confirm no regression + no new finding
5. RECORD     — update the findings register below (status + evidence + commit)
6. COMMIT     — conventional commit; push is manual (user, after ssh-add)
```

A phase is **DONE** only when its finding row shows `CLOSED` with a linked test and commit.
The loop terminates when every row is `CLOSED` and A1–A8 all hold (§4 re-audit log signed off).

---

## 3. Findings register

Severity: 🔴 high · 🟠 medium · 🟡 low. Status: `OPEN` → `IN PROGRESS` → `CLOSED`.

| ID | Sev | Finding | Evidence | Fix (phase) | Verified by | Status |
|----|-----|---------|----------|-------------|-------------|--------|
| **F1** | 🔴 | Non-atomic read-modify-write in origin-risk bump. `hgetall` → decay in Python → `pipeline(hset,expire)` is **batching, not a transaction**. Concurrent bumps of the same origin lose updates ⇒ risk is **undercounted** exactly during a burst attack. | `risk_state.py:163-176` (read at 165, write pipeline at 172-175; no WATCH/MULTI/Lua) | R1: atomic server-side decay+bump via Lua `EVALSHA`; collapses to 1 RTT | `tests/test_correlation_atomic_bump.py` (9 tests + opt-in real-Redis concurrency); real-Redis counterfactual: old path lost **87%** (10.0→1.3), atomic holds exact | **CLOSED** (`_pending commit_`) |
| **F2** | 🟠 | Hot-path Redis cost unbounded by faults. `evaluate_origin_risk` = 2 RTTs (session+tenant get) every non-blocked request; a confirmed incident adds ~6 more (3 bumps × read+write). `socket_timeout=1s`, **no circuit breaker** ⇒ Redis latency spikes hit user latency ×N. | `incident.py:322-323`; `risk_state.py:94,163-185` | R2: pipeline reads (1 RTT) + circuit breaker degrading to in-memory | `tests/test_correlation_resilience.py` (8 tests: get_many 1-RTT, breaker open/half-open/reset, fail-closed); black-hole Redis proof: 15 post-open calls **0.000s** vs ~15s unbounded | **CLOSED** (`_pending commit_`) |
| **F3** | 🟠 | Blast radius of origin-risk BLOCK too coarse. Decision scope `session=(tenant,agent)` is **not per-end-user**; one noisy user or false positive accrues risk that BLOCKs **all** users of a shared agent for ~hours (half-life 15m). Self-inflicted DoS vector. | `incident.py:322-324`; `risk_state.py:66-69` | R3: per-subject scope dimension (JWT `sub`) or single-origin contribution cap | _pending_ | OPEN |
| **F4** | 🟡 | `window_seconds` guard is **inert in production**. `evaluate()` uses `input_detected_at` (`incident.py:251`) but the proxy call **never passes it** ⇒ always `None` ⇒ guard skipped. Yet the knob is admin-tunable, in the UI, and documented as operative. Violates project honesty rule. | `incident.py:251`; `proxy.py:1053-1062` (no `input_detected_at` arg) | R4: wire the input-detection timestamp, OR relabel knob as latent + remove from active UI | _pending_ | OPEN |
| **F5** | 🟡 | Correlator FP/FN rate unquantified. `correlation_confidence` (threshold 0.5) is a heuristic; no labelled dataset or red-team measures its error. A control that can BLOCK legitimate user content must not ship with unknown FP rate. | `confidence.py` (whole); no dataset under `tests/` or `src/evaluation/` covering the correlator | R5: benign+attack labelled corpus + FP/FN report; set target | _pending_ | OPEN |

### Design constraints discovered during audit (inform the fixes)

- **No per-user identity downstream (affects F3).** JWT `sub` is validated but **not**
  propagated: `auth.py:358-364` attaches only `tenant_id`, `agent_id`, `token_jti` to
  `request.state`. API-key auth has no user identity at all (bound tenant only). So a
  per-subject scope is feasible **only for JWT auth**; API-key origins must fall back to
  the session scope with a contribution cap.
- **Redis version = 7** (`redis:7-alpine`) ⇒ Lua effects-replication is the default, so
  `redis.call('TIME')` inside a script is replication-safe (no `replicate_commands()` needed).
- **Fakes are single-threaded** ⇒ the F1 race is invisible to `_FakeRedis`. A1 must be
  proven against a **real** Redis (opt-in test gated on `BULWARK_TEST_REDIS_URL`), while the
  decay+bump *formula* is unit-tested via a shared pure reference function.

---

## 4. Re-audit log

Append one entry per completed phase. Sign off A1–A8 only when all rows are CLOSED.

| Date | Phase | Change (commit) | Findings moved | A-criteria touched | Re-audit result |
|------|-------|-----------------|----------------|--------------------|-----------------|
| _tbd_ | R0 | framework doc | — | (scaffolding) | Baseline recorded; F1–F5 OPEN |
| _tbd_ | R1 | atomic Lua decay+bump in `risk_state.py` | F1 → CLOSED | A1 ✅, A2 (partial: bump now 1 RTT), A7 ✅ (unchanged), A8 ✅ | 111 correlation tests green + real-Redis proof (atomic exact vs old-path 87% loss). mypy on `risk_state.py` improved 5→0. No regression. F2/F3 (read-side RTTs, blast radius) still OPEN. |
| _tbd_ | R2 | `get_many` pipeline + circuit breaker in `risk_state.py`; `incident.py` uses `get_many` | F2 → CLOSED | A2 ✅ (reads now 1 RTT), A3 ✅ (breaker), A7 ✅, A8 ✅ | 119 correlation tests green; mypy/ruff clean on `risk_state.py`+`incident.py`. Black-hole Redis proof: breaker caps latency (15 calls 0.000s vs ~15s). F3 (blast radius), F4 (window), F5 (FP) still OPEN. |

---

## 5. Non-goals / explicitly deferred

- Rewriting the confidence heuristic into an ML model (out of scope until F5 quantifies
  whether the heuristic is even the bottleneck).
- Cross-region risk replication (covered by `docs/MULTI-REGION.md`, orthogonal).
- Changing the fail-safe-OFF default (`correlation_enabled=false`) — stays OFF by design.
