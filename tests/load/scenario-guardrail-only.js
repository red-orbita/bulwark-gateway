/**
 * Sentinel Gateway — Guardrail-Only Scenario
 *
 * Measures the raw regex guardrail processing overhead in isolation.
 * Sends requests that exercise the input guardrail (prompt injection,
 * jailbreak detection, encoded payload scanning) without hitting the
 * backend LLM.
 *
 * Target: p50 <1ms, p95 <2ms, p99 <3ms, >15,000 RPS
 *
 * Run:
 *   k6 run --out json=results/guardrail-only.json tests/load/scenario-guardrail-only.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";
import {
  BASE_URL,
  authHeaders,
  standardStages,
  randomPayload,
  cleanPayload,
  attackPayload,
  isValidResponse,
  isBlocked,
  TARGETS,
  DEFAULT_VUS,
} from "./k6-config.js";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const guardrailLatency = new Trend("guardrail_latency", true);
const blockRate = new Rate("block_rate");
const errorRate = new Rate("error_rate");
const requestsOK = new Counter("requests_ok");
const requestsBlocked = new Counter("requests_blocked");

// ---------------------------------------------------------------------------
// Test options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // Mixed traffic: 80% clean, 20% attack
    mixed_traffic: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(DEFAULT_VUS),
      gracefulRampDown: "10s",
    },
    // Pure attack traffic: measures block-path performance
    attack_only: {
      executor: "constant-arrival-rate",
      rate: 500,
      timeUnit: "1s",
      duration: "1m",
      preAllocatedVUs: 20,
      maxVUs: 50,
      startTime: "3m30s", // After main scenario completes
    },
  },

  thresholds: {
    // Enterprise targets for guardrail-only
    http_req_duration: [
      { threshold: "p(50)<1", abortOnFail: false },
      { threshold: "p(95)<2", abortOnFail: false },
      { threshold: "p(99)<3", abortOnFail: true },
    ],
    guardrail_latency: [
      { threshold: "p(50)<1", abortOnFail: false },
      { threshold: "p(95)<2", abortOnFail: false },
      { threshold: "p(99)<3", abortOnFail: true },
    ],
    error_rate: [{ threshold: "rate<0.01", abortOnFail: true }],
    http_req_failed: [{ threshold: "rate<0.01", abortOnFail: true }],
  },

  // JSON output for CI integration
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
};

// ---------------------------------------------------------------------------
// Main VU function — mixed traffic
// ---------------------------------------------------------------------------

export default function () {
  const headers = authHeaders();
  const payload = randomPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  const startTime = Date.now();
  const res = http.post(url, payload, {
    headers,
    tags: { scenario: "guardrail_only" },
    timeout: "10s",
  });
  const elapsed = Date.now() - startTime;

  guardrailLatency.add(elapsed);

  const valid = isValidResponse(res);
  errorRate.add(!valid);

  if (isBlocked(res)) {
    blockRate.add(true);
    requestsBlocked.add(1);
  } else {
    blockRate.add(false);
    requestsOK.add(1);
  }

  check(res, {
    "status is 200 or 403": (r) => isValidResponse(r),
    "response has body": (r) => r.body && r.body.length > 0,
    "latency under 3ms (p99 target)": () => elapsed < 3,
  });

  // Minimal sleep to avoid overwhelming local testing
  sleep(0.01);
}

// ---------------------------------------------------------------------------
// Attack-only scenario function
// ---------------------------------------------------------------------------

export function attackOnly() {
  const headers = authHeaders();
  const payload = attackPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  const startTime = Date.now();
  const res = http.post(url, payload, {
    headers,
    tags: { scenario: "attack_only" },
    timeout: "10s",
  });
  const elapsed = Date.now() - startTime;

  guardrailLatency.add(elapsed);
  blockRate.add(isBlocked(res));

  check(res, {
    "attack correctly blocked (403)": (r) => r.status === 403,
    "block response fast (<3ms)": () => elapsed < 3,
  });
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const summary = {
    scenario: "guardrail-only",
    timestamp: new Date().toISOString(),
    targets: TARGETS.guardrailOnly,
    results: {
      p50: data.metrics.http_req_duration?.values?.["p(50)"] || null,
      p95: data.metrics.http_req_duration?.values?.["p(95)"] || null,
      p99: data.metrics.http_req_duration?.values?.["p(99)"] || null,
      avg: data.metrics.http_req_duration?.values?.avg || null,
      throughput: data.metrics.http_reqs?.values?.rate || null,
      errorRate: data.metrics.error_rate?.values?.rate || null,
      blockRate: data.metrics.block_rate?.values?.rate || null,
    },
    passed: true,
  };

  // Check against targets
  if (summary.results.p50 > TARGETS.guardrailOnly.p50) summary.passed = false;
  if (summary.results.p95 > TARGETS.guardrailOnly.p95) summary.passed = false;
  if (summary.results.p99 > TARGETS.guardrailOnly.p99) summary.passed = false;

  return {
    "results/guardrail-only.json": JSON.stringify(summary, null, 2),
    stdout: textSummary(data, { indent: " ", enableColors: true }),
  };
}

function textSummary(data, opts) {
  // k6 provides a built-in text summary; this is a fallback
  const d = data.metrics.http_req_duration?.values || {};
  return [
    "",
    "=== Guardrail-Only Scenario Results ===",
    `  p50:  ${(d["p(50)"] || 0).toFixed(2)}ms (target: <${TARGETS.guardrailOnly.p50}ms)`,
    `  p95:  ${(d["p(95)"] || 0).toFixed(2)}ms (target: <${TARGETS.guardrailOnly.p95}ms)`,
    `  p99:  ${(d["p(99)"] || 0).toFixed(2)}ms (target: <${TARGETS.guardrailOnly.p99}ms)`,
    `  avg:  ${(d.avg || 0).toFixed(2)}ms`,
    `  rate: ${(data.metrics.http_reqs?.values?.rate || 0).toFixed(0)} req/s`,
    "",
  ].join("\n");
}
